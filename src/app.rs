//! network-tui state and input handling. Rendering is in `view.rs`; the
//! connection editor lives in `editor.rs`.

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use crossterm::event::{Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers, MouseButton, MouseEvent, MouseEventKind};
use ratatui::style::Color;
use tokio::sync::mpsc::UnboundedSender;

use crate::action::{Action, Ctx};
use crate::backend::form::{self, Form};
use crate::backend::model::{reason_text, DevKind, DevState, Device, Network, Profile, Security, Snapshot};
use crate::backend::val::{Dict, Val};
use crate::backend::{Cmd, Ev, SecretRequest};
use crate::config::Config;
use crate::core::keymap::{ActionSet, Keymap};
use crate::core::keys::KeyCombo;
use crate::editor::{Editor, EditorOutcome};
use crate::ui::input::{InputOutcome, TextInput};
use crate::ui::mouse::MouseMap;
use crate::ui::palette::{Entry, Palette, PaletteOutcome};
use crate::ui::theme::Theme;
use crate::ui::widgets::{ConfirmHit, Level, Toasts};

pub const ACCENT: Color = Color::Rgb(0xa6, 0xe3, 0xa1);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tab {
    Wifi,
    Connections,
    Devices,
    General,
}

impl Tab {
    pub const ALL: [Tab; 4] = [Tab::Wifi, Tab::Connections, Tab::Devices, Tab::General];
    pub fn title(self) -> &'static str {
        match self {
            Tab::Wifi => "Wi-Fi",
            Tab::Connections => "Connections",
            Tab::Devices => "Devices",
            Tab::General => "General",
        }
    }
    pub fn ctx(self) -> Ctx {
        match self {
            Tab::Wifi => Ctx::Wifi,
            Tab::Connections => Ctx::Connections,
            Tab::Devices => Ctx::Devices,
            Tab::General => Ctx::General,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GenRow {
    Hostname,
    Networking,
    WifiRadio,
    Wwan,
    Airplane,
    Connectivity,
}

impl GenRow {
    pub const ALL: [GenRow; 6] = [GenRow::Hostname, GenRow::Networking, GenRow::WifiRadio, GenRow::Wwan, GenRow::Airplane, GenRow::Connectivity];
}

#[derive(Clone, Debug, PartialEq)]
pub enum Target {
    Tab(usize),
    Row(usize),
    Run(Action),
    Confirm(ConfirmHit),
    PaletteRow(usize),
    MenuRow(usize),
    MiniField(usize),
    MiniButton(bool),
    EditorRow(usize),
    EditorButton(bool),
    CloseShare,
    FilterBar,
    WifiDevice(String),
}

/// What a small dialog is for.
#[derive(Clone, Debug)]
pub enum MiniPurpose {
    Password { device: String, ap: String, ssid: String, security: Security },
    Hidden { device: String },
    Hotspot { device: String },
    Import,
    Hostname,
    Secret { id: u64, req: SecretRequest },
}

#[derive(Clone, Debug)]
pub struct MiniField {
    pub label: &'static str,
    pub input: TextInput,
    /// (stored value, label) choices; if set, the field is a selector.
    pub choices: Option<(Vec<(&'static str, &'static str)>, usize)>,
}

impl MiniField {
    pub fn text(label: &'static str, v: &str) -> Self {
        Self { label, input: TextInput::new(v), choices: None }
    }
    pub fn secret(label: &'static str, v: &str) -> Self {
        Self { label, input: TextInput::new(v).masked(), choices: None }
    }
    pub fn choice(label: &'static str, opts: Vec<(&'static str, &'static str)>, sel: usize) -> Self {
        Self { label, input: TextInput::default(), choices: Some((opts, sel)) }
    }
    pub fn value(&self) -> String {
        match &self.choices {
            Some((o, i)) => o[*i].0.to_string(),
            None => self.input.value(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Mini {
    pub title: String,
    pub intro: String,
    pub fields: Vec<MiniField>,
    pub focus: usize,
    pub ok_label: &'static str,
    pub purpose: MiniPurpose,
    pub error: Option<String>,
}

pub enum Popup {
    Help { scroll: u16, max: u16 },
    Palette(Palette<Action>),
    Menu { items: Vec<Action>, sel: usize, at: (u16, u16) },
    Confirm { title: String, msg: String, yes: String, yes_sel: bool, cmd: Cmd },
    Mini(Box<Mini>),
    Editor(Box<Editor>),
    Share { ssid: String, security: Security, password: Option<String>, waiting: Option<String> },
    NewKind { sel: usize },
}

pub const NEW_KINDS: [(&str, &str); 6] = [
    ("802-3-ethernet", "Ethernet"),
    ("802-11-wireless", "Wi-Fi"),
    ("wireguard", "WireGuard VPN"),
    ("vlan", "VLAN"),
    ("bridge", "Bridge"),
    ("bond", "Bond"),
];

pub struct App {
    pub cfg: Config,
    pub cfg_path: PathBuf,
    pub theme: Theme,
    pub keymap: Keymap<Action>,
    pub tx: UnboundedSender<Cmd>,
    pub demo: bool,

    pub snap: Snapshot,
    pub loaded: bool,
    pub unavailable: Option<String>,
    pub tab: Tab,
    pub wifi_dev: Option<String>,
    pub wifi_sel: Option<Vec<u8>>,
    pub conn_sel: Option<String>,
    pub dev_sel: Option<String>,
    pub gen_sel: usize,
    pub list_offset: usize,
    pub list_height: usize,
    pub filter: Option<TextInput>,
    pub filter_focus: bool,
    pub busy: HashMap<String, String>,
    pub popup: Option<Popup>,
    pub queued: Vec<Popup>,
    pub toasts: Toasts,
    pub tick: u64,
    pub show_details: bool,
    pub mouse: MouseMap<Target>,
    last_click: Option<(Instant, Target)>,
    last_toggle: Option<(Action, Instant)>,
    pub quit: bool,
}

impl App {
    pub fn new(cfg: Config, cfg_path: PathBuf, tx: UnboundedSender<Cmd>, demo: bool, mut warnings: Vec<String>) -> Self {
        let (keymap, kw) = Keymap::build(&cfg.keys);
        warnings.extend(kw);
        let theme = Theme::from_config(&cfg.theme, ACCENT, &mut warnings);
        let mut toasts = Toasts::default();
        for w in warnings {
            toasts.push(Level::Warn, w);
        }
        if demo {
            toasts.push(Level::Info, "Demo mode — fake networks, nothing touches NetworkManager");
        }
        let show_details = cfg.general.details;
        Self {
            cfg,
            cfg_path,
            theme,
            keymap,
            tx,
            demo,
            snap: Snapshot::default(),
            loaded: false,
            unavailable: None,
            tab: Tab::Wifi,
            wifi_dev: None,
            wifi_sel: None,
            conn_sel: None,
            dev_sel: None,
            gen_sel: 0,
            list_offset: 0,
            list_height: 10,
            filter: None,
            filter_focus: false,
            busy: HashMap::new(),
            popup: None,
            queued: Vec::new(),
            toasts,
            tick: 0,
            show_details,
            mouse: MouseMap::default(),
            last_click: None,
            last_toggle: None,
            quit: false,
        }
    }

    pub fn send(&self, c: Cmd) {
        let _ = self.tx.send(c);
    }

    pub fn ctx(&self) -> Ctx {
        self.tab.ctx()
    }

    // ------------------------------------------------------------ derived lists

    pub fn wifi_devices(&self) -> Vec<&Device> {
        self.snap.devices.iter().filter(|d| d.kind == DevKind::Wifi).collect()
    }

    pub fn wifi_device(&self) -> Option<&Device> {
        let id = self.wifi_dev.as_ref()?;
        self.snap.devices.iter().find(|d| &d.path == id)
    }

    fn filter_text(&self) -> String {
        self.filter.as_ref().map(|f| f.value().to_lowercase()).unwrap_or_default()
    }

    pub fn networks(&self) -> Vec<Network> {
        let Some(dev) = &self.wifi_dev else { return Vec::new() };
        let q = self.filter_text();
        crate::backend::model::networks(&self.snap, dev)
            .into_iter()
            .filter(|n| n.connected || n.connecting || n.strength >= self.cfg.wifi.min_signal)
            .filter(|n| q.is_empty() || n.ssid.to_lowercase().contains(&q))
            .collect()
    }

    pub fn profiles(&self) -> Vec<&Profile> {
        let q = self.filter_text();
        self.snap
            .profiles
            .iter()
            .filter(|p| p.kind != "loopback")
            .filter(|p| q.is_empty() || p.id.to_lowercase().contains(&q) || p.kind_label().to_lowercase().contains(&q))
            .collect()
    }

    pub fn devices(&self) -> Vec<&Device> {
        self.snap.devices.iter().filter(|d| d.kind != DevKind::Loopback).collect()
    }

    pub fn selected_network(&self) -> Option<Network> {
        let sel = self.wifi_sel.as_ref()?;
        self.networks().into_iter().find(|n| &n.ssid_bytes == sel)
    }

    pub fn selected_profile(&self) -> Option<&Profile> {
        let sel = self.conn_sel.as_ref()?;
        self.snap.profiles.iter().find(|p| &p.path == sel)
    }

    pub fn profile(&self, path: &str) -> Option<&Profile> {
        self.snap.profiles.iter().find(|p| p.path == path)
    }

    pub fn selected_device(&self) -> Option<&Device> {
        let sel = self.dev_sel.as_ref()?;
        self.snap.devices.iter().find(|d| &d.path == sel)
    }

    pub fn hotspot_profile(&self) -> Option<&Profile> {
        let dev = self.wifi_device()?;
        self.snap
            .profiles
            .iter()
            .filter(|p| p.is_wifi() && p.wifi_mode() == "ap" && (p.iface.is_empty() || p.iface == dev.iface))
            .max_by_key(|p| (p.is_active(), p.timestamp))
    }

    pub fn row_count(&self) -> usize {
        match self.tab {
            Tab::Wifi => self.networks().len(),
            Tab::Connections => self.profiles().len(),
            Tab::Devices => self.devices().len(),
            Tab::General => GenRow::ALL.len(),
        }
    }

    pub fn selected_index(&self) -> Option<usize> {
        match self.tab {
            Tab::Wifi => {
                let s = self.wifi_sel.as_ref()?;
                self.networks().iter().position(|n| &n.ssid_bytes == s)
            }
            Tab::Connections => {
                let s = self.conn_sel.as_ref()?;
                self.profiles().iter().position(|p| &p.path == s)
            }
            Tab::Devices => {
                let s = self.dev_sel.as_ref()?;
                self.devices().iter().position(|d| &d.path == s)
            }
            Tab::General => Some(self.gen_sel),
        }
    }

    pub fn select_index(&mut self, i: usize) {
        match self.tab {
            Tab::Wifi => self.wifi_sel = self.networks().get(i).map(|n| n.ssid_bytes.clone()),
            Tab::Connections => self.conn_sel = self.profiles().get(i).map(|p| p.path.clone()),
            Tab::Devices => self.dev_sel = self.devices().get(i).map(|d| d.path.clone()),
            Tab::General => self.gen_sel = i.min(GenRow::ALL.len() - 1),
        }
    }

    fn fix_selection(&mut self) {
        let n = self.row_count();
        if n == 0 {
            return;
        }
        if self.selected_index().is_none() {
            self.select_index(0);
        }
    }

    fn move_sel(&mut self, delta: isize) {
        let n = self.row_count();
        if n == 0 {
            return;
        }
        let cur = self.selected_index().unwrap_or(0) as isize;
        self.select_index((cur + delta).clamp(0, n as isize - 1) as usize);
    }

    // ------------------------------------------------------------ backend events

    pub fn on_backend(&mut self, ev: Ev) {
        match ev {
            Ev::Unavailable(m) => {
                self.unavailable = Some(m);
                self.loaded = true;
            }
            Ev::Snapshot(s) => self.apply_snapshot(*s),
            Ev::Busy { key, label, on } => {
                if on {
                    self.busy.insert(key, label);
                } else {
                    self.busy.remove(&key);
                }
            }
            Ev::Ok(m) => self.toasts.push(Level::Ok, m),
            Ev::Info(m) => self.toasts.push(Level::Info, m),
            Ev::Error(m) => self.toasts.push(Level::Error, m),
            Ev::Secrets { path, setting, values } => self.on_secrets(path, setting, values),
            Ev::SecretRequest { id, req } => {
                let mut intro = if req.retry {
                    format!("“{}” needs a new password — the saved one didn't work.", req.conn_id)
                } else {
                    format!("“{}” needs a password.", req.conn_id)
                };
                if req.setting == "802-1x" {
                    intro.push_str(" (enterprise login)");
                }
                let m = Mini {
                    title: "Password needed".into(),
                    intro,
                    fields: vec![MiniField::secret("Password", "")],
                    focus: 0,
                    ok_label: "Connect",
                    purpose: MiniPurpose::Secret { id, req },
                    error: None,
                };
                self.show_urgent(Popup::Mini(Box::new(m)));
            }
            Ev::SecretCancelled(id) => {
                let is_it = |p: &Popup| matches!(p, Popup::Mini(m) if matches!(m.purpose, MiniPurpose::Secret { id: i, .. } if i == id));
                if self.popup.as_ref().is_some_and(is_it) {
                    self.popup = self.queued.pop();
                }
                self.queued.retain(|p| !is_it(p));
            }
        }
    }

    fn show_urgent(&mut self, p: Popup) {
        if let Some(old) = self.popup.take()
            && matches!(old, Popup::Editor(_) | Popup::Mini(_)) {
                self.queued.push(old); // come back to it afterwards
            }
        self.popup = Some(p);
    }

    fn apply_snapshot(&mut self, s: Snapshot) {
        // Report failures: a device that was connecting and ended up failed/disconnected.
        if self.loaded {
            for d in &s.devices {
                let Some(prev) = self.snap.devices.iter().find(|p| p.path == d.path) else { continue };
                let was_trying = prev.state.busy();
                let failed = d.state == DevState::Failed || (was_trying && d.state == DevState::Disconnected);
                if was_trying && failed && d.state_reason != 39 {
                    let why = reason_text(d.state_reason).map(str::to_string).unwrap_or_else(|| format!("reason {}", d.state_reason));
                    self.toasts.push(Level::Error, format!("{}: couldn't connect — {why}", d.iface));
                }
            }
        }
        let first = !self.loaded;
        self.snap = s;
        self.loaded = true;
        if self.wifi_dev.as_ref().is_none_or(|p| !self.snap.devices.iter().any(|d| &d.path == p)) {
            self.wifi_dev = self.wifi_devices().first().map(|d| d.path.clone());
        }
        if first {
            if !self.wifi_devices().is_empty() {
                self.tab = Tab::Wifi;
            } else {
                self.tab = Tab::Connections;
            }
            if self.cfg.wifi.scan_on_start
                && let Some(d) = self.wifi_dev.clone() {
                    self.send(Cmd::Scan(d));
                }
        }
        let saved_tab = self.tab;
        for t in Tab::ALL {
            self.tab = t;
            self.fix_selection();
        }
        self.tab = saved_tab;
    }

    fn on_secrets(&mut self, path: String, setting: String, values: Dict) {
        match &mut self.popup {
            Some(Popup::Editor(ed)) if ed.path.as_deref() == Some(path.as_str()) => ed.form.apply_secrets(&setting, &values),
            Some(Popup::Share { password, waiting, .. }) if waiting.as_deref() == Some(path.as_str()) => {
                *waiting = None;
                let pw = values.get("psk").or_else(|| values.get("wep-key0")).and_then(Val::str).unwrap_or_default().to_string();
                *password = Some(pw);
            }
            _ => {}
        }
    }

    /// Advances timers; true when that changed what's on screen.
    pub fn on_tick(&mut self) -> bool {
        self.tick = self.tick.wrapping_add(1);
        self.toasts.prune()
    }

    // ------------------------------------------------------------ input

    pub fn on_event(&mut self, ev: Event) {
        match ev {
            Event::Key(k) if k.kind != KeyEventKind::Release => self.on_key(k),
            Event::Mouse(m) if self.cfg.general.mouse => self.on_mouse(m),
            Event::Paste(s) => self.on_paste(&s),
            _ => {}
        }
    }

    fn on_paste(&mut self, s: &str) {
        let line = s.lines().next().unwrap_or("");
        match &mut self.popup {
            Some(Popup::Mini(m)) => {
                if let Some(f) = m.fields.get_mut(m.focus) {
                    f.input.insert_str(line);
                }
            }
            Some(Popup::Editor(ed)) => ed.paste(line),
            Some(Popup::Palette(p)) => p.input.insert_str(line),
            None if self.filter_focus => {
                if let Some(f) = &mut self.filter {
                    f.insert_str(line);
                }
            }
            _ => {}
        }
    }

    fn on_key(&mut self, k: KeyEvent) {
        if self.popup.is_some() {
            return self.popup_key(k);
        }
        if self.filter_focus {
            if let Some(f) = &mut self.filter {
                match f.handle_key(&k) {
                    InputOutcome::Submit => self.filter_focus = false,
                    InputOutcome::Cancel => {
                        self.filter = None;
                        self.filter_focus = false;
                    }
                    InputOutcome::Ignored => {
                        let combo = KeyCombo::from_event(&k);
                        if let Some(&a) = self.keymap.actions_for(&combo).iter().find(|a| matches!(a, Action::Up | Action::Down)) {
                            self.run(a);
                        }
                    }
                    _ => {}
                }
                self.fix_selection();
            }
            return;
        }
        if k.code == KeyCode::Esc {
            if self.filter.is_some() {
                self.filter = None;
            } else {
                self.toasts.dismiss_all();
            }
            return;
        }
        let combo = KeyCombo::from_event(&k);
        let ctx = self.ctx();
        if let Some(&a) = self.keymap.actions_for(&combo).iter().find(|a| a.available(ctx)) {
            if a.is_toggle() {
                if let Some((last, at)) = self.last_toggle
                    && last == a && at.elapsed() < Duration::from_millis(300) {
                        return;
                    }
                self.last_toggle = Some((a, Instant::now()));
            }
            self.run(a);
        }
    }

    fn popup_key(&mut self, k: KeyEvent) {
        use KeyCode::*;
        let Some(mut p) = self.popup.take() else { return };
        let mut close = false;
        match &mut p {
            Popup::Help { scroll, max } => match k.code {
                Esc | Char('q') | Char('?') | Enter => close = true,
                Down | Char('j') => *scroll = (*scroll + 1).min(*max),
                Up | Char('k') => *scroll = scroll.saturating_sub(1),
                PageDown | Char(' ') => *scroll = (*scroll + 10).min(*max),
                PageUp => *scroll = scroll.saturating_sub(10),
                Home | Char('g') => *scroll = 0,
                End | Char('G') => *scroll = *max,
                _ => {}
            },
            Popup::Palette(pal) => match pal.handle_key(&k) {
                PaletteOutcome::Run(a) => {
                    self.run(a);
                    return;
                }
                PaletteOutcome::Close => close = true,
                PaletteOutcome::None => {}
            },
            Popup::Menu { items, sel, .. } => {
                let n = items.len().max(1);
                match k.code {
                    Esc | Char('q') => close = true,
                    Down | Char('j') | Tab => *sel = (*sel + 1) % n,
                    Up | Char('k') | BackTab => *sel = (*sel + n - 1) % n,
                    Enter | Char(' ') => {
                        let a = items.get(*sel).copied();
                        if let Some(a) = a {
                            self.run(a);
                        }
                        return;
                    }
                    _ => {
                        let combo = KeyCombo::from_event(&k);
                        if let Some(&a) = items.iter().find(|&&a| self.keymap.keys_for(a).contains(&combo)) {
                            self.run(a);
                            return;
                        }
                    }
                }
            }
            Popup::Confirm { yes_sel, cmd, .. } => match k.code {
                Esc | Char('n') | Char('q') => close = true,
                Left | Right | Tab | BackTab | Char('h') | Char('l') => *yes_sel = !*yes_sel,
                Char('y') => {
                    self.send(cmd.clone());
                    close = true;
                }
                Enter => {
                    if *yes_sel {
                        self.send(cmd.clone());
                    }
                    close = true;
                }
                _ => {}
            },
            Popup::Mini(m) => {
                if let Some(done) = mini_key(m, &k) {
                    if done {
                        if self.submit_mini(m) {
                            close = true;
                        }
                    } else {
                        if let MiniPurpose::Secret { id, .. } = m.purpose {
                            self.send(Cmd::SecretReply { id, secrets: None });
                        }
                        close = true;
                    }
                }
            }
            Popup::Editor(ed) => match ed.handle_key(&k) {
                EditorOutcome::None => {}
                EditorOutcome::Cancel => close = true,
                EditorOutcome::Save(settings) => {
                    self.save_editor(ed, settings);
                    close = true;
                }
            },
            Popup::Share { .. } => close = matches!(k.code, Esc | Enter | Char('q') | Char('y')),
            Popup::NewKind { sel } => match k.code {
                Esc | Char('q') => close = true,
                Down | Char('j') | Tab => *sel = (*sel + 1) % NEW_KINDS.len(),
                Up | Char('k') | BackTab => *sel = (*sel + NEW_KINDS.len() - 1) % NEW_KINDS.len(),
                Enter | Char(' ') => {
                    let kind = NEW_KINDS[*sel].0;
                    self.open_new_editor(kind);
                    return;
                }
                _ => {}
            },
        }
        if close {
            self.popup = self.queued.pop();
        } else if self.popup.is_none() {
            self.popup = Some(p);
        }
    }

    // ------------------------------------------------------------ mouse

    fn on_mouse(&mut self, m: MouseEvent) {
        let hit = self.mouse.hit(m.column, m.row);
        match m.kind {
            MouseEventKind::ScrollDown | MouseEventKind::ScrollUp => {
                let d: isize = if m.kind == MouseEventKind::ScrollDown { 1 } else { -1 };
                match &mut self.popup {
                    Some(Popup::Help { scroll, max }) => *scroll = (*scroll as isize + d * 3).clamp(0, *max as isize) as u16,
                    Some(Popup::Editor(ed)) => ed.scroll_by(d * 2),
                    Some(Popup::Menu { items, sel, .. }) => *sel = (*sel as isize + d).clamp(0, items.len() as isize - 1) as usize,
                    Some(_) => {}
                    None => self.move_sel(d),
                }
            }
            MouseEventKind::Down(MouseButton::Left) => {
                let Some((rect, t)) = hit else {
                    if matches!(self.popup, Some(Popup::Help { .. } | Popup::Menu { .. } | Popup::Palette(_) | Popup::Share { .. } | Popup::NewKind { .. })) {
                        self.popup = None;
                    }
                    return;
                };
                let double = self.last_click.as_ref().is_some_and(|(at, prev)| *prev == t && at.elapsed() < Duration::from_millis(400));
                self.last_click = Some((Instant::now(), t.clone()));
                self.click(t, double, m.column.saturating_sub(rect.x));
            }
            MouseEventKind::Down(MouseButton::Right) => {
                if self.popup.is_none()
                    && let Some((_, Target::Row(i))) = hit {
                        self.select_index(i);
                        self.open_menu(Some((m.column, m.row)));
                    }
            }
            _ => {}
        }
    }

    fn click(&mut self, t: Target, double: bool, rel_x: u16) {
        match t {
            Target::Tab(i) => {
                self.tab = Tab::ALL[i.min(Tab::ALL.len() - 1)];
                self.list_offset = 0;
            }
            Target::Row(i) => {
                self.filter_focus = false;
                let already = self.selected_index() == Some(i);
                self.select_index(i);
                if double || (self.tab == Tab::General && already) {
                    self.last_click = None;
                    let a = match self.tab {
                        Tab::Wifi => Action::Connect,
                        Tab::Connections => Action::Activate,
                        Tab::Devices => Action::DeviceToggle,
                        Tab::General => Action::GeneralActivate,
                    };
                    self.run(a);
                }
            }
            Target::Run(a) => {
                if matches!(self.popup, Some(Popup::Menu { .. })) {
                    self.popup = None;
                } else if self.popup.is_some() {
                    return;
                }
                self.run(a);
            }
            Target::Confirm(h) => {
                if let Some(Popup::Confirm { cmd, .. }) = self.popup.take()
                    && h == ConfirmHit::Yes {
                        self.send(cmd);
                    }
                self.popup = self.popup.take().or_else(|| self.queued.pop());
            }
            Target::PaletteRow(row) => {
                if let Some(Popup::Palette(p)) = &self.popup
                    && let Some(a) = p.value_at(row) {
                        self.popup = None;
                        self.run(a);
                    }
            }
            Target::MenuRow(row) => {
                if let Some(Popup::Menu { items, .. }) = &self.popup
                    && let Some(&a) = items.get(row) {
                        self.popup = None;
                        self.run(a);
                    }
            }
            Target::MiniField(i) => {
                if let Some(Popup::Mini(m)) = &mut self.popup {
                    if m.focus == i {
                        if let Some((o, sel)) = &mut m.fields[i].choices {
                            *sel = (*sel + 1) % o.len();
                        } else {
                            m.fields[i].input.click(rel_x.saturating_sub(MINI_LABEL_W));
                        }
                    }
                    m.focus = i;
                }
            }
            Target::MiniButton(ok) => {
                if let Some(Popup::Mini(mut m)) = self.popup.take() {
                    if ok {
                        if !self.submit_mini(&mut m) {
                            self.popup = Some(Popup::Mini(m));
                            return;
                        }
                    } else if let MiniPurpose::Secret { id, .. } = m.purpose {
                        self.send(Cmd::SecretReply { id, secrets: None });
                    }
                    if self.popup.is_none() {
                        self.popup = self.queued.pop();
                    }
                }
            }
            Target::EditorRow(i) => {
                if let Some(Popup::Editor(ed)) = &mut self.popup {
                    ed.click_row(i, double, rel_x);
                }
            }
            Target::EditorButton(save) => {
                if let Some(Popup::Editor(mut ed)) = self.popup.take() {
                    if save {
                        match ed.try_save() {
                            Some(settings) => {
                                self.save_editor(&ed, settings);
                                self.popup = self.queued.pop();
                            }
                            None => self.popup = Some(Popup::Editor(ed)),
                        }
                    } else {
                        self.popup = self.queued.pop();
                    }
                }
            }
            Target::CloseShare => self.popup = None,
            Target::FilterBar => {
                if let Some(f) = &mut self.filter {
                    f.click(rel_x.saturating_sub(3));
                }
                self.filter_focus = true;
            }
            Target::WifiDevice(p) => {
                self.wifi_dev = Some(p);
                self.wifi_sel = None;
                self.fix_selection();
            }
        }
    }

    // ------------------------------------------------------------ dialogs

    fn submit_mini(&mut self, m: &mut Mini) -> bool {
        let v: Vec<String> = m.fields.iter().map(MiniField::value).collect();
        match m.purpose.clone() {
            MiniPurpose::Password { device, ap, ssid, security } => {
                let pw = v[0].clone();
                if security == Security::Wep {
                    if pw.is_empty() {
                        m.error = Some("enter the WEP key".into());
                        return false;
                    }
                } else if !(8..=63).contains(&pw.len()) && pw.len() != 64 {
                    m.error = Some("WPA passwords are 8–63 characters".into());
                    return false;
                }
                let mut s = form::wifi_join_settings(&ssid, security.key_mgmt(), &pw, false);
                self.apply_new_profile_defaults(&mut s);
                self.send(Cmd::ConnectWifi { device, ap, profile: None, settings: Some(s), label: ssid });
            }
            MiniPurpose::Hidden { device } => {
                let ssid = v[0].trim().to_string();
                if ssid.is_empty() || ssid.len() > 32 {
                    m.error = Some("network name must be 1–32 characters".into());
                    m.focus = 0;
                    return false;
                }
                let km = if v[1].is_empty() { None } else { Some(v[1].as_str()) };
                if km.is_some() && !(8..=63).contains(&v[2].len()) {
                    m.error = Some("WPA passwords are 8–63 characters".into());
                    m.focus = 2;
                    return false;
                }
                let mut s = form::wifi_join_settings(&ssid, km, &v[2], true);
                self.apply_new_profile_defaults(&mut s);
                self.send(Cmd::ConnectWifi { device, ap: "/".into(), profile: None, settings: Some(s), label: ssid });
            }
            MiniPurpose::Hotspot { device } => {
                let name = v[0].trim().to_string();
                if name.is_empty() || name.len() > 32 {
                    m.error = Some("hotspot name must be 1–32 characters".into());
                    m.focus = 0;
                    return false;
                }
                if !(8..=63).contains(&v[1].len()) {
                    m.error = Some("password must be 8–63 characters".into());
                    m.focus = 1;
                    return false;
                }
                let iface = self.snap.devices.iter().find(|d| d.path == device).map(|d| d.iface.clone()).unwrap_or_default();
                let s = form::hotspot_settings(&name, &v[1], &v[2], &iface);
                self.send(Cmd::AddProfile { settings: s, activate_on: Some(device) });
                self.toasts.push(Level::Info, format!("Starting hotspot “{name}”… (Wi-Fi client connection will drop)"));
            }
            MiniPurpose::Import => {
                let file = expand_home(v[0].trim());
                if !std::path::Path::new(&file).is_file() {
                    m.error = Some(format!("no such file: {file}"));
                    return false;
                }
                self.send(Cmd::Import { kind: v[1].clone(), file });
            }
            MiniPurpose::Hostname => {
                let h = v[0].trim().to_string();
                if h.is_empty() || h.len() > 64 || !h.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.') || h.starts_with('-') {
                    m.error = Some("letters, digits, '-' and '.' only".into());
                    return false;
                }
                self.send(Cmd::SetHostname(h));
            }
            MiniPurpose::Secret { id, req } => {
                if v[0].is_empty() {
                    m.error = Some("enter the password, or press Esc to cancel".into());
                    return false;
                }
                let mut d = Dict::new();
                d.insert(req.key.clone(), Val::Str(v[0].clone()));
                self.send(Cmd::SecretReply { id, secrets: Some(d) });
            }
        }
        true
    }

    fn apply_new_profile_defaults(&self, s: &mut crate::backend::val::Settings) {
        let mac = self.cfg.wifi.new_profile_mac.trim();
        if !mac.is_empty()
            && let Some(w) = s.get_mut("802-11-wireless") {
                w.insert("assigned-mac-address".into(), Val::Str(mac.to_string()));
            }
    }

    fn save_editor(&mut self, ed: &Editor, settings: crate::backend::val::Settings) {
        match &ed.path {
            Some(p) => self.send(Cmd::UpdateProfile { path: p.clone(), settings }),
            None => self.send(Cmd::AddProfile { settings, activate_on: ed.activate_on.clone() }),
        }
    }

    fn open_editor(&mut self, path: &str) {
        let Some(p) = self.profile(path) else { return };
        let form = Form::from_settings(&p.settings, false);
        for setting in form.secret_settings() {
            self.send(Cmd::GetSecrets { path: path.to_string(), setting: setting.to_string() });
        }
        let title = format!("Edit “{}”", p.id);
        self.popup = Some(Popup::Editor(Box::new(Editor::new(form, Some(path.to_string()), title, None))));
    }

    fn open_new_editor(&mut self, kind: &str) {
        let label = NEW_KINDS.iter().find(|k| k.0 == kind).map(|k| k.1).unwrap_or("Connection");
        let mut s = form::new_settings(kind, &format!("New {label}"));
        self.apply_new_profile_defaults(&mut s);
        let form = Form::from_settings(&s, true);
        self.popup = Some(Popup::Editor(Box::new(Editor::new(form, None, format!("New {label} connection"), None))));
    }

    fn open_menu(&mut self, at: Option<(u16, u16)>) {
        use Action::*;
        let items: Vec<Action> = match self.tab {
            Tab::Wifi => {
                let Some(n) = self.selected_network() else { return };
                let mut v = vec![Connect];
                if n.profile.is_some() {
                    v.extend([Edit, Autoconnect, Share, Forget]);
                } else if n.security.is_open() {
                    v.push(Share);
                }
                v
            }
            Tab::Connections => vec![Activate, EditProfile, ProfileAutoconnect, DeleteProfile],
            Tab::Devices => vec![DeviceToggle, Managed, DeviceAutoconnect],
            Tab::General => vec![GeneralActivate],
        };
        self.popup = Some(Popup::Menu { items, sel: 0, at: at.unwrap_or((0, 0)) });
    }

    fn confirm(&mut self, title: &str, msg: String, yes: &str, cmd: Cmd) {
        if self.cfg.general.confirm_delete {
            self.popup = Some(Popup::Confirm { title: title.into(), msg, yes: yes.into(), yes_sel: false, cmd });
        } else {
            self.send(cmd);
        }
    }

    // ------------------------------------------------------------ labels

    pub fn action_label(&self, a: Action) -> String {
        use Action::*;
        match a {
            Connect => match self.selected_network() {
                Some(n) if n.connected || n.connecting => "Disconnect".into(),
                _ => "Connect".into(),
            },
            Activate => if self.selected_profile().is_some_and(|p| p.is_active()) { "Deactivate" } else { "Activate" }.into(),
            DeviceToggle => if self.selected_device().is_some_and(|d| d.active.is_some()) { "Disconnect" } else { "Connect" }.into(),
            Autoconnect => {
                let on = self.selected_network().and_then(|n| n.profile).and_then(|p| self.profile(&p).map(|p| p.autoconnect)).unwrap_or(false);
                if on { "Don't auto-connect" } else { "Auto-connect" }.into()
            }
            ProfileAutoconnect => if self.selected_profile().is_some_and(|p| p.autoconnect) { "Don't auto-connect" } else { "Auto-connect" }.into(),
            Managed => if self.selected_device().is_some_and(|d| d.managed) { "Unmanage" } else { "Manage" }.into(),
            DeviceAutoconnect => if self.selected_device().is_some_and(|d| d.autoconnect) { "Don't auto-connect" } else { "Auto-connect" }.into(),
            WifiRadio => if self.snap.general.wifi_enabled { "Turn Wi-Fi off" } else { "Turn Wi-Fi on" }.into(),
            Hotspot => if self.hotspot_profile().is_some_and(|p| p.is_active()) { "Stop hotspot" } else { "Start hotspot" }.into(),
            Forget => "Forget".into(),
            Edit | EditProfile => "Edit".into(),
            Share => "Share (QR)".into(),
            DeleteProfile => "Delete".into(),
            other => other.description().into(),
        }
    }

    pub fn short_label(&self, a: Action) -> String {
        use Action::*;
        match a {
            Connect | Activate | DeviceToggle | Hotspot => self.action_label(a).to_lowercase(),
            Scan => "scan".into(),
            Edit | EditProfile => "edit".into(),
            Forget => "forget".into(),
            Hidden => "hidden".into(),
            Share => "share".into(),
            Filter => "filter".into(),
            Help => "help".into(),
            NewProfile => "new".into(),
            DeleteProfile => "delete".into(),
            Import => "import".into(),
            Managed => "managed".into(),
            DeviceAutoconnect => "auto".into(),
            GeneralActivate => "change".into(),
            Hostname => "hostname".into(),
            Airplane => "airplane".into(),
            CheckConnectivity => "check".into(),
            other => other.name().replace('_', " "),
        }
    }

    // ------------------------------------------------------------ run

    pub fn run(&mut self, a: Action) {
        use Action::*;
        self.popup = match self.popup.take() {
            Some(Popup::Menu { .. }) | Some(Popup::Palette(_)) => None,
            other => other,
        };
        match a {
            Quit => self.quit = true,
            Help => self.popup = Some(Popup::Help { scroll: 0, max: 0 }),
            Palette => {
                let ctx = self.ctx();
                let entries = Action::all()
                    .iter()
                    .copied()
                    .filter(|a| a.available(ctx) && !matches!(a, Palette | Up | Down | Top | Bottom | PageUp | PageDown))
                    .map(|a| Entry { label: self.action_label(a), keys: self.keymap.hint(a).unwrap_or_default(), value: a })
                    .collect();
                self.popup = Some(Popup::Palette(crate::ui::palette::Palette::new(entries)));
            }
            NextTab | PrevTab => {
                let i = Tab::ALL.iter().position(|t| *t == self.tab).unwrap_or(0);
                let n = Tab::ALL.len();
                self.tab = Tab::ALL[if a == NextTab { (i + 1) % n } else { (i + n - 1) % n }];
                self.list_offset = 0;
            }
            TabWifi => self.tab = Tab::Wifi,
            TabConnections => self.tab = Tab::Connections,
            TabDevices => self.tab = Tab::Devices,
            TabGeneral => self.tab = Tab::General,
            Up => self.move_sel(-1),
            Down => self.move_sel(1),
            Top => self.move_sel(-100_000),
            Bottom => self.move_sel(100_000),
            PageUp => self.move_sel(-(self.list_height.max(2) as isize - 1)),
            PageDown => self.move_sel(self.list_height.max(2) as isize - 1),
            Filter => {
                if matches!(self.tab, Tab::Devices | Tab::General) {
                    self.tab = Tab::Wifi;
                }
                if self.filter.is_none() {
                    self.filter = Some(TextInput::default().with_placeholder("type to filter"));
                }
                self.filter_focus = true;
            }
            Menu => self.open_menu(None),
            Details => self.show_details = !self.show_details,
            WifiRadio => self.send(Cmd::SetWifiEnabled(!self.snap.general.wifi_enabled)),

            Connect => self.connect_selected(),
            Scan => match self.wifi_dev.clone() {
                Some(d) if self.snap.general.wifi_enabled => {
                    self.send(Cmd::Scan(d));
                    self.toasts.push(Level::Info, "Scanning…");
                }
                Some(_) => self.toasts.push(Level::Warn, "Wi-Fi is off — press w to turn it on"),
                None => self.toasts.push(Level::Warn, "No Wi-Fi device"),
            },
            Forget => {
                let Some(n) = self.selected_network() else { return };
                let Some(p) = n.profile.clone() else {
                    return self.toasts.push(Level::Info, format!("“{}” isn't saved", n.ssid));
                };
                self.confirm("Forget network", format!("Forget “{}”? Its saved password and settings will be deleted.", n.ssid), "Forget", Cmd::DeleteProfile { path: p, label: n.ssid });
            }
            Edit => {
                let Some(n) = self.selected_network() else { return };
                match n.profile {
                    Some(p) => self.open_editor(&p),
                    None => self.toasts.push(Level::Info, "Connect first — or use the Connections tab to create a profile"),
                }
            }
            Autoconnect => {
                let Some(path) = self.selected_network().and_then(|n| n.profile) else {
                    return self.toasts.push(Level::Info, "Only saved networks can auto-connect");
                };
                self.toggle_profile_autoconnect(&path);
            }
            Hidden => {
                let Some(device) = self.wifi_dev.clone() else { return self.toasts.push(Level::Warn, "No Wi-Fi device") };
                let m = Mini {
                    title: "Hidden network".into(),
                    intro: "Join a network that doesn't broadcast its name.".into(),
                    fields: vec![
                        MiniField::text("Name (SSID)", ""),
                        MiniField::choice("Security", vec![("wpa-psk", "WPA/WPA2 personal"), ("sae", "WPA3 personal"), ("", "none (open)")], 0),
                        MiniField::secret("Password", ""),
                    ],
                    focus: 0,
                    ok_label: "Connect",
                    purpose: MiniPurpose::Hidden { device },
                    error: None,
                };
                self.popup = Some(Popup::Mini(Box::new(m)));
            }
            Hotspot => self.hotspot(),
            Share => self.share(),

            Activate => {
                let Some(p) = self.selected_profile().cloned() else { return };
                if p.is_active() {
                    if let Some(a) = self.snap.active.iter().find(|a| a.conn_path == p.path) {
                        self.send(Cmd::Deactivate { active: a.path.clone(), label: p.id.clone() });
                    }
                } else {
                    self.send(Cmd::Activate { profile: p.path.clone(), device: None, label: p.id.clone() });
                    self.toasts.push(Level::Info, format!("Activating {}…", p.id));
                }
            }
            NewProfile => self.popup = Some(Popup::NewKind { sel: 0 }),
            DeleteProfile => {
                let Some(p) = self.selected_profile().cloned() else { return };
                self.confirm("Delete connection", format!("Delete “{}” ({})? This can't be undone.", p.id, p.kind_label()), "Delete", Cmd::DeleteProfile { path: p.path, label: p.id });
            }
            EditProfile => {
                if let Some(p) = self.conn_sel.clone() {
                    self.open_editor(&p);
                }
            }
            ProfileAutoconnect => {
                if let Some(p) = self.conn_sel.clone() {
                    self.toggle_profile_autoconnect(&p);
                }
            }
            Import => {
                let m = Mini {
                    title: "Import VPN".into(),
                    intro: "Import an OpenVPN (.ovpn) or WireGuard (.conf) file.".into(),
                    fields: vec![
                        MiniField::text("File", "~/"),
                        MiniField::choice("Type", vec![("openvpn", "OpenVPN (needs networkmanager-openvpn)"), ("wireguard", "WireGuard")], 0),
                    ],
                    focus: 0,
                    ok_label: "Import",
                    purpose: MiniPurpose::Import,
                    error: None,
                };
                self.popup = Some(Popup::Mini(Box::new(m)));
            }

            DeviceToggle => {
                let Some(d) = self.selected_device().cloned() else { return };
                if !d.managed {
                    return self.toasts.push(Level::Info, format!("{} isn't managed by NetworkManager (press M to manage it)", d.iface));
                }
                if d.active.is_some() {
                    self.send(Cmd::DisconnectDevice { device: d.path.clone(), label: d.iface.clone() });
                } else {
                    // Let NM pick the best available profile for this device.
                    match d.available_connections.first() {
                        Some(c) => self.send(Cmd::Activate { profile: c.clone(), device: Some(d.path.clone()), label: d.iface.clone() }),
                        None => self.toasts.push(Level::Info, format!("No saved connection fits {} — create one in Connections", d.iface)),
                    }
                }
            }
            Managed => {
                let Some(d) = self.selected_device().cloned() else { return };
                self.send(Cmd::SetManaged { device: d.path, on: !d.managed });
            }
            DeviceAutoconnect => {
                let Some(d) = self.selected_device().cloned() else { return };
                self.send(Cmd::SetDeviceAutoconnect { device: d.path, on: !d.autoconnect });
            }

            GeneralActivate => match GenRow::ALL[self.gen_sel.min(GenRow::ALL.len() - 1)] {
                GenRow::Hostname => self.run(Hostname),
                GenRow::Networking => self.run(Networking),
                GenRow::WifiRadio => self.run(WifiRadio),
                GenRow::Wwan => self.send(Cmd::SetWwanEnabled(!self.snap.general.wwan_enabled)),
                GenRow::Airplane => self.run(Airplane),
                GenRow::Connectivity => self.run(CheckConnectivity),
            },
            Hostname => {
                let m = Mini {
                    title: "Hostname".into(),
                    intro: "This computer's name on the network.".into(),
                    fields: vec![MiniField::text("Hostname", &self.snap.general.hostname)],
                    focus: 0,
                    ok_label: "Save",
                    purpose: MiniPurpose::Hostname,
                    error: None,
                };
                self.popup = Some(Popup::Mini(Box::new(m)));
            }
            Networking => {
                let on = !self.snap.general.networking_enabled;
                if on {
                    self.send(Cmd::SetNetworkingEnabled(true));
                } else {
                    self.popup = Some(Popup::Confirm {
                        title: "Disable networking".into(),
                        msg: "Turn off ALL networking (every device disconnects)?".into(),
                        yes: "Turn off".into(),
                        yes_sel: false,
                        cmd: Cmd::SetNetworkingEnabled(false),
                    });
                }
            }
            Airplane => {
                let g = &self.snap.general;
                let airplane = !g.wifi_enabled && !g.wwan_enabled;
                self.send(Cmd::SetWifiEnabled(airplane));
                self.send(Cmd::SetWwanEnabled(airplane && g.wwan_hw_enabled));
                self.toasts.push(Level::Info, if airplane { "Airplane mode off" } else { "Airplane mode on (Wi-Fi and mobile off; Bluetooth is separate)" });
            }
            CheckConnectivity => {
                self.send(Cmd::CheckConnectivity);
                self.toasts.push(Level::Info, "Checking connectivity…");
            }
        }
    }

    fn toggle_profile_autoconnect(&mut self, path: &str) {
        let Some(p) = self.profile(path) else { return };
        let mut s = p.settings.clone();
        let on = !p.autoconnect;
        s.entry("connection".into()).or_default().insert("autoconnect".into(), Val::Bool(on));
        let id = p.id.clone();
        self.send(Cmd::UpdateProfile { path: path.to_string(), settings: s });
        self.toasts.push(Level::Ok, format!("{id}: auto-connect {}", if on { "on" } else { "off" }));
    }

    fn connect_selected(&mut self) {
        let Some(n) = self.selected_network() else { return };
        let Some(dev) = self.wifi_device().cloned() else { return };
        if !self.snap.general.wifi_enabled {
            return self.toasts.push(Level::Warn, "Wi-Fi is off — press w to turn it on");
        }
        if n.connected || n.connecting {
            return self.send(Cmd::DisconnectDevice { device: dev.path, label: n.ssid });
        }
        if let Some(p) = n.profile.clone() {
            self.send(Cmd::ConnectWifi { device: dev.path, ap: n.best_ap, profile: Some(p), settings: None, label: n.ssid });
        } else if n.security == Security::Enterprise {
            // Enterprise needs username, method, certificates: use the full editor.
            let mut s = form::wifi_join_settings(&n.ssid, Some("wpa-eap"), "", false);
            self.apply_new_profile_defaults(&mut s);
            let form = Form::from_settings(&s, true);
            let ed = Editor::new(form, None, format!("Join “{}” (enterprise)", n.ssid), Some(dev.path));
            self.popup = Some(Popup::Editor(Box::new(ed)));
        } else if n.security.needs_password() {
            let m = Mini {
                title: format!("Connect to {}", n.ssid),
                intro: format!("{} · {}% signal", n.security.label(), n.strength),
                fields: vec![MiniField::secret("Password", "")],
                focus: 0,
                ok_label: "Connect",
                purpose: MiniPurpose::Password { device: dev.path, ap: n.best_ap, ssid: n.ssid, security: n.security },
                error: None,
            };
            self.popup = Some(Popup::Mini(Box::new(m)));
        } else {
            let mut s = form::wifi_join_settings(&n.ssid, n.security.key_mgmt(), "", false);
            self.apply_new_profile_defaults(&mut s);
            if n.security == Security::Open {
                self.toasts.push(Level::Warn, format!("“{}” is open: others nearby can see your unencrypted traffic", n.ssid));
            }
            self.send(Cmd::ConnectWifi { device: dev.path, ap: n.best_ap, profile: None, settings: Some(s), label: n.ssid });
        }
    }

    fn hotspot(&mut self) {
        let Some(dev) = self.wifi_device().cloned() else { return self.toasts.push(Level::Warn, "No Wi-Fi device") };
        if let Some(p) = self.hotspot_profile().cloned() {
            if p.is_active() {
                if let Some(a) = self.snap.active.iter().find(|a| a.conn_path == p.path) {
                    self.send(Cmd::Deactivate { active: a.path.clone(), label: p.id.clone() });
                }
            } else {
                self.send(Cmd::Activate { profile: p.path.clone(), device: Some(dev.path), label: p.id.clone() });
                self.toasts.push(Level::Info, format!("Starting hotspot “{}” (edit it in Connections)", p.id));
            }
            return;
        }
        let name = if self.cfg.wifi.hotspot_name.is_empty() {
            format!("{}-hotspot", if self.snap.general.hostname.is_empty() { "linux" } else { &self.snap.general.hostname })
        } else {
            self.cfg.wifi.hotspot_name.clone()
        };
        let bands = vec![("bg", "2.4 GHz (best range)"), ("a", "5 GHz (faster)"), ("", "automatic")];
        let sel = bands.iter().position(|b| b.0 == self.cfg.wifi.hotspot_band).unwrap_or(0);
        let mut pw = MiniField::text("Password", &random_password(12));
        pw.input.masked = false; // it's a fresh suggestion; show it so it can be shared
        let m = Mini {
            title: "Start a hotspot".into(),
            intro: format!("Share this computer's connection over {}. Your Wi-Fi client connection will drop.", dev.iface),
            fields: vec![MiniField::text("Name", &name), pw, MiniField::choice("Band", bands, sel)],
            focus: 0,
            ok_label: "Start",
            purpose: MiniPurpose::Hotspot { device: dev.path },
            error: None,
        };
        self.popup = Some(Popup::Mini(Box::new(m)));
    }

    fn share(&mut self) {
        let Some(n) = self.selected_network() else { return };
        if n.security.is_open() {
            self.popup = Some(Popup::Share { ssid: n.ssid, security: n.security, password: Some(String::new()), waiting: None });
            return;
        }
        let Some(path) = n.profile else {
            return self.toasts.push(Level::Info, "Only saved networks can be shared (the password is needed)");
        };
        if n.security == Security::Enterprise {
            return self.toasts.push(Level::Info, "Enterprise networks can't be shared as a QR code");
        }
        self.send(Cmd::GetSecrets { path: path.clone(), setting: "802-11-wireless-security".into() });
        self.popup = Some(Popup::Share { ssid: n.ssid, security: n.security, password: None, waiting: Some(path) });
    }
}

/// Label column width in mini dialogs (also used for click offsets).
pub const MINI_LABEL_W: u16 = 14;

/// Key handling for small dialogs. Some(true) = submit, Some(false) = cancel.
fn mini_key(m: &mut Mini, k: &KeyEvent) -> Option<bool> {
    let n = m.fields.len();
    let ctrl = k.modifiers.contains(KeyModifiers::CONTROL);
    let f = &mut m.fields[m.focus];
    match k.code {
        KeyCode::Esc => return Some(false),
        KeyCode::Tab | KeyCode::Down => m.focus = (m.focus + 1) % n,
        KeyCode::BackTab | KeyCode::Up => m.focus = (m.focus + n - 1) % n,
        KeyCode::Char('r') if ctrl => {
            for f in &mut m.fields {
                if f.choices.is_none() && f.label.contains("assword") {
                    f.input.masked = !f.input.masked;
                }
            }
        }
        KeyCode::Enter => {
            if m.focus + 1 < n && f.choices.is_none() && m.fields[m.focus + 1..].iter().any(|x| x.choices.is_none() && x.input.is_empty()) {
                m.focus += 1; // fill the form top-down with Enter
            } else {
                return Some(true);
            }
        }
        KeyCode::Left | KeyCode::Right | KeyCode::Char(' ') if f.choices.is_some() => {
            let (o, sel) = f.choices.as_mut().expect("checked");
            let len = o.len();
            *sel = if k.code == KeyCode::Left { (*sel + len - 1) % len } else { (*sel + 1) % len };
        }
        _ => {
            if f.choices.is_none() {
                f.input.handle_key(k);
                m.error = None;
            }
        }
    }
    None
}

pub fn expand_home(p: &str) -> String {
    match p.strip_prefix("~/") {
        Some(rest) => dirs::home_dir().map(|h| h.join(rest).display().to_string()).unwrap_or_else(|| p.to_string()),
        None => p.to_string(),
    }
}

/// Random password from an unambiguous alphabet (no 0/O, 1/l/I).
pub fn random_password(len: usize) -> String {
    const A: &[u8] = b"abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let mut buf = vec![0u8; len];
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        use std::io::Read;
        let _ = f.read_exact(&mut buf);
    }
    buf.iter().map(|b| A[*b as usize % A.len()] as char).collect()
}

/// `WIFI:` QR payload understood by Android and iOS cameras.
pub fn wifi_qr_payload(ssid: &str, security: Security, password: &str) -> String {
    let esc = |s: &str| s.chars().fold(String::new(), |mut o, c| {
        if matches!(c, '\\' | ';' | ',' | ':' | '"') {
            o.push('\\');
        }
        o.push(c);
        o
    });
    let t = match security {
        Security::Open | Security::Owe => "nopass",
        Security::Wep => "WEP",
        Security::Wpa3 => "SAE",
        _ => "WPA",
    };
    if t == "nopass" {
        format!("WIFI:T:nopass;S:{};;", esc(ssid))
    } else {
        format!("WIFI:T:{t};S:{};P:{};;", esc(ssid), esc(password))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn qr_payload_escapes() {
        assert_eq!(wifi_qr_payload("My;Net", Security::Wpa2, "p:w\"d"), r#"WIFI:T:WPA;S:My\;Net;P:p\:w\"d;;"#);
        assert_eq!(wifi_qr_payload("Cafe", Security::Open, ""), "WIFI:T:nopass;S:Cafe;;");
    }

    #[test]
    fn random_password_is_unambiguous() {
        let p = random_password(32);
        assert_eq!(p.len(), 32);
        assert!(!p.contains(['0', 'O', '1', 'l', 'I']));
    }
}
