//! Rendering for network-tui.

use ratatui::{
    layout::{Constraint, Layout, Margin, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Paragraph, Wrap},
    Frame,
};
use unicode_width::UnicodeWidthStr;

use crate::action::Action;
use crate::app::{wifi_qr_payload, App, GenRow, Mini, Popup, Tab, Target, MINI_LABEL_W, NEW_KINDS};
use crate::backend::model::{band, channel, Connectivity, DevKind, DevState, Device, Network, Profile, Security};
use crate::config::{IconSet, SignalStyle};
use crate::core::keymap::ActionSet;
use crate::ui::theme::Theme;
use crate::ui::widgets::{self, centered, checkbox, empty_state, panel, popup, signal_bars, spinner, toggle, truncate, HelpRow};

pub fn render(app: &mut App, f: &mut Frame) {
    app.mouse.clear();
    let area = f.area();
    let [header, body, footer] = Layout::vertical([Constraint::Length(1), Constraint::Min(3), Constraint::Length(1)]).areas(area);
    render_header(app, f, header);
    if let Some(m) = app.unavailable.clone() {
        empty_state(f, body, &app.theme, "NetworkManager is unavailable", &[&m]);
    } else if !app.loaded {
        empty_state(f, body, &app.theme, &format!("{} Talking to NetworkManager…", spinner(app.tick)), &[]);
    } else {
        match app.tab {
            Tab::Wifi => render_wifi(app, f, body),
            Tab::Connections => render_connections(app, f, body),
            Tab::Devices => render_devices(app, f, body),
            Tab::General => render_general(app, f, body),
        }
    }
    render_footer(app, f, footer);
    app.toasts.render(f, body, &app.theme);
    render_popup(app, f, area);
}

fn render_header(app: &mut App, f: &mut Frame, area: Rect) {
    let t = app.theme.clone();
    let mut right: Vec<Span> = Vec::new();
    if app.demo {
        right.push(Span::styled(" DEMO ", Style::default().add_modifier(Modifier::REVERSED)));
        right.push(Span::raw(" "));
    }
    if app.loaded && app.unavailable.is_none() {
        let primary = app.snap.active.iter().find(|a| a.default4).map(|a| a.id.clone());
        // The connection name is the first thing to go on narrow screens, so the tabs fit.
        if let (Some(p), true) = (primary, area.width >= 80) {
            right.push(Span::styled(format!("{} ", truncate(&p, 24)), t.text()));
        }
        let (dot, style) = match app.snap.general.connectivity {
            Connectivity::Full => ("● online", t.ok()),
            Connectivity::Limited => ("◐ limited", t.warn()),
            Connectivity::Portal => ("◐ sign-in needed", t.warn()),
            Connectivity::None => ("○ offline", t.error()),
            Connectivity::Unknown => ("○ unknown", t.dim()),
        };
        right.push(Span::styled(format!("{dot} "), style));
    }
    let rw: u16 = right.iter().map(|s| s.content.width() as u16).sum();
    let titles: Vec<&str> = Tab::ALL.iter().map(|t| t.title()).collect();
    let sel = Tab::ALL.iter().position(|x| *x == app.tab).unwrap_or(0);
    let tabs_area = Rect { width: area.width.saturating_sub(rw), ..area };
    widgets::tabs(f, tabs_area, &titles, sel, &t, &mut app.mouse, Target::Tab);
    if rw <= area.width {
        f.render_widget(Line::from(right), Rect { x: area.right() - rw, width: rw, ..area });
    }
}

fn render_footer(app: &mut App, f: &mut Frame, area: Rect) {
    let items: Vec<(String, String, Target)> = Action::footer(app.ctx())
        .iter()
        .filter_map(|&a| app.keymap.hint(a).map(|k| (k, app.short_label(a), Target::Run(a))))
        .collect();
    let area = Rect { x: area.x + 1, width: area.width.saturating_sub(2), ..area };
    widgets::hints(f, area, &items, &app.theme, &mut app.mouse);
}

/// Split into list + optional details panel.
fn split(app: &App, area: Rect, details_w: u16) -> (Rect, Option<Rect>) {
    if app.show_details && area.width >= 60 + details_w {
        let [l, d] = Layout::horizontal([Constraint::Min(50), Constraint::Length(details_w)]).areas(area);
        (l, Some(d))
    } else {
        (area, None)
    }
}

/// Shared list chrome: block, filter bar, scroll handling. Returns inner rect.
fn list_frame(app: &mut App, f: &mut Frame, area: Rect, title: &str) -> Rect {
    let focused = !app.filter_focus;
    let block = panel(&app.theme, title, focused);
    let mut inner = block.inner(area);
    f.render_widget(block, area);
    if let Some(fi) = &app.filter {
        let fb = Rect { y: inner.bottom().saturating_sub(1), height: 1, ..inner };
        inner.height = inner.height.saturating_sub(1);
        f.render_widget(Span::styled(" / ", app.theme.key()), Rect { width: 3, ..fb });
        fi.render(f, Rect { x: fb.x + 3, width: fb.width.saturating_sub(3), ..fb }, &app.theme, app.filter_focus);
        app.mouse.add(fb, crate::app::Target::FilterBar);
    }
    inner
}

/// Compute scroll offset so `sel` (a row index into `total`) is visible.
fn scroll(app: &mut App, sel: Option<usize>, total: usize, height: usize) -> usize {
    let mut off = app.list_offset.min(total.saturating_sub(height));
    if let Some(i) = sel {
        if i < off {
            off = i;
        } else if i >= off + height {
            off = i + 1 - height;
        }
    }
    app.list_offset = off;
    app.list_height = height;
    off
}

fn signal(app: &App, strength: u8) -> Vec<Span<'static>> {
    let t = &app.theme;
    match app.cfg.general.signal {
        SignalStyle::Bars => vec![signal_bars(strength, t)],
        SignalStyle::Percent => vec![Span::styled(format!("{strength:>3}%"), t.dim())],
        SignalStyle::Both => vec![signal_bars(strength, t), Span::styled(format!(" {strength:>3}%"), t.dim())],
    }
}

fn lock(app: &App, s: Security) -> &'static str {
    match (app.cfg.general.icons, s.is_open()) {
        (IconSet::Nerd, false) => "󰌾",
        (IconSet::Nerd, true) => "󰿆",
        (IconSet::Unicode, false) => "⚿",
        (_, true) => " ",
        (IconSet::Ascii, false) => "*",
    }
}

// ---------------------------------------------------------------- Wi-Fi

fn render_wifi(app: &mut App, f: &mut Frame, area: Rect) {
    let t = app.theme.clone();
    let wifi_devs: Vec<Device> = app.wifi_devices().into_iter().cloned().collect();
    if wifi_devs.is_empty() {
        return empty_state(f, area, &t, "No Wi-Fi device", &["NetworkManager doesn't see a wireless card.", "Check `rfkill list` and that the driver is loaded. Other connections are in tab 2."]);
    }
    let (list_area, details) = split(app, area, 46);
    let mut inner = list_frame(app, f, list_area, "Wi-Fi");

    // Device chooser when there's more than one card.
    if wifi_devs.len() > 1 {
        let mut x = inner.x + 1;
        f.render_widget(Span::styled("Device:", t.dim()), Rect::new(x, inner.y, 7, 1));
        x += 8;
        for d in &wifi_devs {
            let label = format!(" {} ", d.iface);
            let w = label.width() as u16;
            let cur = app.wifi_dev.as_deref() == Some(d.path.as_str());
            let st = if cur { t.accent().add_modifier(Modifier::REVERSED) } else { t.dim() };
            let r = Rect::new(x, inner.y, w, 1);
            f.render_widget(Span::styled(label, st), r);
            app.mouse.add(r, Target::WifiDevice(d.path.clone()));
            x += w + 1;
        }
        inner.y += 2;
        inner.height = inner.height.saturating_sub(2);
    }
    // Banners.
    let banner = |f: &mut Frame, msg: String, style: Style, target: Option<Target>, inner: &mut Rect, app: &mut App| {
        let b = Rect { height: 1, ..*inner };
        f.render_widget(Span::styled(msg, style), b);
        if let Some(tg) = target {
            app.mouse.add(b, tg);
        }
        inner.y += 2;
        inner.height = inner.height.saturating_sub(2);
    };
    if !app.snap.general.wifi_enabled {
        let k = app.keymap.hint(Action::WifiRadio).unwrap_or_default();
        banner(f, format!(" Wi-Fi is off — press {k} or click here to turn it on "), t.warn().add_modifier(Modifier::REVERSED), Some(Target::Run(Action::WifiRadio)), &mut inner, app);
    } else if !app.snap.general.wifi_hw_enabled {
        banner(f, " Wi-Fi is disabled by a hardware switch ".into(), t.error().add_modifier(Modifier::REVERSED), None, &mut inner, app);
    }
    if let Some(h) = app.hotspot_profile().filter(|p| p.is_active()).cloned() {
        let k = app.keymap.hint(Action::Hotspot).unwrap_or_default();
        banner(f, format!(" 󰀂 Hotspot “{}” is on — {k} to stop ", h.id), t.info().add_modifier(Modifier::REVERSED), Some(Target::Run(Action::Hotspot)), &mut inner, app);
    }

    let nets = app.networks();
    let saved_count = nets.iter().filter(|n| n.profile.is_some()).count();
    enum Row<'a> {
        Header(String),
        Net(usize, &'a Network),
        Hint(&'static str),
    }
    let mut rows = Vec::new();
    rows.push(Row::Header(format!("Saved · {saved_count}")));
    if saved_count == 0 {
        rows.push(Row::Hint("no saved networks in range"));
    }
    for (i, n) in nets.iter().enumerate().filter(|(_, n)| n.profile.is_some()) {
        rows.push(Row::Net(i, n));
    }
    rows.push(Row::Hint(""));
    rows.push(Row::Header(format!("Other networks · {}", nets.len() - saved_count)));
    if nets.len() == saved_count {
        rows.push(Row::Hint(if app.snap.general.wifi_enabled { "nothing else in range — press s to scan" } else { "" }));
    }
    for (i, n) in nets.iter().enumerate().filter(|(_, n)| n.profile.is_none()) {
        rows.push(Row::Net(i, n));
    }
    let sel = app.selected_index();
    let sel_row = sel.and_then(|s| rows.iter().position(|r| matches!(r, Row::Net(i, _) if *i == s)));
    let off = scroll(app, sel_row, rows.len(), inner.height as usize);
    let busy_dev = app.wifi_dev.as_ref().and_then(|d| app.busy.get(d)).cloned();
    for (n, row) in rows.iter().enumerate().skip(off).take(inner.height as usize) {
        let r = Rect { y: inner.y + (n - off) as u16, height: 1, ..inner };
        match row {
            Row::Header(h) => f.render_widget(Span::styled(format!(" {}", h.to_uppercase()), t.dim().add_modifier(Modifier::BOLD)), r),
            Row::Hint(h) => f.render_widget(Span::styled(format!("   {h}"), t.dim().add_modifier(Modifier::ITALIC)), r),
            Row::Net(i, net) => {
                let selected = sel == Some(*i);
                let base = if selected { t.selected(!app.filter_focus) } else { Style::default() };
                f.render_widget(Span::styled(" ".repeat(r.width as usize), base), r);
                // Fixed-width right columns: security · bands · status.
                let (status, st_style) = if net.connecting {
                    let label = busy_dev.clone().unwrap_or_else(|| "connecting".into());
                    (format!("{} {}…", spinner(app.tick), truncate(&label, 10)), t.info())
                } else if net.connected {
                    ("● connected".to_string(), t.ok())
                } else if let Some(p) = net.profile.as_ref().and_then(|p| app.profile(p)) {
                    ((if p.autoconnect { "auto" } else { "manual" }).to_string(), t.dim())
                } else {
                    (String::new(), t.dim())
                };
                let bands: Vec<&str> = net.bands.iter().map(|b| match *b { "2.4 GHz" => "2.4", "5 GHz" => "5", "6 GHz" => "6", o => o }).collect();
                let right = vec![
                    Span::styled(format!("{:<8}", net.security.label()), if net.security.is_open() { t.warn() } else { t.dim() }),
                    Span::styled(format!("{:<8}", bands.join("/")), t.dim()),
                    Span::styled(format!("{:<14}", truncate(&status, 14)), st_style),
                ];
                let rw = 30usize;
                let mut spans = vec![if selected { Span::styled("▌", t.accent()) } else { Span::raw(" ") }];
                spans.extend(signal(app, net.strength));
                spans.push(Span::styled(format!(" {} ", lock(app, net.security)), t.dim()));
                let used: usize = spans.iter().map(|s| s.content.width()).sum();
                let avail = (r.width as usize).saturating_sub(used + rw + 1);
                let name = truncate(&net.ssid, avail);
                let pad = avail.saturating_sub(name.width());
                spans.push(Span::styled(name, if net.connected { t.bold() } else { t.text() }));
                spans.push(Span::raw(" ".repeat(pad + 1)));
                spans.extend(right);
                f.render_widget(Line::from(spans).style(base), r);
                app.mouse.add(r, Target::Row(*i));
            }
        }
    }
    if let Some(d) = details {
        let n = app.selected_network();
        wifi_details(app, f, d, n);
    }
}

struct Kv<'a> {
    lines: Vec<(Line<'a>, Option<Target>)>,
    t: Theme,
}

impl<'a> Kv<'a> {
    fn new(t: &Theme) -> Self {
        Self { lines: Vec::new(), t: t.clone() }
    }
    fn title(&mut self, s: &str) {
        self.lines.push((Line::from(Span::styled(s.to_string(), self.t.accent().add_modifier(Modifier::BOLD))), None));
    }
    fn kv(&mut self, k: &str, v: impl Into<String>) {
        let v = v.into();
        if v.is_empty() {
            return;
        }
        self.lines.push((Line::from(vec![Span::styled(format!("{k:<11}"), self.t.dim()), Span::styled(v, self.t.text())]), None));
    }
    fn kvs(&mut self, k: &str, v: Span<'a>, target: Option<Target>) {
        self.lines.push((Line::from(vec![Span::styled(format!("{k:<11}"), self.t.dim()), v]), target));
    }
    fn gap(&mut self) {
        self.lines.push((Line::raw(""), None));
    }
    fn section(&mut self, s: &str) {
        self.gap();
        self.lines.push((Line::from(Span::styled(s.to_uppercase(), self.t.dim().add_modifier(Modifier::BOLD))), None));
    }
    fn note(&mut self, s: &str, style: Style) {
        self.lines.push((Line::from(Span::styled(s.to_string(), style)), None));
    }
    fn render(self, f: &mut Frame, area: Rect, app: &mut App, title: &str) {
        let block = panel(&app.theme, title, false);
        let inner = block.inner(area).inner(Margin::new(1, 0));
        f.render_widget(block, area);
        for (i, (l, tg)) in self.lines.into_iter().enumerate() {
            if i as u16 >= inner.height {
                break;
            }
            let r = Rect { y: inner.y + i as u16, height: 1, ..inner };
            f.render_widget(widgets::fit_line(l, r.width as usize), r);
            if let Some(tg) = tg {
                app.mouse.add(r, tg);
            }
        }
    }
}

fn ip_lines(kv: &mut Kv, d: &Device) {
    if !d.ip4.addresses.is_empty() {
        kv.kv("IPv4", d.ip4.addresses.join(", "));
        kv.kv("Gateway", d.ip4.gateway.clone());
        kv.kv("DNS", d.ip4.dns.join(", "));
    }
    if !d.ip6.addresses.is_empty() {
        kv.kv("IPv6", d.ip6.addresses.first().cloned().unwrap_or_default());
    }
}

fn wifi_details(app: &mut App, f: &mut Frame, area: Rect, n: Option<Network>) {
    let t = app.theme.clone();
    let mut kv = Kv::new(&t);
    let Some(n) = n else {
        kv.note("select a network", t.dim());
        return kv.render(f, area, app, "Details");
    };
    kv.title(&n.ssid);
    kv.gap();
    let ap = app.snap.aps.get(&n.best_ap).cloned();
    kv.kvs("Signal", Span::styled(format!("{}%", n.strength), t.text()), None);
    kv.kvs("Security", Span::styled(n.security.label().to_string(), if n.security.is_open() { t.warn() } else { t.text() }), None);
    if let Some(ap) = &ap {
        kv.kv("Band", format!("{} · channel {}", band(ap.freq), channel(ap.freq)));
        kv.kv("Access pt", format!("{}{}", ap.bssid, if n.ap_count > 1 { format!("  (+{} more)", n.ap_count - 1) } else { String::new() }));
        if ap.max_bitrate_kbps > 0 {
            kv.kv("Max rate", format!("{} Mb/s", ap.max_bitrate_kbps / 1000));
        }
    }
    if n.security.is_open() {
        kv.note("⚠ unencrypted: nearby people can see your traffic", t.warn());
    }
    if let Some(p) = n.profile.as_ref().and_then(|p| app.profile(p)).cloned() {
        kv.section("Saved profile");
        kv.kv("Name", p.id.clone());
        kv.kvs("Auto", checkbox(p.autoconnect, &t), Some(Target::Run(Action::Autoconnect)));
        kv.kv("Last used", ago(p.timestamp));
        kv.kv("IPv4", p.ipv4_summary());
        let mac = p.settings.get("802-11-wireless").map(|w| crate::backend::val::DictExt::s(w, "assigned-mac-address")).unwrap_or_default();
        kv.kv("MAC", mac_label(&mac));
    }
    if n.connected
        && let Some(d) = app.wifi_device().cloned() {
            kv.section("Connection");
            ip_lines(&mut kv, &d);
            if d.bitrate_kbps > 0 {
                kv.kv("Link rate", format!("{} Mb/s", d.bitrate_kbps / 1000));
            }
            let randomized = !d.perm_hw_addr.is_empty() && !d.perm_hw_addr.eq_ignore_ascii_case(&d.hw_addr);
            kv.kv("Your MAC", format!("{}{}", d.hw_addr, if randomized { " (randomized)" } else { "" }));
        }
    kv.render(f, area, app, "Details");
}

fn mac_label(m: &str) -> String {
    match m {
        "" => "default".into(),
        "stable" => "random per network (stable)".into(),
        "random" => "random every connection".into(),
        "permanent" => "real hardware address".into(),
        "preserve" => "keep current".into(),
        other => other.into(),
    }
}

fn ago(ts: u64) -> String {
    if ts == 0 {
        return "never".into();
    }
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(ts);
    let d = now.saturating_sub(ts);
    match d {
        0..=59 => "just now".into(),
        60..=3599 => format!("{}m ago", d / 60),
        3600..=86_399 => format!("{}h ago", d / 3600),
        86_400..=2_591_999 => format!("{}d ago", d / 86_400),
        _ => format!("{}mo ago", d / 2_592_000),
    }
}

// ---------------------------------------------------------------- Connections

fn render_connections(app: &mut App, f: &mut Frame, area: Rect) {
    let t = app.theme.clone();
    let (list_area, details) = split(app, area, 46);
    let inner = list_frame(app, f, list_area, "Connections");
    let profs: Vec<Profile> = app.profiles().into_iter().cloned().collect();
    let [head, list] = Layout::vertical([Constraint::Length(1), Constraint::Min(1)]).areas(inner);
    let cols = |name: String, kind: &str, dev: &str, last: &str| format!("{name}  {kind:<10} {dev:<9} {last:>9}");
    let name_w = (head.width as usize).saturating_sub(36).max(10);
    f.render_widget(Span::styled(format!("  {}", cols(format!("{:<name_w$}", "NAME"), "TYPE", "DEVICE", "LAST USED")), t.dim().add_modifier(Modifier::BOLD)), head);
    if profs.is_empty() {
        f.render_widget(Span::styled("   no connections", t.dim()), list);
    }
    let sel = app.selected_index();
    let off = scroll(app, sel, profs.len(), list.height as usize);
    for (i, p) in profs.iter().enumerate().skip(off).take(list.height as usize) {
        let r = Rect { y: list.y + (i - off) as u16, height: 1, ..list };
        let selected = sel == Some(i);
        let base = if selected { t.selected(!app.filter_focus) } else { Style::default() };
        f.render_widget(Span::styled(" ".repeat(r.width as usize), base), r);
        let busy = app.busy.contains_key(&p.path);
        let dot = if busy {
            Span::styled(format!("{} ", spinner(app.tick)), t.info())
        } else if p.active_state == Some(2) {
            Span::styled("● ", t.ok())
        } else if p.active_state == Some(1) {
            Span::styled(format!("{} ", spinner(app.tick)), t.info())
        } else {
            Span::styled("○ ", t.dim())
        };
        let mut name = truncate(&p.id, name_w.saturating_sub(5));
        if !p.autoconnect {
            name.push_str(" ⏸");
        }
        let dev = p.active_devices.first().cloned().unwrap_or_else(|| if p.iface.is_empty() { "—".into() } else { p.iface.clone() });
        let line = Line::from(vec![
            if selected { Span::styled("▌", t.accent()) } else { Span::raw(" ") },
            dot,
            Span::styled(format!("{name:<name_w$}"), if p.is_active() { t.bold() } else { t.text() }),
            Span::styled(format!("  {:<10} {:<9} {:>9}", p.kind_label(), truncate(&dev, 9), ago(p.timestamp)), t.dim()),
        ]);
        f.render_widget(widgets::fit_line(line, r.width as usize).style(base), r);
        app.mouse.add(r, Target::Row(i));
    }
    if let Some(d) = details {
        let p = app.selected_profile().cloned();
        let mut kv = Kv::new(&t);
        match p {
            None => kv.note("select a connection", t.dim()),
            Some(p) => {
                kv.title(&p.id);
                kv.gap();
                kv.kv("Type", p.kind_label().to_string());
                let state = match p.active_state {
                    Some(2) => Span::styled(format!("● active on {}", p.active_devices.join(", ")), t.ok()),
                    Some(1) => Span::styled("connecting…", t.info()),
                    _ => Span::styled("○ inactive", t.dim()),
                };
                kv.kvs("State", state, Some(Target::Run(Action::Activate)));
                kv.kvs("Auto", checkbox(p.autoconnect, &t), Some(Target::Run(Action::ProfileAutoconnect)));
                if p.priority != 0 {
                    kv.kv("Priority", p.priority.to_string());
                }
                kv.kv("Device", if p.iface.is_empty() { "any".into() } else { p.iface.clone() });
                if let Some(s) = &p.ssid {
                    kv.kv("SSID", s.clone());
                }
                kv.kv("IPv4", p.ipv4_summary());
                kv.kv("Last used", ago(p.timestamp));
                kv.kv("UUID", p.uuid.clone());
                if !p.filename.is_empty() {
                    kv.section("Stored in");
                    kv.note(&p.filename, t.dim());
                }
                if p.unsaved {
                    kv.note("⚠ has unsaved changes (in memory only)", t.warn());
                }
            }
        }
        kv.render(f, d, app, "Details");
    }
}

// ---------------------------------------------------------------- Devices

fn state_style(t: &Theme, s: DevState) -> Style {
    match s {
        DevState::Connected => t.ok(),
        DevState::Failed => t.error(),
        DevState::Connecting | DevState::NeedAuth | DevState::Disconnecting => t.info(),
        DevState::Unmanaged | DevState::Unavailable | DevState::Unknown => t.dim(),
        DevState::Disconnected => t.text(),
    }
}

fn render_devices(app: &mut App, f: &mut Frame, area: Rect) {
    let t = app.theme.clone();
    let (list_area, details) = split(app, area, 46);
    let inner = list_frame(app, f, list_area, "Devices");
    let devs: Vec<Device> = app.devices().into_iter().cloned().collect();
    let [head, list] = Layout::vertical([Constraint::Length(1), Constraint::Min(1)]).areas(inner);
    f.render_widget(Span::styled(format!("  {:<12} {:<10} {:<14} {:<18} {}", "DEVICE", "TYPE", "STATE", "CONNECTION", "ADDRESS"), t.dim().add_modifier(Modifier::BOLD)), head);
    let sel = app.selected_index();
    let off = scroll(app, sel, devs.len(), list.height as usize);
    for (i, d) in devs.iter().enumerate().skip(off).take(list.height as usize) {
        let r = Rect { y: list.y + (i - off) as u16, height: 1, ..list };
        let selected = sel == Some(i);
        let base = if selected { t.selected(true) } else { Style::default() };
        f.render_widget(Span::styled(" ".repeat(r.width as usize), base), r);
        let conn = d.active.as_ref().and_then(|a| app.snap.active.iter().find(|x| &x.path == a)).map(|a| a.id.clone()).unwrap_or_else(|| "—".into());
        let state = if app.busy.contains_key(&d.path) || d.state.busy() { format!("{} {}", spinner(app.tick), d.state.label()) } else { d.state.label().to_string() };
        let line = Line::from(vec![
            if selected { Span::styled("▌", t.accent()) } else { Span::raw(" ") },
            Span::styled(format!(" {:<12} ", truncate(&d.iface, 12)), if d.state == DevState::Connected { t.bold() } else { t.text() }),
            Span::styled(format!("{:<10} ", d.kind.label()), t.dim()),
            Span::styled(format!("{:<14} ", state), state_style(&t, d.state)),
            Span::styled(format!("{:<18} ", truncate(&conn, 18)), t.text()),
            Span::styled(d.ip4.addresses.first().cloned().unwrap_or_default(), t.dim()),
        ]);
        f.render_widget(widgets::fit_line(line, r.width as usize).style(base), r);
        app.mouse.add(r, Target::Row(i));
    }
    if let Some(dr) = details {
        let mut kv = Kv::new(&t);
        match app.selected_device().cloned() {
            None => kv.note("select a device", t.dim()),
            Some(d) => {
                kv.title(&d.iface);
                kv.gap();
                kv.kv("Type", d.kind.label().to_string());
                kv.kvs("State", Span::styled(d.state.label().to_string(), state_style(&t, d.state)), None);
                if (d.state == DevState::Failed || d.state == DevState::Disconnected)
                    && let Some(r) = crate::backend::model::reason_text(d.state_reason) {
                        kv.note(&format!("last: {r}"), t.dim());
                    }
                kv.kv("Driver", d.driver.clone());
                kv.kv("MAC", d.hw_addr.clone());
                if !d.perm_hw_addr.is_empty() && !d.perm_hw_addr.eq_ignore_ascii_case(&d.hw_addr) {
                    kv.kv("Real MAC", format!("{} (hidden)", d.perm_hw_addr));
                }
                if d.mtu > 0 {
                    kv.kv("MTU", d.mtu.to_string());
                }
                if d.kind == DevKind::Ethernet {
                    let cable = match d.carrier {
                        Some(true) => format!("plugged in{}", if d.speed > 0 { format!(" · {} Mb/s", d.speed) } else { String::new() }),
                        Some(false) => "unplugged".into(),
                        None => String::new(),
                    };
                    kv.kv("Cable", cable);
                }
                if !d.ip4.addresses.is_empty() || !d.ip6.addresses.is_empty() {
                    kv.section("Addresses");
                    ip_lines(&mut kv, &d);
                }
                kv.section("Settings");
                kv.kvs("Managed", checkbox(d.managed, &t), Some(Target::Run(Action::Managed)));
                kv.kvs("Auto", checkbox(d.autoconnect, &t), Some(Target::Run(Action::DeviceAutoconnect)));
                if !d.managed {
                    kv.note("Not managed: something else (docker, libvirt, systemd-networkd) owns it.", t.dim());
                }
            }
        }
        kv.render(f, dr, app, "Details");
    }
}

// ---------------------------------------------------------------- General

fn render_general(app: &mut App, f: &mut Frame, area: Rect) {
    let t = app.theme.clone();
    let block = panel(&t, "General", true);
    let inner = block.inner(area).inner(Margin::new(1, 1));
    f.render_widget(block, area);
    let g = app.snap.general.clone();
    let airplane = !g.wifi_enabled && !g.wwan_enabled;
    for (i, row) in GenRow::ALL.iter().enumerate() {
        let r = Rect { y: inner.y + (i as u16) * 2, height: 1, ..inner };
        if r.y >= inner.bottom() {
            break;
        }
        let selected = app.gen_sel == i;
        let base = if selected { t.selected(true) } else { Style::default() };
        f.render_widget(Span::styled(" ".repeat(r.width as usize), base), r);
        let (label, value, note): (&str, Span, String) = match row {
            GenRow::Hostname => ("Hostname", Span::styled(g.hostname.clone(), t.bold()), "this computer's name on the network".into()),
            GenRow::Networking => ("Networking", toggle(g.networking_enabled, &t), "master switch for every device".into()),
            GenRow::WifiRadio => ("Wi-Fi", toggle(g.wifi_enabled, &t), if g.wifi_hw_enabled { "radio on/off".into() } else { "blocked by hardware switch".into() }),
            GenRow::Wwan => ("Mobile data", toggle(g.wwan_enabled, &t), if g.wwan_hw_enabled { "WWAN radio".into() } else { "no modem".into() }),
            GenRow::Airplane => ("Airplane mode", toggle(airplane, &t), "Wi-Fi + mobile off (Bluetooth is in bluetooth-tui)".into()),
            GenRow::Connectivity => (
                "Internet",
                Span::styled(g.connectivity.label().to_string(), match g.connectivity {
                    Connectivity::Full => t.ok(),
                    Connectivity::None => t.error(),
                    _ => t.warn(),
                }),
                if g.connectivity_check_enabled { "press Enter to check now".into() } else { "connectivity checking is disabled in NM".into() },
            ),
        };
        let line = Line::from(vec![
            if selected { Span::styled("▌", t.accent()) } else { Span::raw(" ") },
            Span::styled(format!("{label:<16}"), t.text()),
            value,
            Span::raw("   "),
            Span::styled(note, t.dim()),
        ]);
        f.render_widget(widgets::fit_line(line, r.width as usize).style(base), r);
        app.mouse.add(r, Target::Row(i));
    }
    let y = inner.y + GenRow::ALL.len() as u16 * 2 + 1;
    let info = [
        ("NetworkManager", if g.version.is_empty() { "?".into() } else { g.version.clone() }),
        ("Wi-Fi backend", g.wifi_backend.clone().unwrap_or_else(|| "wpa_supplicant (default)".into())),
        ("Config", app.cfg_path.display().to_string()),
    ];
    for (i, (k, v)) in info.iter().enumerate() {
        let r = Rect { y: y + i as u16, height: 1, ..inner };
        if r.y >= inner.bottom() {
            break;
        }
        f.render_widget(Line::from(vec![Span::styled(format!(" {k:<16}"), t.dim()), Span::styled(v.clone(), t.dim())]), r);
    }
}

// ---------------------------------------------------------------- popups

fn render_popup(app: &mut App, f: &mut Frame, area: Rect) {
    let t = app.theme.clone();
    let Some(mut p) = app.popup.take() else { return };
    match &mut p {
        Popup::Help { scroll, max } => {
            app.mouse.modal_barrier();
            let rows = help_rows(app);
            *max = widgets::help(f, area, &t, "network-tui · help", &rows, *scroll);
        }
        Popup::Palette(pal) => pal.render(f, area, &t, &mut app.mouse, Target::PaletteRow),
        Popup::Menu { items, sel, at } => {
            app.mouse.modal_barrier();
            let labels: Vec<(String, String)> = items.iter().map(|&a| (app.action_label(a), app.keymap.hint(a).unwrap_or_default())).collect();
            let w = labels.iter().map(|(l, k)| l.width() + k.width() + 4).max().unwrap_or(10) as u16 + 2;
            let h = items.len() as u16 + 2;
            let (mut x, mut y) = *at;
            if (x, y) == (0, 0) {
                let c = centered(area, w, h);
                (x, y) = (c.x, c.y);
            }
            let r = Rect::new(x.min(area.right().saturating_sub(w)), y.min(area.bottom().saturating_sub(h)), w, h);
            let inner = popup(f, r, &t, "Actions");
            for (i, (l, k)) in labels.iter().enumerate() {
                let rr = Rect { y: inner.y + i as u16, height: 1, ..inner };
                let style = if i == *sel { t.selected(true) } else { t.text() };
                let danger = matches!(items[i], Action::Forget | Action::DeleteProfile);
                let pad = (inner.width as usize).saturating_sub(l.width() + k.width() + 2);
                f.render_widget(Line::from(vec![Span::styled(format!(" {l}"), if danger { style.patch(t.error()) } else { style }), Span::styled(" ".repeat(pad), style), Span::styled(format!("{k} "), style.patch(t.dim()))]), rr);
                app.mouse.add(rr, Target::MenuRow(i));
            }
        }
        Popup::Confirm { title, msg, yes, yes_sel, .. } => widgets::confirm(f, area, &t, title, msg, yes, *yes_sel, &mut app.mouse, Target::Confirm),
        Popup::Mini(m) => render_mini(app, f, area, m),
        Popup::Editor(ed) => ed.render(f, area, &t, &mut app.mouse),
        Popup::Share { ssid, security, password, .. } => render_share(app, f, area, ssid, *security, password.as_deref()),
        Popup::NewKind { sel } => {
            app.mouse.modal_barrier();
            let r = centered(area, 40, NEW_KINDS.len() as u16 + 4);
            let inner = popup(f, r, &t, "New connection");
            f.render_widget(Span::styled(" What kind?", t.dim()), Rect { height: 1, ..inner });
            for (i, (_, label)) in NEW_KINDS.iter().enumerate() {
                let rr = Rect { y: inner.y + 1 + i as u16, height: 1, ..inner };
                let st = if i == *sel { t.selected(true) } else { t.text() };
                f.render_widget(Span::styled(format!(" {label:<w$}", w = inner.width as usize - 1), st), rr);
                app.mouse.add(rr, Target::MenuRow(i));
            }
        }
    }
    app.popup = Some(p);
}

fn render_mini(app: &mut App, f: &mut Frame, area: Rect, m: &Mini) {
    let t = app.theme.clone();
    app.mouse.modal_barrier();
    let w = 66u16.min(area.width);
    let intro_lines = (m.intro.width() as u16 / (w - 4)) + 1;
    let h = intro_lines + 1 + m.fields.len() as u16 + 1 + 1 + 1 + 2;
    let r = centered(area, w, h);
    let inner = popup(f, r, &t, &m.title).inner(Margin::new(1, 0));
    f.render_widget(Paragraph::new(m.intro.clone()).wrap(Wrap { trim: true }).style(t.dim()), Rect { height: intro_lines, ..inner });
    let mut y = inner.y + intro_lines + 1;
    for (i, fl) in m.fields.iter().enumerate() {
        let rr = Rect { y, height: 1, ..inner };
        let focused = i == m.focus;
        f.render_widget(Span::styled(format!("{:<w$}", fl.label, w = MINI_LABEL_W as usize), if focused { t.accent() } else { t.text() }), rr);
        let vr = Rect { x: rr.x + MINI_LABEL_W, width: rr.width.saturating_sub(MINI_LABEL_W), ..rr };
        f.render_widget(Span::styled(" ".repeat(vr.width as usize), if focused { t.selected(false) } else { Style::default() }), vr);
        match &fl.choices {
            Some((o, sel)) => {
                f.render_widget(Line::from(vec![Span::styled("‹ ", t.dim()), Span::styled(o[*sel].1, t.bold()), Span::styled(" ›", t.dim())]), vr);
            }
            None => fl.input.render(f, vr, &t, focused),
        }
        app.mouse.add(rr, Target::MiniField(i));
        y += 1;
    }
    y += 1;
    if let Some(e) = &m.error {
        f.render_widget(Span::styled(format!("✗ {e}"), t.error()), Rect { y, height: 1, ..inner });
    } else if m.fields.iter().any(|f| f.label.contains("assword")) {
        f.render_widget(Span::styled("Ctrl-R show/hide password · Tab next field", t.dim()), Rect { y, height: 1, ..inner });
    }
    y += 1;
    let ok = format!(" {} ", m.ok_label);
    let cancel = " Cancel ";
    let okr = Rect::new(inner.x, y, ok.width() as u16, 1);
    let cr = Rect::new(okr.right() + 1, y, cancel.width() as u16, 1);
    f.render_widget(Span::styled(ok, t.accent().add_modifier(Modifier::REVERSED | Modifier::BOLD)), okr);
    f.render_widget(Span::styled(cancel, t.dim().add_modifier(Modifier::REVERSED)), cr);
    app.mouse.add(okr, Target::MiniButton(true));
    app.mouse.add(cr, Target::MiniButton(false));
}

/// QR code drawn with half-blocks: two modules per character row, black on white.
pub fn qr_lines(payload: &str) -> Vec<String> {
    let Ok(code) = qrcode::QrCode::new(payload.as_bytes()) else { return vec!["(too long for a QR code)".into()] };
    let w = code.width();
    let colors = code.to_colors();
    let quiet = 2usize;
    let size = w + quiet * 2;
    let dark = |x: usize, y: usize| -> bool {
        if x < quiet || y < quiet || x >= w + quiet || y >= w + quiet {
            return false;
        }
        colors[(y - quiet) * w + (x - quiet)] == qrcode::Color::Dark
    };
    (0..size.div_ceil(2))
        .map(|row| {
            (0..size)
                .map(|x| match (dark(x, row * 2), dark(x, row * 2 + 1)) {
                    (true, true) => '█',
                    (true, false) => '▀',
                    (false, true) => '▄',
                    (false, false) => ' ',
                })
                .collect()
        })
        .collect()
}

fn render_share(app: &mut App, f: &mut Frame, area: Rect, ssid: &str, sec: Security, password: Option<&str>) {
    let t = app.theme.clone();
    app.mouse.modal_barrier();
    let Some(pw) = password else {
        let r = centered(area, 40, 5);
        let inner = popup(f, r, &t, "Share network");
        f.render_widget(Span::styled(format!("{} reading saved password…", spinner(app.tick)), t.dim()), inner);
        return;
    };
    let lines = qr_lines(&wifi_qr_payload(ssid, sec, pw));
    let qw = lines.first().map(|l| l.chars().count()).unwrap_or(10) as u16;
    let info = if pw.is_empty() { ssid.to_string() } else { format!("{ssid}  ·  password: {pw}") };
    let r = centered(area, (qw + 4).max(info.width() as u16 + 4).max(44), lines.len() as u16 + 7);
    let inner = popup(f, r, &t, "Share network");
    let qx = inner.x + inner.width.saturating_sub(qw) / 2;
    let qr_style = Style::default().fg(Color::Black).bg(Color::White);
    for (i, l) in lines.iter().enumerate() {
        f.render_widget(Span::styled(l.clone(), qr_style), Rect::new(qx, inner.y + i as u16, qw, 1));
    }
    let y = inner.y + lines.len() as u16 + 1;
    f.render_widget(Line::from(Span::styled(info, t.text())).centered(), Rect { y, height: 1, ..inner });
    f.render_widget(Line::from(Span::styled("Scan with a phone camera · Esc close", t.dim())).centered(), Rect { y: y + 2, height: 1, ..inner });
    app.mouse.add(r, Target::CloseShare);
}

fn help_rows(app: &App) -> Vec<HelpRow> {
    let mut rows = Vec::new();
    for section in ["General keys", "Wi-Fi tab", "Connections tab", "Devices tab", "General tab"] {
        rows.push(HelpRow::Section(section.into()));
        for &a in Action::all().iter().filter(|a| a.section() == section) {
            rows.push(HelpRow::Key(app.keymap.keys_label(a), a.description().to_string(), a.name().to_string()));
        }
    }
    rows.push(HelpRow::Section("Editor".into()));
    rows.push(HelpRow::Text("j/k or Tab move · Enter/Space change · ←/→ pick · Ctrl-S save · Esc cancel · Ctrl-R show passwords".into()));
    rows.push(HelpRow::Section("Mouse".into()));
    rows.push(HelpRow::Text("click to select · double-click to connect · right-click for actions · wheel scrolls".into()));
    rows.push(HelpRow::Text("tabs, footer hints, checkboxes and buttons are clickable".into()));
    rows.push(HelpRow::Section("Files".into()));
    rows.push(HelpRow::Text(format!("config  {}", app.cfg_path.display())));
    rows.push(HelpRow::Text(format!("log     {}", crate::core::logging::log_dir(crate::config::APP).join("network-tui.log").display())));
    rows.push(HelpRow::Text("Connection profiles are stored by NetworkManager (/etc/NetworkManager/system-connections).".into()));
    rows
}

#[cfg(test)]
mod snapshots {
    //! `cargo test snap -- --nocapture` prints each screen as text.
    use super::*;
    use crate::backend::Ev;
    use crate::config::Config;
    use ratatui::{backend::TestBackend, Terminal};

    async fn app() -> App {
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        let mut a = App::new(Config::default(), "/tmp/n.toml".into(), tx, true, vec![]);
        a.cfg.wifi.scan_on_start = false;
        let mut h = crate::backend::demo::spawn();
        while let Some(ev) = h.rx.recv().await {
            let is_snap = matches!(ev, Ev::Snapshot(_));
            a.on_backend(ev);
            if is_snap {
                break;
            }
        }
        a.toasts.dismiss_all();
        a
    }

    fn dump(app: &mut App, w: u16, h: u16) -> String {
        let mut t = Terminal::new(TestBackend::new(w, h)).unwrap();
        t.draw(|f| render(app, f)).unwrap();
        let buf = t.backend().buffer().clone();
        let mut out = String::new();
        for y in 0..h {
            let mut skip = 0;
            for x in 0..w {
                if skip > 0 {
                    skip -= 1;
                    continue;
                }
                let s = buf[(x, y)].symbol();
                skip = s.width().saturating_sub(1);
                out.push_str(s);
            }
            out.push('\n');
        }
        out
    }

    #[tokio::test]
    async fn snap_wifi() {
        let mut a = app().await;
        println!("{}", dump(&mut a, 120, 30));
    }

    #[tokio::test]
    async fn snap_connections_devices_general() {
        let mut a = app().await;
        for tab in [Tab::Connections, Tab::Devices, Tab::General] {
            a.tab = tab;
            println!("{}", dump(&mut a, 120, 24));
        }
    }

    #[tokio::test]
    async fn snap_editor_and_share() {
        let mut a = app().await;
        a.tab = Tab::Connections;
        a.run(Action::EditProfile);
        println!("{}", dump(&mut a, 110, 32));
        a.popup = None;
        a.tab = Tab::Wifi;
        a.popup = Some(Popup::Share { ssid: "Home-5G".into(), security: Security::Wpa2, password: Some("correct horse battery".into()), waiting: None });
        println!("{}", dump(&mut a, 100, 34));
        a.popup = None;
        a.run(Action::Hotspot);
        println!("{}", dump(&mut a, 100, 24));
    }

    #[tokio::test]
    async fn snap_sweep() {
        let mut a = app().await;
        a.show_details = true;
        for tab in Tab::ALL {
            a.tab = tab;
            for (w, h) in [(60, 18), (90, 24), (140, 30)] {
                println!("=== {tab:?} {w}x{h}\n{}", dump(&mut a, w, h));
            }
        }
    }
}
