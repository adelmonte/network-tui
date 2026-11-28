//! `network-tui daemon`: the root service that owns the network. It keeps
//! profiles, drives iwd for Wi-Fi, configures everything else itself over
//! netlink, and serves the TUI on a Unix socket (JSON lines of
//! [`Cmd`]/[`Ev`]).

mod activate;
pub mod dhcp;
pub mod iwd;
pub mod iwdfile;
pub mod link;
pub mod scan;
mod snapshot;
pub mod store;
pub mod sys;
pub mod vpn;
pub mod wg;
mod wifi;

use std::collections::{BTreeMap, BTreeSet};
use std::os::unix::fs::PermissionsExt;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::mpsc::{unbounded_channel, UnboundedSender};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tokio::time::Instant;

use crate::backend::model::Connectivity;
use crate::backend::val::{Dict, DictExt, Settings};
use crate::backend::{Cmd, Ev, SecretRequest, SOCKET};

use store::Store;

pub enum Internal {
    ClientNew { id: u64, tx: UnboundedSender<String>, privileged: bool },
    ClientCmd { id: u64, cmd: Cmd },
    ClientGone(u64),
    IwdChanged,
    IwdRestarted,
    LinksChanged,
    Agent { network: String, ask: iwd::Ask, reply: oneshot::Sender<Option<Vec<String>>> },
    AgentCancel,
    WifiDone { ifname: String, uuid: String, res: Result<(), zbus::Error> },
    Activated { uuid: String, res: Result<Extra, String> },
    Dhcp { iface: String, ev: dhcp::DhcpEv },
    Vpn { uuid: String, ev: vpn::VpnEv },
    Connectivity { c: Connectivity, client: Option<u64> },
}

/// Per-kind details of an active connection.
#[derive(Clone, Debug, Default)]
pub enum Extra {
    #[default]
    None,
    Hotspot { prev_forward: String },
    Wg { full4: bool, full6: bool },
    Vpn { pid: Option<u32> },
}

pub struct Active {
    pub uuid: String,
    pub kind: String,
    pub iface: String,
    /// 1 activating, 2 activated (NM's numbering, which the UI uses).
    pub state: u32,
    pub task: Option<JoinHandle<()>>,
    pub client: u64,
    pub label: String,
    pub extra: Extra,
    pub lease: Option<dhcp::Lease>,
}

struct Client {
    tx: UnboundedSender<String>,
    privileged: bool,
}

enum PendingSecret {
    Agent { reply: oneshot::Sender<Option<Vec<String>>>, uuid: Option<String>, key: String, user: Option<String> },
    Vpn { uuid: String, key: String },
}

struct WifiPending {
    uuid: String,
    label: String,
    client: u64,
    /// Already went back to the user for a new password once.
    retried: bool,
    /// The agent handed iwd a new secret; rewrite the iwd file once connected.
    secret_changed: bool,
}

pub struct Daemon {
    tx: UnboundedSender<Internal>,
    store: Store,
    iwd: Option<iwd::Iwd>,
    iw: iwd::IwdState,
    /// iwd's signal list per interface: (network path, dBm).
    signals: BTreeMap<String, Vec<(String, i16)>>,
    /// Connected BSSID and bitrate per interface.
    diag: BTreeMap<String, (String, u32)>,
    bss: BTreeMap<String, BTreeMap<String, (scan::Bss, Instant)>>,
    was_scanning: BTreeSet<String>,
    nl: rtnetlink::Handle,
    links: link::Links,
    clients: BTreeMap<u64, Client>,
    secrets: BTreeMap<u64, PendingSecret>,
    next_id: u64,
    wifi_pending: BTreeMap<String, WifiPending>,
    reasons: BTreeMap<String, u32>,
    actives: BTreeMap<String, Active>,
    wired_blocked: BTreeSet<String>,
    connectivity: Connectivity,
    last_primary: Option<u32>,
    last_json: String,
    dirty: bool,
    refresh_iwd: bool,
    refresh_links: bool,
}

pub fn dev_path(ifname: &str) -> String {
    format!("/device/{ifname}")
}

pub fn prof_path(uuid: &str) -> String {
    format!("/profile/{uuid}")
}

pub fn act_path(uuid: &str) -> String {
    format!("/active/{uuid}")
}

fn tail<'a>(path: &'a str, prefix: &str) -> &'a str {
    path.strip_prefix(prefix).unwrap_or("")
}

pub async fn run(ready_fd: Option<i32>) -> color_eyre::Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        color_eyre::eyre::bail!("the daemon must run as root");
    }
    let (tx, mut rx) = unbounded_channel();
    let nl = link::connect()?;
    link::watch(tx.clone())?;
    let mut d = Daemon {
        tx: tx.clone(),
        store: Store::load(),
        iwd: None,
        iw: iwd::IwdState::default(),
        signals: BTreeMap::new(),
        diag: BTreeMap::new(),
        bss: BTreeMap::new(),
        was_scanning: BTreeSet::new(),
        nl,
        links: link::Links::default(),
        clients: BTreeMap::new(),
        secrets: BTreeMap::new(),
        next_id: 1,
        wifi_pending: BTreeMap::new(),
        reasons: BTreeMap::new(),
        actives: BTreeMap::new(),
        wired_blocked: BTreeSet::new(),
        connectivity: Connectivity::Unknown,
        last_primary: None,
        last_json: String::new(),
        dirty: true,
        refresh_iwd: false,
        refresh_links: false,
    };
    d.sync_iwd_files();
    d.connect_iwd().await;
    d.do_refresh_links().await;
    d.do_refresh_iwd().await;
    if !d.store.state.networking {
        d.networking_off().await;
    }
    d.autoconnect_virtual().await;
    d.autoconnect_wired().await;
    serve(tx.clone())?;
    tracing::info!("network-tui daemon {} listening on {SOCKET}", env!("CARGO_PKG_VERSION"));
    if let Some(fd) = ready_fd {
        unsafe {
            libc::write(fd, b"\n".as_ptr() as *const libc::c_void, 1);
            libc::close(fd);
        }
    }

    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let mut int = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    let mut tick = tokio::time::interval(Duration::from_secs(10));
    let mut ticks: u64 = 0;
    let mut deadline: Option<Instant> = None;
    loop {
        let wait = async {
            match deadline {
                Some(t) => tokio::time::sleep_until(t).await,
                None => std::future::pending().await,
            }
        };
        tokio::select! {
            Some(ev) = rx.recv() => {
                d.handle(ev).await;
                // Coalesce bursts of events into one refresh and one snapshot.
                if deadline.is_none() && (d.dirty || d.refresh_iwd || d.refresh_links) {
                    deadline = Some(Instant::now() + Duration::from_millis(80));
                }
            }
            _ = wait => {
                deadline = None;
                if std::mem::take(&mut d.refresh_links) {
                    d.do_refresh_links().await;
                }
                if std::mem::take(&mut d.refresh_iwd) {
                    d.do_refresh_iwd().await;
                }
                d.publish();
            }
            _ = tick.tick() => {
                ticks += 1;
                d.tick(ticks).await;
                d.publish();
            }
            _ = term.recv() => break,
            _ = int.recv() => break,
        }
    }
    let _ = std::fs::remove_file(SOCKET);
    for a in d.actives.values_mut() {
        if let Some(t) = a.task.take() {
            t.abort();
        }
    }
    Ok(())
}

fn serve(tx: UnboundedSender<Internal>) -> std::io::Result<()> {
    let _ = std::fs::remove_file(SOCKET);
    let listener = UnixListener::bind(SOCKET)?;
    std::fs::set_permissions(SOCKET, std::fs::Permissions::from_mode(0o666))?;
    tokio::spawn(async move {
        let mut next = 1u64;
        loop {
            let Ok((stream, _)) = listener.accept().await else { continue };
            let privileged = stream.peer_cred().map(|c| sys::privileged(c.uid(), c.gid())).unwrap_or(false);
            let id = next;
            next += 1;
            tokio::spawn(client(stream, id, privileged, tx.clone()));
        }
    });
    Ok(())
}

async fn client(stream: UnixStream, id: u64, privileged: bool, tx: UnboundedSender<Internal>) {
    let (r, mut w) = stream.into_split();
    let (otx, mut orx) = unbounded_channel::<String>();
    if tx.send(Internal::ClientNew { id, tx: otx, privileged }).is_err() {
        return;
    }
    tokio::spawn(async move {
        while let Some(line) = orx.recv().await {
            if w.write_all(line.as_bytes()).await.is_err() {
                break;
            }
        }
    });
    let mut r = BufReader::new(r);
    let mut line = String::new();
    loop {
        line.clear();
        match (&mut r).take(4 << 20).read_line(&mut line).await {
            Ok(0) | Err(_) => break,
            Ok(_) if !line.ends_with('\n') => break,
            Ok(_) => match serde_json::from_str::<Cmd>(&line) {
                Ok(cmd) => {
                    if tx.send(Internal::ClientCmd { id, cmd }).is_err() {
                        break;
                    }
                }
                Err(e) => tracing::warn!("client {id}: bad command: {e}"),
            },
        }
    }
    let _ = tx.send(Internal::ClientGone(id));
}

/// Commands anyone may send; everything else needs a privileged client.
fn harmless(c: &Cmd) -> bool {
    matches!(c, Cmd::Scan(_) | Cmd::CheckConnectivity | Cmd::SecretReply { .. })
}

impl Daemon {
    fn emit(&self, client: u64, ev: Ev) {
        if let Some(c) = self.clients.get(&client) {
            let mut l = serde_json::to_string(&ev).expect("events serialize");
            l.push('\n');
            let _ = c.tx.send(l);
        }
    }

    fn ok(&self, client: u64, msg: impl Into<String>) {
        self.emit(client, Ev::Ok(msg.into()));
    }

    fn info(&self, client: u64, msg: impl Into<String>) {
        self.emit(client, Ev::Info(msg.into()));
    }

    fn err(&self, client: u64, msg: impl Into<String>) {
        self.emit(client, Ev::Error(msg.into()));
    }

    fn busy(&self, client: u64, key: &str, label: &str, on: bool) {
        self.emit(client, Ev::Busy { key: key.to_string(), label: label.to_string(), on });
    }

    /// A client to ask for a secret: the one that started it, else any privileged one.
    fn secret_client(&self, preferred: Option<u64>) -> Option<u64> {
        preferred.filter(|c| self.clients.contains_key(c)).or_else(|| self.clients.iter().find(|(_, c)| c.privileged).map(|(id, _)| *id))
    }

    fn ask_secret(&mut self, client: Option<u64>, req: SecretRequest, pending: PendingSecret) -> bool {
        let Some(c) = self.secret_client(client) else { return false };
        let id = self.next_id;
        self.next_id += 1;
        self.secrets.insert(id, pending);
        self.emit(c, Ev::SecretRequest { id, req });
        self.dirty = true;
        true
    }

    fn publish(&mut self) {
        self.dirty = false;
        let snap = self.snapshot();
        let ev = Ev::Snapshot(Box::new(snap));
        let mut json = serde_json::to_string(&ev).expect("snapshot serializes");
        if json == self.last_json {
            return;
        }
        json.push('\n');
        for c in self.clients.values() {
            let _ = c.tx.send(json.clone());
        }
        json.pop();
        self.last_json = json;
    }

    async fn connect_iwd(&mut self) {
        match iwd::Iwd::connect().await {
            Ok(i) => {
                if let Err(e) = i.watch(self.tx.clone()).await {
                    tracing::warn!("watching iwd: {e}");
                }
                if let Err(e) = i.register_agent(self.tx.clone()).await {
                    tracing::warn!("registering the iwd agent: {e} (is iwd running?)");
                }
                self.iwd = Some(i);
            }
            Err(e) => tracing::warn!("system bus: {e}"),
        }
    }

    async fn do_refresh_links(&mut self) {
        match link::dump(&self.nl).await {
            Ok(l) => {
                let lost: Vec<String> = self
                    .actives
                    .values()
                    .filter(|a| a.kind == "802-3-ethernet" && l.by_name(&a.iface).is_none_or(|x| !x.carrier))
                    .map(|a| a.uuid.clone())
                    .collect();
                self.links = l;
                for u in lost {
                    tracing::info!("carrier lost; deactivating {u}");
                    self.deactivate(&u, 40).await;
                }
                self.autoconnect_wired().await;
                let primary = self.links.primary();
                if primary != self.last_primary {
                    self.last_primary = primary;
                    self.start_connectivity_check(None);
                }
            }
            Err(e) => tracing::warn!("netlink dump: {e}"),
        }
        self.dirty = true;
    }

    fn start_connectivity_check(&self, client: Option<u64>) {
        let tx = self.tx.clone();
        let online = self.links.primary().is_some();
        tokio::spawn(async move {
            let c = if online { sys::check_connectivity().await } else { Connectivity::None };
            let _ = tx.send(Internal::Connectivity { c, client });
        });
    }

    async fn tick(&mut self, n: u64) {
        if self.iwd.is_none() && n.is_multiple_of(3) {
            self.connect_iwd().await;
        }
        if !self.clients.is_empty() {
            self.refresh_diag().await;
            // Keep the network list fresh while someone is looking at it.
            if n.is_multiple_of(12) {
                self.background_scan().await;
            }
        }
        if n.is_multiple_of(30) {
            self.start_connectivity_check(None);
        }
        let cutoff = Instant::now() - Duration::from_secs(240);
        for list in self.bss.values_mut() {
            list.retain(|_, (_, seen)| *seen > cutoff);
        }
        self.dirty = true;
    }

    async fn handle(&mut self, ev: Internal) {
        match ev {
            Internal::ClientNew { id, tx, privileged } => {
                let mut snap = serde_json::to_string(&Ev::Snapshot(Box::new(self.snapshot()))).expect("snapshot serializes");
                snap.push('\n');
                let _ = tx.send(snap);
                self.clients.insert(id, Client { tx, privileged });
            }
            Internal::ClientGone(id) => {
                self.clients.remove(&id);
            }
            Internal::ClientCmd { id, cmd } => {
                let privileged = self.clients.get(&id).is_some_and(|c| c.privileged);
                if !privileged && !harmless(&cmd) {
                    self.err(id, "Not allowed: only root and members of the wheel or network group can change network settings");
                    return;
                }
                self.command(id, cmd).await;
                self.dirty = true;
            }
            Internal::IwdChanged => self.refresh_iwd = true,
            Internal::IwdRestarted => {
                if let Some(i) = &self.iwd {
                    // Re-register: a restarted iwd forgets its agent.
                    let _ = i.register_agent(self.tx.clone()).await;
                }
                self.refresh_iwd = true;
            }
            Internal::LinksChanged => self.refresh_links = true,
            Internal::Agent { network, ask, reply } => self.on_agent(network, ask, reply),
            Internal::AgentCancel => {
                let ids: Vec<u64> = self.secrets.iter().filter(|(_, p)| matches!(p, PendingSecret::Agent { .. })).map(|(id, _)| *id).collect();
                for id in ids {
                    self.secrets.remove(&id);
                    for c in self.clients.keys() {
                        self.emit(*c, Ev::SecretCancelled(id));
                    }
                }
                self.dirty = true;
            }
            Internal::WifiDone { ifname, uuid, res } => self.on_wifi_done(ifname, uuid, res).await,
            Internal::Activated { uuid, res } => self.on_activated(uuid, res).await,
            Internal::Dhcp { iface, ev } => self.on_dhcp(iface, ev).await,
            Internal::Vpn { uuid, ev } => self.on_vpn(uuid, ev),
            Internal::Connectivity { c, client } => {
                self.connectivity = c;
                if let Some(id) = client {
                    self.info(id, format!("Connectivity: {}", c.label()));
                }
                self.dirty = true;
            }
        }
    }

    fn profile_by_path(&self, path: &str) -> Option<Settings> {
        self.store.profiles.get(tail(path, "/profile/")).cloned()
    }

    async fn command(&mut self, client: u64, cmd: Cmd) {
        match cmd {
            Cmd::Scan(dev) => self.scan(client, tail(&dev, "/device/")).await,
            Cmd::ConnectWifi { device, ap, profile, settings, label } => {
                self.connect_wifi(client, tail(&device, "/device/").to_string(), ap, profile, settings, label).await;
            }
            Cmd::Activate { profile, device, label } => {
                let Some(s) = self.profile_by_path(&profile) else { return self.err(client, format!("{label}: that profile no longer exists")) };
                self.activate(client, s, device.map(|d| tail(&d, "/device/").to_string()), label).await;
            }
            Cmd::Deactivate { active, label } => {
                let uuid = tail(&active, "/active/").to_string();
                if self.deactivate(&uuid, 39).await {
                    self.ok(client, format!("Disconnected {label}"));
                } else {
                    self.err(client, format!("{label} isn't active"));
                }
            }
            Cmd::DisconnectDevice { device, label } => {
                let ifname = tail(&device, "/device/").to_string();
                self.disconnect_device(&ifname).await;
                self.ok(client, format!("Disconnected {label}"));
            }
            Cmd::AddProfile { settings, activate_on } => self.add_profile(client, settings, activate_on).await,
            Cmd::UpdateProfile { path, settings } => self.update_profile(client, &path, settings),
            Cmd::DeleteProfile { path, label } => {
                let uuid = tail(&path, "/profile/").to_string();
                self.deactivate(&uuid, 39).await;
                match self.store.remove(&uuid) {
                    Some(s) => {
                        self.forget_files(&s).await;
                        self.ok(client, format!("Forgot {label}"));
                    }
                    None => self.err(client, format!("{label}: that profile no longer exists")),
                }
            }
            Cmd::GetSecrets { path, setting } => {
                let values = self.profile_by_path(&path).and_then(|s| s.get(&setting).cloned()).unwrap_or_default();
                self.emit(client, Ev::Secrets { path, setting, values });
            }
            Cmd::SetWifiEnabled(on) => self.set_wifi(client, on).await,
            Cmd::SetWwanEnabled(on) => {
                if sys::rfkill("wwan").2 {
                    if let Err(e) = sys::set_rfkill("wwan", !on) {
                        self.err(client, format!("Mobile data: {e}"));
                    }
                } else if on {
                    self.info(client, "No mobile broadband hardware");
                }
            }
            Cmd::SetNetworkingEnabled(on) => {
                self.store.state.networking = on;
                self.store.save_state();
                if on {
                    self.wired_blocked.clear();
                    self.autoconnect_virtual().await;
                    self.autoconnect_wired().await;
                    self.wifi_autoconnect().await;
                    self.info(client, "Networking enabled");
                } else {
                    self.networking_off().await;
                    self.info(client, "Networking disabled");
                }
            }
            Cmd::SetHostname(h) => match sys::set_hostname(&h) {
                Ok(()) => self.ok(client, format!("Hostname set to {h}")),
                Err(e) => self.err(client, format!("Setting the hostname: {e}")),
            },
            Cmd::CheckConnectivity => self.start_connectivity_check(Some(client)),
            Cmd::SetManaged { device, on } => {
                let ifname = tail(&device, "/device/").to_string();
                if on {
                    self.store.state.unmanaged.remove(&ifname);
                } else {
                    self.disconnect_device(&ifname).await;
                    self.store.state.unmanaged.insert(ifname.clone());
                }
                self.store.save_state();
                self.ok(client, format!("{ifname}: {}", if on { "managed" } else { "left alone (unmanaged)" }));
                if on {
                    self.autoconnect_wired().await;
                }
            }
            Cmd::SetDeviceAutoconnect { device, on } => {
                let ifname = tail(&device, "/device/").to_string();
                if on {
                    self.store.state.no_autoconnect.remove(&ifname);
                } else {
                    self.store.state.no_autoconnect.insert(ifname);
                }
                self.store.save_state();
            }
            Cmd::Import { kind, file, contents } => self.import(client, &kind, &file, &contents),
            Cmd::SecretReply { id, secrets } => self.on_secret_reply(id, secrets).await,
        }
    }

    fn import(&mut self, client: u64, kind: &str, file: &str, contents: &str) {
        let name = std::path::Path::new(file).file_stem().map(|s| s.to_string_lossy().to_string()).unwrap_or_else(|| "VPN".into());
        let res = match kind {
            "wireguard" => wg::import_conf(contents, &name).map(|mut s| {
                // wg-quick names the interface after the file.
                if name.len() <= 15 && name.chars().all(|c| c.is_ascii_alphanumeric() || "_=+.-".contains(c)) {
                    s.get_mut("connection").expect("set").insert("interface-name".into(), crate::backend::val::Val::Str(name.clone()));
                }
                s
            }),
            "openvpn" => {
                let tmp = std::env::temp_dir().join(format!("network-tui-import-{}.ovpn", std::process::id()));
                let r = store::write_private(&tmp, contents.as_bytes()).map_err(|e| e.to_string()).and_then(|_| vpn::import(&tmp, &self.store.vpn_dir()));
                let _ = std::fs::remove_file(&tmp);
                r.map(|mut s| {
                    s.get_mut("connection").expect("set").insert("id".into(), crate::backend::val::Val::Str(name.clone()));
                    s
                })
            }
            k => Err(format!("can't import “{k}” files")),
        };
        match res.and_then(|s| self.store.put(s).map_err(|e| e.to_string())) {
            Ok(_) => self.ok(client, format!("Imported {name}")),
            Err(e) => self.err(client, format!("Import failed: {e}")),
        }
    }

    async fn add_profile(&mut self, client: u64, mut settings: Settings, activate_on: Option<String>) {
        let label = store::id(&settings);
        if store::uuid(&settings).is_empty() {
            settings.entry("connection".into()).or_default().insert("uuid".into(), crate::backend::val::Val::Str(crate::backend::form::new_uuid()));
        }
        if store::is_wifi_client(&settings)
            && let Err(e) = self.replace_same_ssid(&settings) {
                return self.err(client, format!("{label}: {e}"));
            }
        if let Err(e) = self.store.put(settings.clone()) {
            return self.err(client, format!("Saving {label}: {e}"));
        }
        if activate_on.is_none() {
            self.ok(client, format!("Saved {label}"));
        }
        if let Some(dev) = activate_on {
            self.activate(client, settings, Some(tail(&dev, "/device/").to_string()), label).await;
        }
    }

    fn update_profile(&mut self, client: u64, path: &str, mut settings: Settings) {
        let uuid = tail(path, "/profile/").to_string();
        let Some(old) = self.store.profiles.get(&uuid).cloned() else {
            return self.err(client, "That profile no longer exists");
        };
        store::merge_secrets(&mut settings, &old);
        settings.entry("connection".into()).or_default().insert("uuid".into(), crate::backend::val::Val::Str(uuid.clone()));
        // Keep the last-used time; the editor doesn't know about it.
        if let Some(ts) = old.get("connection").and_then(|c| c.get("timestamp")).cloned() {
            settings.entry("connection".into()).or_default().entry("timestamp".into()).or_insert(ts);
        }
        let label = store::id(&settings);
        if store::is_wifi_client(&settings) {
            let old_file = iwdfile::path_for(&old).ok();
            if let Err(e) = iwdfile::write(&settings, old_file.as_deref()) {
                return self.err(client, format!("{label}: {e}"));
            }
        }
        match self.store.put(settings) {
            Ok(_) => self.ok(client, format!("Saved {label}")),
            Err(e) => self.err(client, format!("Saving {label}: {e}")),
        }
    }

    async fn forget_files(&mut self, s: &Settings) {
        if store::is_wifi_client(s)
            && let Ok(path) = iwdfile::path_for(s) {
                let shared = self.store.profiles.values().any(|o| store::is_wifi_client(o) && iwdfile::path_for(o).ok().as_deref() == Some(&path));
                if !shared {
                    let _ = std::fs::remove_file(&path);
                }
            }
        if store::kind(s) == "vpn" {
            let cfg = vpn::data(s, "config");
            if cfg.starts_with(&self.store.vpn_dir().to_string_lossy().to_string()) {
                let _ = std::fs::remove_file(cfg);
            }
        }
    }

    async fn on_secret_reply(&mut self, id: u64, secrets: Option<Dict>) {
        let Some(p) = self.secrets.remove(&id) else { return };
        match p {
            PendingSecret::Agent { reply, uuid, key, user } => {
                let Some(d) = secrets else {
                    let _ = reply.send(None);
                    return;
                };
                let value = d.s(&key);
                if let Some(u) = &uuid
                    && let Some(mut s) = self.store.profiles.get(u).cloned() {
                        let setting = if key == "psk" { "802-11-wireless-security" } else { "802-1x" };
                        s.entry(setting.into()).or_default().insert(key.clone(), crate::backend::val::Val::Str(value.clone()));
                        let _ = self.store.put(s);
                        for p in self.wifi_pending.values_mut().filter(|p| &p.uuid == u) {
                            p.secret_changed = true;
                        }
                    }
                let out = match user {
                    Some(u) => vec![u, value],
                    None => vec![value],
                };
                let _ = reply.send(Some(out));
            }
            PendingSecret::Vpn { uuid, key } => {
                let Some(a) = self.actives.get(&uuid) else { return };
                let (client, label) = (a.client, a.label.clone());
                let Some(d) = secrets else {
                    self.actives.remove(&uuid);
                    self.busy(client, &prof_path(&uuid), &label, false);
                    return;
                };
                if let Some(mut s) = self.store.profiles.get(&uuid).cloned() {
                    if key == "username" {
                        vpn::set_data(&mut s, "username", &d.s(&key));
                    } else {
                        vpn::set_secret(&mut s, &key, &d.s(&key));
                    }
                    let _ = self.store.put(s.clone());
                    self.actives.remove(&uuid);
                    self.activate(client, s, None, label).await;
                }
            }
        }
    }
}
