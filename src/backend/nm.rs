//! NetworkManager backend over the system D-Bus (zbus).
//!
//! State: one `GetManagedObjects` call returns every NM object with all its
//! properties. We re-run it (debounced) whenever NM emits any signal, and
//! re-read saved-connection settings when they change. So it's event-driven
//! without hand-tracking dozens of property streams, and the parsing lives in
//! pure code (`model.rs`) that's unit-tested.

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures::StreamExt;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
use tokio::sync::oneshot;
use zbus::zvariant::{ObjectPath, OwnedObjectPath, OwnedValue, Value};
use zbus::{Connection, MatchRule, MessageStream};

use super::model::{self, NM, NM_PATH};
use super::val::{Dict, DictExt, Objects, Settings, Val};
use super::{Cmd, Ev, Handle, SecretRequest};

const SETTINGS_PATH: &str = "/org/freedesktop/NetworkManager/Settings";
const IF_SETTINGS: &str = "org.freedesktop.NetworkManager.Settings";
const IF_CONN: &str = "org.freedesktop.NetworkManager.Settings.Connection";
const IF_DEVICE: &str = "org.freedesktop.NetworkManager.Device";
const IF_WIRELESS: &str = "org.freedesktop.NetworkManager.Device.Wireless";
const AGENT_PATH: &str = "/org/freedesktop/NetworkManager/SecretAgent";

type DbusSettings = HashMap<String, HashMap<String, OwnedValue>>;

pub fn spawn() -> Handle {
    let (tx, cmd_rx) = unbounded_channel();
    let (ev_tx, rx) = unbounded_channel();
    tokio::spawn(async move {
        if let Err(e) = run(cmd_rx, ev_tx.clone()).await {
            let _ = ev_tx.send(Ev::Unavailable(format!(
                "Can't talk to NetworkManager: {e}. Is it running? (systemctl status NetworkManager)"
            )));
        }
    });
    Handle { tx, rx }
}

// ---------------------------------------------------------------- value conversion

pub fn to_val(v: &Value) -> Val {
    match v {
        Value::Bool(b) => Val::Bool(*b),
        Value::U8(n) => Val::U8(*n),
        Value::I16(n) => Val::I32(*n as i32),
        Value::U16(n) => Val::U32(*n as u32),
        Value::I32(n) => Val::I32(*n),
        Value::U32(n) => Val::U32(*n),
        Value::I64(n) => Val::I64(*n),
        Value::U64(n) => Val::U64(*n),
        Value::F64(n) => Val::F64(*n),
        Value::Str(s) => Val::Str(s.to_string()),
        Value::ObjectPath(p) => Val::Path(p.to_string()),
        Value::Value(inner) => to_val(inner),
        Value::Array(a) => {
            let sig = a.element_signature().to_string();
            let items = a.inner();
            match sig.as_str() {
                "y" => Val::Bytes(items.iter().filter_map(|x| if let Value::U8(b) = x { Some(*b) } else { None }).collect()),
                "s" => Val::StrList(items.iter().filter_map(|x| if let Value::Str(s) = x { Some(s.to_string()) } else { None }).collect()),
                "o" => Val::PathList(items.iter().filter_map(|x| if let Value::ObjectPath(p) = x { Some(p.to_string()) } else { None }).collect()),
                "u" => Val::U32List(items.iter().filter_map(|x| if let Value::U32(n) = x { Some(*n) } else { None }).collect()),
                "ay" => Val::BytesList(items.iter().filter_map(|x| if let Val::Bytes(b) = to_val(x) { Some(b) } else { None }).collect()),
                "au" => Val::U32ListList(items.iter().filter_map(|x| if let Val::U32List(b) = to_val(x) { Some(b) } else { None }).collect()),
                "a{sv}" => Val::DictList(items.iter().filter_map(|x| if let Val::Dict(d) = to_val(x) { Some(d) } else { None }).collect()),
                other => Val::Other(format!("a{other}")),
            }
        }
        Value::Dict(d) => {
            let mut dict = Dict::new();
            let mut strmap = BTreeMap::new();
            let mut all_str = true;
            for (k, v) in d.iter() {
                let Value::Str(k) = k else { continue };
                match v {
                    Value::Str(s) => {
                        strmap.insert(k.to_string(), s.to_string());
                    }
                    other => {
                        all_str = false;
                        dict.insert(k.to_string(), to_val(other));
                    }
                }
            }
            if all_str && !strmap.is_empty() {
                Val::StrMap(strmap)
            } else {
                for (k, v) in strmap {
                    dict.insert(k, Val::Str(v));
                }
                Val::Dict(dict)
            }
        }
        Value::Structure(s) => {
            let f = s.fields();
            if !f.is_empty() && f.iter().all(|x| matches!(x, Value::U32(_))) {
                Val::U32List(f.iter().filter_map(|x| if let Value::U32(n) = x { Some(*n) } else { None }).collect())
            } else {
                Val::Other("struct".into())
            }
        }
        _ => Val::Other("unsupported".into()),
    }
}

/// Convert back for writing settings. Returns None for values we can't
/// represent (they're dropped from the update, which NM treats as default).
pub fn from_val(v: &Val) -> Option<Value<'static>> {
    Some(match v {
        Val::Bool(b) => Value::from(*b),
        Val::U8(n) => Value::from(*n),
        Val::I32(n) => Value::from(*n),
        Val::U32(n) => Value::from(*n),
        Val::I64(n) => Value::from(*n),
        Val::U64(n) => Value::from(*n),
        Val::F64(n) => Value::from(*n),
        Val::Str(s) => Value::from(s.clone()),
        Val::Path(p) => Value::from(OwnedObjectPath::try_from(p.clone()).ok()?),
        Val::Bytes(b) => Value::from(b.clone()),
        Val::BytesList(l) => Value::from(l.clone()),
        Val::StrList(l) => Value::from(l.clone()),
        Val::PathList(l) => Value::from(l.iter().filter_map(|p| OwnedObjectPath::try_from(p.clone()).ok()).collect::<Vec<_>>()),
        Val::U32List(l) => Value::from(l.clone()),
        Val::U32ListList(l) => Value::from(l.clone()),
        Val::Dict(d) => Value::from(dict_to_dbus(d)),
        Val::StrMap(m) => Value::from(m.iter().map(|(k, v)| (k.clone(), v.clone())).collect::<HashMap<String, String>>()),
        Val::DictList(l) => Value::from(l.iter().map(dict_to_dbus).collect::<Vec<_>>()),
        Val::Other(_) => return None,
    })
}

fn dict_to_dbus(d: &Dict) -> HashMap<String, Value<'static>> {
    d.iter().filter_map(|(k, v)| from_val(v).map(|v| (k.clone(), v))).collect()
}

fn settings_to_dbus(s: &Settings) -> HashMap<String, HashMap<String, Value<'static>>> {
    s.iter().map(|(name, d)| (name.clone(), dict_to_dbus(d))).collect()
}

fn settings_from_dbus(s: &DbusSettings) -> Settings {
    s.iter()
        .map(|(name, d)| (name.clone(), d.iter().map(|(k, v)| (k.clone(), to_val(v))).collect::<Dict>()))
        .collect()
}

// ---------------------------------------------------------------- D-Bus helpers

#[derive(Clone)]
struct Bus {
    conn: Connection,
}

impl Bus {
    async fn call<B, R>(&self, path: &str, iface: &str, method: &str, body: &B) -> zbus::Result<R>
    where
        B: serde::Serialize + zbus::zvariant::DynamicType,
        R: for<'d> serde::Deserialize<'d> + zbus::zvariant::Type,
    {
        let msg = self.conn.call_method(Some(NM), path, Some(iface), method, body).await?;
        msg.body().deserialize::<R>()
    }

    async fn call0<B>(&self, path: &str, iface: &str, method: &str, body: &B) -> zbus::Result<()>
    where
        B: serde::Serialize + zbus::zvariant::DynamicType,
    {
        self.conn.call_method(Some(NM), path, Some(iface), method, body).await?;
        Ok(())
    }

    async fn set_prop(&self, path: &str, iface: &str, prop: &str, v: Value<'_>) -> zbus::Result<()> {
        self.conn
            .call_method(Some(NM), path, Some("org.freedesktop.DBus.Properties"), "Set", &(iface, prop, v))
            .await?;
        Ok(())
    }

    async fn managed_objects(&self) -> zbus::Result<Objects> {
        type Raw = HashMap<OwnedObjectPath, HashMap<String, HashMap<String, OwnedValue>>>;
        let msg = self
            .conn
            .call_method(Some(NM), "/org/freedesktop", Some("org.freedesktop.DBus.ObjectManager"), "GetManagedObjects", &())
            .await?;
        let raw: Raw = msg.body().deserialize()?;
        Ok(raw
            .into_iter()
            .map(|(p, ifaces)| {
                let ifaces = ifaces
                    .into_iter()
                    .map(|(i, props)| (i, props.iter().map(|(k, v)| (k.clone(), to_val(v))).collect::<Dict>()))
                    .collect();
                (p.to_string(), ifaces)
            })
            .collect())
    }

    async fn connection_settings(&self, path: &str) -> zbus::Result<Settings> {
        let s: DbusSettings = self.call(path, IF_CONN, "GetSettings", &()).await?;
        Ok(settings_from_dbus(&s))
    }

    async fn secrets(&self, path: &str, setting: &str) -> zbus::Result<Settings> {
        let s: DbusSettings = self.call(path, IF_CONN, "GetSecrets", &(setting,)).await?;
        Ok(settings_from_dbus(&s))
    }
}

fn op(p: &str) -> ObjectPath<'_> {
    ObjectPath::try_from(p).unwrap_or_else(|_| ObjectPath::try_from("/").expect("root path"))
}

/// Turn D-Bus errors into readable text.
pub fn friendly(e: &zbus::Error) -> String {
    let s = e.to_string();
    if s.contains("NotAuthorized") || s.contains("Insufficient privileges") || s.contains("not authorized") {
        return "not allowed — polkit denied it (are you in the right group, or running over SSH?)".into();
    }
    if s.contains("UnknownConnection") {
        return "that profile no longer exists".into();
    }
    if s.contains("Scanning not allowed") || s.contains("NotAllowed") && s.contains("scan") {
        return "can't scan right now (Wi-Fi busy or off)".into();
    }
    // org.freedesktop.NetworkManager.X.Y: message -> message
    s.split_once(": ").map(|(_, m)| m.to_string()).unwrap_or(s)
}

// ---------------------------------------------------------------- secret agent

type Pending = Arc<Mutex<HashMap<u64, (String, String, oneshot::Sender<Option<Dict>>)>>>;
static NEXT: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, zbus::DBusError)]
#[zbus(prefix = "org.freedesktop.NetworkManager.SecretAgent")]
enum AgentError {
    #[zbus(error)]
    ZBus(zbus::Error),
    UserCanceled(String),
    NoSecrets(String),
}

struct SecretAgent {
    ev: UnboundedSender<Ev>,
    pending: Pending,
}

/// Which key in `setting` holds the secret the user should type.
pub fn secret_key(conn: &Settings, setting: &str, hints: &[String]) -> String {
    match setting {
        "802-11-wireless-security" => {
            let km = conn.get(setting).map(|d| d.s("key-mgmt")).unwrap_or_default();
            if km == "none" { "wep-key0".into() } else { "psk".into() }
        }
        "802-1x" => {
            let eap = conn.get("802-1x").and_then(|d| d.get("eap")).map(Val::str_list).unwrap_or_default();
            if eap.iter().any(|e| e == "tls") { "private-key-password".into() } else { "password".into() }
        }
        "wireguard" => "private-key".into(),
        _ => hints.first().cloned().unwrap_or_else(|| "password".into()),
    }
}

#[zbus::interface(name = "org.freedesktop.NetworkManager.SecretAgent")]
impl SecretAgent {
    async fn get_secrets(
        &self,
        connection: DbusSettings,
        connection_path: OwnedObjectPath,
        setting_name: String,
        hints: Vec<String>,
        flags: u32,
    ) -> Result<HashMap<String, HashMap<String, OwnedValue>>, AgentError> {
        const ALLOW_INTERACTION: u32 = 0x1;
        const REQUEST_NEW: u32 = 0x2;
        if flags & ALLOW_INTERACTION == 0 {
            return Err(AgentError::NoSecrets("network-tui only provides secrets interactively".into()));
        }
        let conn = settings_from_dbus(&connection);
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        let key = secret_key(&conn, &setting_name, &hints);
        let conn_id = conn.get("connection").map(|c| c.s("id")).unwrap_or_default();
        let (tx, rx) = oneshot::channel();
        self.pending.lock().expect("agent map").insert(id, (connection_path.to_string(), setting_name.clone(), tx));
        let _ = self.ev.send(Ev::SecretRequest {
            id,
            req: SecretRequest { conn_id, setting: setting_name.clone(), key: key.clone(), retry: flags & REQUEST_NEW != 0 },
        });
        match rx.await {
            Ok(Some(values)) => {
                let mut inner: HashMap<String, OwnedValue> = HashMap::new();
                if setting_name == "vpn" {
                    // VPN plugins take secrets as an a{ss} named "secrets".
                    let m: HashMap<String, String> = values.iter().map(|(k, v)| (k.clone(), v.str().unwrap_or_default().to_string())).collect();
                    inner.insert("secrets".into(), OwnedValue::try_from(Value::from(m)).map_err(|e| AgentError::ZBus(e.into()))?);
                } else {
                    for (k, v) in &values {
                        if let Some(val) = from_val(v) {
                            inner.insert(k.clone(), OwnedValue::try_from(val).map_err(|e| AgentError::ZBus(e.into()))?);
                        }
                    }
                }
                Ok(HashMap::from([(setting_name, inner)]))
            }
            _ => Err(AgentError::UserCanceled("cancelled".into())),
        }
    }

    async fn cancel_get_secrets(&self, connection_path: OwnedObjectPath, setting_name: String) {
        let mut map = self.pending.lock().expect("agent map");
        let ids: Vec<u64> =
            map.iter().filter(|(_, (p, s, _))| *p == connection_path.as_str() && *s == setting_name).map(|(id, _)| *id).collect();
        for id in ids {
            map.remove(&id);
            let _ = self.ev.send(Ev::SecretCancelled(id));
        }
    }

    // NM keeps system-owned secrets itself; we don't store anything.
    async fn save_secrets(&self, _connection: DbusSettings, _connection_path: OwnedObjectPath) {}
    async fn delete_secrets(&self, _connection: DbusSettings, _connection_path: OwnedObjectPath) {}
}

// ---------------------------------------------------------------- main loop

struct State {
    bus: Bus,
    ev: UnboundedSender<Ev>,
    settings: BTreeMap<String, Settings>,
    last: Option<model::Snapshot>,
    wifi_backend: Option<String>,
    pending: Pending,
}

async fn run(mut cmds: UnboundedReceiver<Cmd>, ev: UnboundedSender<Ev>) -> zbus::Result<()> {
    let conn = Connection::system().await?;
    let bus = Bus { conn: conn.clone() };
    // Fail early with a clear message if NM isn't there.
    let _: String = {
        let msg = conn
            .call_method(Some(NM), NM_PATH, Some("org.freedesktop.DBus.Properties"), "Get", &(NM, "Version"))
            .await?;
        let v: OwnedValue = msg.body().deserialize()?;
        String::try_from(v).unwrap_or_default()
    };

    let pending: Pending = Arc::default();
    let agent = SecretAgent { ev: ev.clone(), pending: pending.clone() };
    let mut agent_ok = conn.object_server().at(AGENT_PATH, agent).await.is_ok();
    if agent_ok {
        agent_ok = bus
            .call0("/org/freedesktop/NetworkManager/AgentManager", "org.freedesktop.NetworkManager.AgentManager", "Register", &("network-tui",))
            .await
            .is_ok();
    }
    if !agent_ok {
        let _ = ev.send(Ev::Info("Couldn't register as a password agent; NM will use another agent if one is running".into()));
    }

    let rule = MatchRule::builder()
        .msg_type(zbus::message::Type::Signal)
        .sender(NM)?
        .path_namespace("/org/freedesktop")?
        .build();
    let mut signals = MessageStream::for_match_rule(rule, &conn, Some(256)).await?;

    let mut st = State { bus, ev, settings: BTreeMap::new(), last: None, wifi_backend: model::detect_wifi_backend(), pending };
    st.reload_all_settings().await;
    st.refresh().await;

    let debounce = Duration::from_millis(120);
    let mut dirty = false;
    let mut deadline = tokio::time::Instant::now();
    let mut settings_dirty: Vec<(String, bool)> = Vec::new(); // (path, removed)
    loop {
        let timer = tokio::time::sleep_until(deadline);
        tokio::select! {
            cmd = cmds.recv() => match cmd {
                Some(c) => st.command(c).await,
                None => break,
            },
            Some(Ok(msg)) = signals.next() => {
                let h = msg.header();
                let member = h.member().map(|m| m.to_string()).unwrap_or_default();
                let path = h.path().map(|p| p.to_string()).unwrap_or_default();
                match member.as_str() {
                    "NewConnection" => if let Ok((p,)) = msg.body().deserialize::<(OwnedObjectPath,)>() { settings_dirty.push((p.to_string(), false)); },
                    "ConnectionRemoved" => if let Ok((p,)) = msg.body().deserialize::<(OwnedObjectPath,)>() { settings_dirty.push((p.to_string(), true)); },
                    "Updated" => settings_dirty.push((path, false)),
                    _ => {}
                }
                if !dirty {
                    dirty = true;
                    deadline = tokio::time::Instant::now() + debounce;
                }
            }
            _ = timer, if dirty => {
                dirty = false;
                for (p, removed) in std::mem::take(&mut settings_dirty) {
                    if removed {
                        st.settings.remove(&p);
                    } else if let Ok(s) = st.bus.connection_settings(&p).await {
                        st.settings.insert(p, s);
                    }
                }
                st.refresh().await;
            }
        }
    }
    Ok(())
}

impl State {
    fn emit(&self, e: Ev) {
        let _ = self.ev.send(e);
    }

    async fn reload_all_settings(&mut self) {
        let paths: Vec<OwnedObjectPath> = self.bus.call(SETTINGS_PATH, IF_SETTINGS, "ListConnections", &()).await.unwrap_or_default();
        self.settings.clear();
        for p in paths {
            match self.bus.connection_settings(p.as_str()).await {
                Ok(s) => {
                    self.settings.insert(p.to_string(), s);
                }
                Err(e) => tracing::warn!("GetSettings {p}: {e}"),
            }
        }
    }

    async fn refresh(&mut self) {
        let objects = match self.bus.managed_objects().await {
            Ok(o) => o,
            Err(e) => return self.emit(Ev::Error(format!("Refresh failed: {}", friendly(&e)))),
        };
        let mut snap = model::parse(&objects, &self.settings);
        snap.general.wifi_backend = self.wifi_backend.clone();
        // Access points churn signals during scans; skip snapshots that change nothing.
        if self.last.as_ref() == Some(&snap) {
            return;
        }
        self.last = Some(snap.clone());
        self.emit(Ev::Snapshot(Box::new(snap)));
    }

    /// Run a call in the background with a busy marker and result toast.
    fn task<F>(&self, key: String, label: String, ok: Option<String>, fut: F)
    where
        F: std::future::Future<Output = zbus::Result<()>> + Send + 'static,
    {
        let ev = self.ev.clone();
        tokio::spawn(async move {
            let _ = ev.send(Ev::Busy { key: key.clone(), label: label.clone(), on: true });
            let r = fut.await;
            let _ = ev.send(Ev::Busy { key, label: label.clone(), on: false });
            match r {
                Ok(()) => {
                    if let Some(m) = ok {
                        let _ = ev.send(Ev::Ok(m));
                    }
                }
                Err(e) => {
                    let _ = ev.send(Ev::Error(format!("{label}: {}", friendly(&e))));
                }
            }
        });
    }

    async fn command(&mut self, c: Cmd) {
        let bus = self.bus.clone();
        match c {
            Cmd::Scan(dev) => {
                let ev = self.ev.clone();
                tokio::spawn(async move {
                    let opts: HashMap<String, Value> = HashMap::new();
                    if let Err(e) = bus.call0(&dev, IF_WIRELESS, "RequestScan", &(opts,)).await {
                        // Common with iwd while it's already scanning; not worth an error toast.
                        let _ = ev.send(Ev::Info(format!("Scan: {}", friendly(&e))));
                    }
                });
            }
            Cmd::ConnectWifi { device, ap, profile, settings, label } => {
                let msg = format!("Connecting to {label}…");
                self.task(device.clone(), label.clone(), None, async move {
                    match (profile, settings) {
                        (Some(p), _) => {
                            let _: OwnedObjectPath = bus.call(NM_PATH, NM, "ActivateConnection", &(op(&p), op(&device), op(&ap))).await?;
                        }
                        (None, Some(s)) => {
                            let _: (OwnedObjectPath, OwnedObjectPath) =
                                bus.call(NM_PATH, NM, "AddAndActivateConnection", &(settings_to_dbus(&s), op(&device), op(&ap))).await?;
                        }
                        (None, None) => {}
                    }
                    Ok(())
                });
                self.emit(Ev::Info(msg));
            }
            Cmd::Activate { profile, device, label } => {
                let dev = device.unwrap_or_else(|| "/".into());
                self.task(profile.clone(), label.clone(), None, async move {
                    let _: OwnedObjectPath = bus.call(NM_PATH, NM, "ActivateConnection", &(op(&profile), op(&dev), op("/"))).await?;
                    Ok(())
                });
            }
            Cmd::Deactivate { active, label } => {
                self.task(active.clone(), label.clone(), Some(format!("Disconnected {label}")), async move {
                    bus.call0(NM_PATH, NM, "DeactivateConnection", &(op(&active),)).await
                });
            }
            Cmd::DisconnectDevice { device, label } => {
                self.task(device.clone(), label.clone(), Some(format!("Disconnected {label}")), async move {
                    bus.call0(&device, IF_DEVICE, "Disconnect", &()).await
                });
            }
            Cmd::AddProfile { settings, activate_on } => {
                let name = settings.get("connection").map(|c| c.s("id")).unwrap_or_default();
                self.task("add".into(), format!("Save {name}"), Some(format!("Saved {name}")), async move {
                    let d = settings_to_dbus(&settings);
                    match activate_on {
                        Some(dev) => {
                            let _: (OwnedObjectPath, OwnedObjectPath) = bus.call(NM_PATH, NM, "AddAndActivateConnection", &(d, op(&dev), op("/"))).await?;
                        }
                        None => {
                            let _: OwnedObjectPath = bus.call(SETTINGS_PATH, IF_SETTINGS, "AddConnection", &(d,)).await?;
                        }
                    }
                    Ok(())
                });
            }
            Cmd::UpdateProfile { path, settings } => {
                let name = settings.get("connection").map(|c| c.s("id")).unwrap_or_default();
                self.task(path.clone(), format!("Save {name}"), Some(format!("Saved {name}")), async move {
                    // Update replaces everything, including secrets: merge stored
                    // secrets back in for any secret-bearing setting we didn't touch.
                    let mut s = settings;
                    for setting in ["802-11-wireless-security", "802-1x", "wireguard", "vpn"] {
                        if !s.contains_key(setting) {
                            continue;
                        }
                        if let Ok(sec) = bus.secrets(&path, setting).await
                            && let Some(values) = sec.get(setting) {
                                let d = s.get_mut(setting).expect("checked");
                                for (k, v) in values {
                                    d.entry(k.clone()).or_insert_with(|| v.clone());
                                }
                            }
                    }
                    bus.call0(&path, IF_CONN, "Update", &(settings_to_dbus(&s),)).await
                });
            }
            Cmd::DeleteProfile { path, label } => {
                self.task(path.clone(), label.clone(), Some(format!("Forgot {label}")), async move { bus.call0(&path, IF_CONN, "Delete", &()).await });
            }
            Cmd::GetSecrets { path, setting } => {
                let ev = self.ev.clone();
                tokio::spawn(async move {
                    match bus.secrets(&path, &setting).await {
                        Ok(s) => {
                            let values = s.get(&setting).cloned().unwrap_or_default();
                            let _ = ev.send(Ev::Secrets { path, setting, values });
                        }
                        Err(e) => {
                            let _ = ev.send(Ev::Error(format!("Reading saved password: {}", friendly(&e))));
                        }
                    }
                });
            }
            Cmd::SetWifiEnabled(on) => self.task("wifi".into(), "Wi-Fi radio".into(), None, async move {
                bus.set_prop(NM_PATH, NM, "WirelessEnabled", Value::from(on)).await
            }),
            Cmd::SetWwanEnabled(on) => self.task("wwan".into(), "Mobile radio".into(), None, async move {
                bus.set_prop(NM_PATH, NM, "WwanEnabled", Value::from(on)).await
            }),
            Cmd::SetNetworkingEnabled(on) => self.task("net".into(), "Networking".into(), None, async move {
                bus.call0(NM_PATH, NM, "Enable", &(on,)).await
            }),
            Cmd::SetHostname(h) => self.task("hostname".into(), "Hostname".into(), Some(format!("Hostname set to {h}")), async move {
                bus.call0(SETTINGS_PATH, IF_SETTINGS, "SaveHostname", &(h,)).await
            }),
            Cmd::CheckConnectivity => {
                let ev = self.ev.clone();
                tokio::spawn(async move {
                    match bus.call::<_, u32>(NM_PATH, NM, "CheckConnectivity", &()).await {
                        Ok(c) => {
                            let _ = ev.send(Ev::Info(format!("Connectivity: {}", model::Connectivity::from_u32(c).label())));
                        }
                        Err(e) => {
                            let _ = ev.send(Ev::Error(format!("Connectivity check: {}", friendly(&e))));
                        }
                    }
                });
            }
            Cmd::SetManaged { device, on } => self.task(device.clone(), "Managed".into(), None, async move {
                bus.set_prop(&device, IF_DEVICE, "Managed", Value::from(on)).await
            }),
            Cmd::SetDeviceAutoconnect { device, on } => self.task(device.clone(), "Autoconnect".into(), None, async move {
                bus.set_prop(&device, IF_DEVICE, "Autoconnect", Value::from(on)).await
            }),
            Cmd::Import { kind, file } => {
                // NM has no D-Bus import API; the VPN plugins' importers live in
                // libnm, which nmcli wraps. Shelling out is the reliable route.
                let ev = self.ev.clone();
                tokio::spawn(async move {
                    let _ = ev.send(Ev::Busy { key: "import".into(), label: "Import".into(), on: true });
                    let out = tokio::process::Command::new("nmcli").args(["connection", "import", "type", &kind, "file", &file]).output().await;
                    let _ = ev.send(Ev::Busy { key: "import".into(), label: "Import".into(), on: false });
                    let _ = match out {
                        Ok(o) if o.status.success() => ev.send(Ev::Ok(String::from_utf8_lossy(&o.stdout).trim().to_string())),
                        Ok(o) => ev.send(Ev::Error(format!("Import: {}", String::from_utf8_lossy(&o.stderr).trim()))),
                        Err(e) => ev.send(Ev::Error(format!("Import: couldn't run nmcli: {e}"))),
                    };
                });
            }
            Cmd::SecretReply { id, secrets } => {
                if let Some((_, _, tx)) = self.pending.lock().expect("agent map").remove(&id) {
                    let _ = tx.send(secrets);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn val_round_trip_through_zvariant() {
        let mut d = Dict::new();
        d.insert("address".into(), Val::Str("10.0.0.2".into()));
        d.insert("prefix".into(), Val::U32(24));
        let cases = vec![
            Val::Bool(true),
            Val::U32(7),
            Val::I64(-1),
            Val::Str("x".into()),
            Val::Bytes(b"ssid".to_vec()),
            Val::StrList(vec!["a".into(), "b".into()]),
            Val::U32List(vec![1, 2]),
            Val::BytesList(vec![vec![0u8; 16]]),
            Val::DictList(vec![d.clone()]),
            Val::Dict(d),
            Val::StrMap(BTreeMap::from([("mode".into(), "802.3ad".into())])),
        ];
        for c in cases {
            let v = from_val(&c).unwrap();
            assert_eq!(to_val(&v), c, "{c:?}");
        }
    }

    #[test]
    fn secret_key_selection() {
        let s = super::super::form::wifi_join_settings("Home", Some("wpa-psk"), "x", false);
        assert_eq!(secret_key(&s, "802-11-wireless-security", &[]), "psk");
        let s = super::super::form::wifi_join_settings("Old", Some("none"), "x", false);
        assert_eq!(secret_key(&s, "802-11-wireless-security", &[]), "wep-key0");
        assert_eq!(secret_key(&Settings::new(), "vpn", &["password".into()]), "password");
    }
}
