//! iwd over D-Bus: Wi-Fi state, connecting, scanning, access point mode,
//! and the password agent iwd calls when it needs a secret.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use futures::StreamExt;
use tokio::sync::{mpsc::UnboundedSender, oneshot};
use zbus::zvariant::{ObjectPath, OwnedObjectPath, OwnedValue, Value};
use zbus::{Connection, MatchRule, MessageStream};

use crate::backend::val::{Dict, DictExt, Val};

use super::Internal;

pub const IWD: &str = "net.connman.iwd";
const AGENT_PATH: &str = "/network_tui/agent";
const IF_ADAPTER: &str = "net.connman.iwd.Adapter";
const IF_DEVICE: &str = "net.connman.iwd.Device";
const IF_STATION: &str = "net.connman.iwd.Station";
const IF_NETWORK: &str = "net.connman.iwd.Network";
const IF_KNOWN: &str = "net.connman.iwd.KnownNetwork";
const IF_AP: &str = "net.connman.iwd.AccessPoint";
const IF_DIAG: &str = "net.connman.iwd.StationDiagnostic";

#[derive(Clone, Debug, Default)]
pub struct Adapter {
    pub powered: bool,
}

#[derive(Clone, Debug, Default)]
pub struct IwdDevice {
    pub path: String,
    pub name: String,
    pub powered: bool,
    pub mode: String,
}

#[derive(Clone, Debug, Default)]
pub struct Station {
    pub state: String,
    pub connected_network: Option<String>,
    pub scanning: bool,
}

#[derive(Clone, Debug, Default)]
pub struct Network {
    pub name: String,
    /// "open", "psk", "8021x", "wep"
    pub kind: String,
    pub device: String,
}

#[derive(Clone, Debug, Default)]
pub struct Known {
    pub name: String,
    pub kind: String,
}

#[derive(Clone, Debug, Default)]
pub struct IwdState {
    pub adapters: BTreeMap<String, Adapter>,
    pub devices: Vec<IwdDevice>,
    /// Keyed by device path.
    pub stations: BTreeMap<String, Station>,
    pub networks: BTreeMap<String, Network>,
    pub known: BTreeMap<String, Known>,
    /// Devices in access point mode, by path.
    pub aps: BTreeSet<String>,
}

impl IwdState {
    pub fn device(&self, ifname: &str) -> Option<&IwdDevice> {
        self.devices.iter().find(|d| d.name == ifname)
    }

    pub fn station(&self, ifname: &str) -> Option<&Station> {
        self.stations.get(&self.device(ifname)?.path)
    }

    /// The network a device is connected (or connecting) to.
    pub fn current_network(&self, ifname: &str) -> Option<&Network> {
        self.networks.get(self.station(ifname)?.connected_network.as_ref()?)
    }

    pub fn network_by_name(&self, ifname: &str, ssid: &str) -> Option<(&String, &Network)> {
        let dev = &self.device(ifname)?.path;
        self.networks.iter().find(|(_, n)| &n.device == dev && n.name == ssid)
    }
}

type Objects = BTreeMap<String, BTreeMap<String, Dict>>;

fn to_val(v: &Value) -> Val {
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
        Value::Array(a) => match a.element_signature().to_string().as_str() {
            "s" => Val::StrList(a.inner().iter().filter_map(|x| if let Value::Str(s) = x { Some(s.to_string()) } else { None }).collect()),
            "o" => Val::PathList(a.inner().iter().filter_map(|x| if let Value::ObjectPath(p) = x { Some(p.to_string()) } else { None }).collect()),
            "y" => Val::Bytes(a.inner().iter().filter_map(|x| if let Value::U8(b) = x { Some(*b) } else { None }).collect()),
            other => Val::Other(format!("a{other}")),
        },
        _ => Val::Other("unsupported".into()),
    }
}

fn op(p: &str) -> ObjectPath<'_> {
    ObjectPath::try_from(p).unwrap_or_else(|_| ObjectPath::try_from("/").expect("root path"))
}

/// iwd's D-Bus errors in plain words, with a reason code the UI understands.
pub fn friendly(e: &zbus::Error) -> (String, u32) {
    let s = e.to_string();
    let name = match e {
        zbus::Error::MethodError(n, _, _) => n.to_string(),
        _ => String::new(),
    };
    let (msg, code) = match name.rsplit('.').next().unwrap_or("") {
        "Failed" | "InvalidFormat" => ("authentication failed (wrong password?)", 8),
        "Timeout" => ("timed out (wrong password or weak signal)", 11),
        "Aborted" => ("cancelled", 39),
        "NotFound" => ("the network wasn't found (out of range or hidden?)", 53),
        "NoAgent" => ("a password is needed", 7),
        "NotSupported" => ("not supported by this network or adapter", 4),
        "Busy" | "InProgress" => ("the adapter is busy — try again in a moment", 4),
        "NotAvailable" => ("Wi-Fi is off or unavailable", 4),
        "NotConfigured" => ("not configured", 4),
        _ => return (s.split_once(": ").map(|(_, m)| m.to_string()).unwrap_or(s), 4),
    };
    (msg.to_string(), code)
}

#[derive(Clone)]
pub struct Iwd {
    conn: Connection,
}

impl Iwd {
    pub async fn connect() -> zbus::Result<Self> {
        Ok(Self { conn: Connection::system().await? })
    }

    async fn call0<B>(&self, path: &str, iface: &str, method: &str, body: &B) -> zbus::Result<()>
    where
        B: serde::Serialize + zbus::zvariant::DynamicType,
    {
        self.conn.call_method(Some(IWD), path, Some(iface), method, body).await?;
        Ok(())
    }

    async fn set_prop(&self, path: &str, iface: &str, prop: &str, v: Value<'_>) -> zbus::Result<()> {
        self.conn.call_method(Some(IWD), path, Some("org.freedesktop.DBus.Properties"), "Set", &(iface, prop, v)).await?;
        Ok(())
    }

    async fn objects(&self) -> zbus::Result<Objects> {
        type Raw = HashMap<OwnedObjectPath, HashMap<String, HashMap<String, OwnedValue>>>;
        let msg = self.conn.call_method(Some(IWD), "/", Some("org.freedesktop.DBus.ObjectManager"), "GetManagedObjects", &()).await?;
        let raw: Raw = msg.body().deserialize()?;
        Ok(raw
            .into_iter()
            .map(|(p, ifaces)| {
                let ifaces = ifaces.into_iter().map(|(i, props)| (i, props.iter().map(|(k, v)| (k.clone(), to_val(v))).collect::<Dict>())).collect();
                (p.to_string(), ifaces)
            })
            .collect())
    }

    pub async fn state(&self) -> zbus::Result<IwdState> {
        let objs = self.objects().await?;
        let mut st = IwdState::default();
        for (path, ifaces) in &objs {
            if let Some(a) = ifaces.get(IF_ADAPTER) {
                st.adapters.insert(path.clone(), Adapter { powered: a.b("Powered") });
            }
            if let Some(d) = ifaces.get(IF_DEVICE) {
                st.devices.push(IwdDevice {
                    path: path.clone(),
                    name: d.s("Name"),
                    powered: d.b("Powered"),
                    mode: d.s("Mode"),
                });
            }
            if let Some(s) = ifaces.get(IF_STATION) {
                st.stations.insert(path.clone(), Station { state: s.s("State"), connected_network: s.path("ConnectedNetwork"), scanning: s.b("Scanning") });
            }
            if let Some(n) = ifaces.get(IF_NETWORK) {
                st.networks.insert(
                    path.clone(),
                    Network { name: n.s("Name"), kind: n.s("Type"), device: n.s("Device") },
                );
            }
            if let Some(k) = ifaces.get(IF_KNOWN) {
                st.known.insert(path.clone(), Known { name: k.s("Name"), kind: k.s("Type") });
            }
            if ifaces.contains_key(IF_AP) {
                st.aps.insert(path.clone());
            }
        }
        Ok(st)
    }

    /// Signal strengths (dBm) of the station's networks, by network path.
    pub async fn ordered_networks(&self, station: &str) -> zbus::Result<Vec<(String, i16)>> {
        let msg = self.conn.call_method(Some(IWD), station, Some(IF_STATION), "GetOrderedNetworks", &()).await?;
        let v: Vec<(OwnedObjectPath, i16)> = msg.body().deserialize()?;
        Ok(v.into_iter().map(|(p, s)| (p.to_string(), s / 100)).collect())
    }

    /// The connected BSSID and bitrate (kbit/s) of a station.
    pub async fn diagnostics(&self, station: &str) -> zbus::Result<(String, u32)> {
        let msg = self.conn.call_method(Some(IWD), station, Some(IF_DIAG), "GetDiagnostics", &()).await?;
        let d: HashMap<String, OwnedValue> = msg.body().deserialize()?;
        let d: Dict = d.iter().map(|(k, v)| (k.clone(), to_val(v))).collect();
        let rate = d.u("RxBitrate").max(d.u("TxBitrate")) * 100;
        Ok((d.s("ConnectedBss").to_lowercase(), rate))
    }

    pub async fn scan(&self, station: &str) -> zbus::Result<()> {
        self.call0(station, IF_STATION, "Scan", &()).await
    }

    pub async fn connect_network(&self, network: &str) -> zbus::Result<()> {
        self.call0(network, IF_NETWORK, "Connect", &()).await
    }

    pub async fn connect_hidden(&self, station: &str, ssid: &str) -> zbus::Result<()> {
        self.call0(station, IF_STATION, "ConnectHiddenNetwork", &(ssid,)).await
    }

    pub async fn disconnect(&self, station: &str) -> zbus::Result<()> {
        self.call0(station, IF_STATION, "Disconnect", &()).await
    }

    pub async fn set_powered(&self, path: &str, adapter: bool, on: bool) -> zbus::Result<()> {
        self.set_prop(path, if adapter { IF_ADAPTER } else { IF_DEVICE }, "Powered", Value::from(on)).await
    }

    pub async fn set_mode(&self, device: &str, mode: &str) -> zbus::Result<()> {
        self.set_prop(device, IF_DEVICE, "Mode", Value::from(mode)).await
    }

    pub async fn ap_start_profile(&self, device: &str, ssid: &str) -> zbus::Result<()> {
        self.call0(device, IF_AP, "StartProfile", &(ssid,)).await
    }

    pub async fn ap_stop(&self, device: &str) -> zbus::Result<()> {
        self.call0(device, IF_AP, "Stop", &()).await
    }

    pub async fn register_agent(&self, tx: UnboundedSender<Internal>) -> zbus::Result<()> {
        let server = self.conn.object_server();
        let _ = server.remove::<Agent, _>(AGENT_PATH).await;
        server.at(AGENT_PATH, Agent { tx }).await?;
        self.call0("/net/connman/iwd", "net.connman.iwd.AgentManager", "RegisterAgent", &(op(AGENT_PATH),)).await
    }

    /// Forward every iwd signal (and iwd starting or stopping) as a nudge.
    pub async fn watch(&self, tx: UnboundedSender<Internal>) -> zbus::Result<()> {
        let rule = MatchRule::builder().msg_type(zbus::message::Type::Signal).sender(IWD)?.build();
        let mut signals = MessageStream::for_match_rule(rule, &self.conn, Some(256)).await?;
        let owner = MatchRule::builder()
            .msg_type(zbus::message::Type::Signal)
            .sender("org.freedesktop.DBus")?
            .member("NameOwnerChanged")?
            .add_arg(IWD)?
            .build();
        let mut owners = MessageStream::for_match_rule(owner, &self.conn, Some(16)).await?;
        tokio::spawn(async move {
            loop {
                let ev = tokio::select! {
                    m = signals.next() => match m { Some(_) => Internal::IwdChanged, None => break },
                    m = owners.next() => match m { Some(_) => Internal::IwdRestarted, None => break },
                };
                if tx.send(ev).is_err() {
                    break;
                }
            }
        });
        Ok(())
    }
}

/// What iwd's agent asked for.
#[derive(Clone, Debug, PartialEq)]
pub enum Ask {
    Passphrase,
    PrivateKeyPassphrase,
    UserAndPassword,
    Password(String),
}

#[derive(Debug, zbus::DBusError)]
#[zbus(prefix = "net.connman.iwd.Agent.Error")]
enum AgentError {
    #[zbus(error)]
    ZBus(zbus::Error),
    Canceled(String),
}

struct Agent {
    tx: UnboundedSender<Internal>,
}

impl Agent {
    async fn ask(&self, network: OwnedObjectPath, ask: Ask) -> Result<Vec<String>, AgentError> {
        let (reply, rx) = oneshot::channel();
        let _ = self.tx.send(Internal::Agent { network: network.to_string(), ask, reply });
        match rx.await {
            Ok(Some(v)) => Ok(v),
            _ => Err(AgentError::Canceled("cancelled".into())),
        }
    }
}

#[zbus::interface(name = "net.connman.iwd.Agent")]
impl Agent {
    async fn release(&self) {}

    async fn request_passphrase(&self, network: OwnedObjectPath) -> Result<String, AgentError> {
        Ok(self.ask(network, Ask::Passphrase).await?.into_iter().next().unwrap_or_default())
    }

    async fn request_private_key_passphrase(&self, network: OwnedObjectPath) -> Result<String, AgentError> {
        Ok(self.ask(network, Ask::PrivateKeyPassphrase).await?.into_iter().next().unwrap_or_default())
    }

    async fn request_user_name_and_password(&self, network: OwnedObjectPath) -> Result<(String, String), AgentError> {
        let mut v = self.ask(network, Ask::UserAndPassword).await?.into_iter();
        Ok((v.next().unwrap_or_default(), v.next().unwrap_or_default()))
    }

    async fn request_user_password(&self, network: OwnedObjectPath, user: String) -> Result<String, AgentError> {
        Ok(self.ask(network, Ask::Password(user)).await?.into_iter().next().unwrap_or_default())
    }

    async fn cancel(&self, _reason: String) {
        let _ = self.tx.send(Internal::AgentCancel);
    }
}
