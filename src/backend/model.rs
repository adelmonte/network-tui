//! Typed view of the network state the daemon publishes: devices, access
//! points, active connections and saved profiles. Profiles keep
//! NetworkManager's settings layout (`connection`, `ipv4`, ...), which the
//! editor and the daemon both speak. Pure code, serializable for the socket.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::val::{ssid_to_string, Dict, DictExt, Settings, Val};

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct General {
    pub version: String,
    pub hostname: String,
    pub networking_enabled: bool,
    pub wifi_enabled: bool,
    pub wifi_hw_enabled: bool,
    pub wwan_enabled: bool,
    pub wwan_hw_enabled: bool,
    pub connectivity: Connectivity,
    pub connectivity_check_enabled: bool,
    pub state: u32,
    /// Which Wi-Fi backend NM is configured with ("iwd", "wpa_supplicant"), from NM's config files.
    pub wifi_backend: Option<String>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum Connectivity {
    #[default]
    Unknown,
    None,
    Portal,
    Limited,
    Full,
}

impl Connectivity {
    pub fn from_u32(v: u32) -> Self {
        match v {
            1 => Self::None,
            2 => Self::Portal,
            3 => Self::Limited,
            4 => Self::Full,
            _ => Self::Unknown,
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::None => "offline",
            Self::Portal => "captive portal (sign-in page)",
            Self::Limited => "limited (no internet)",
            Self::Full => "online",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum DevKind {
    Ethernet,
    Wifi,
    WireGuard,
    Bridge,
    Bond,
    Vlan,
    Tun,
    Bluetooth,
    Modem,
    Loopback,
    Other,
}

impl DevKind {
    pub fn from_u32(v: u32) -> Self {
        match v {
            1 => Self::Ethernet,
            2 => Self::Wifi,
            5 => Self::Bluetooth,
            8 => Self::Modem,
            10 => Self::Bond,
            11 => Self::Vlan,
            13 => Self::Bridge,
            16 => Self::Tun,
            29 => Self::WireGuard,
            32 => Self::Loopback,
            _ => Self::Other,
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            Self::Ethernet => "Ethernet",
            Self::Wifi => "Wi-Fi",
            Self::WireGuard => "WireGuard",
            Self::Bridge => "Bridge",
            Self::Bond => "Bond",
            Self::Vlan => "VLAN",
            Self::Tun => "TUN/TAP",
            Self::Bluetooth => "Bluetooth",
            Self::Modem => "Mobile broadband",
            Self::Loopback => "Loopback",
            Self::Other => "Other",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum DevState {
    Unknown,
    Unmanaged,
    Unavailable,
    Disconnected,
    Connecting,
    NeedAuth,
    Connected,
    Disconnecting,
    Failed,
}

impl DevState {
    pub fn from_u32(v: u32) -> Self {
        match v {
            10 => Self::Unmanaged,
            20 => Self::Unavailable,
            30 => Self::Disconnected,
            40 | 50 | 70 | 80 | 90 => Self::Connecting,
            60 => Self::NeedAuth,
            100 => Self::Connected,
            110 => Self::Disconnecting,
            120 => Self::Failed,
            _ => Self::Unknown,
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Unmanaged => "unmanaged",
            Self::Unavailable => "unavailable",
            Self::Disconnected => "disconnected",
            Self::Connecting => "connecting",
            Self::NeedAuth => "needs password",
            Self::Connected => "connected",
            Self::Disconnecting => "disconnecting",
            Self::Failed => "failed",
        }
    }
    pub fn busy(self) -> bool {
        matches!(self, Self::Connecting | Self::NeedAuth | Self::Disconnecting)
    }
}

/// Plain-English text for NetworkManager device state reasons.
pub fn reason_text(code: u32) -> Option<&'static str> {
    Some(match code {
        4 => "configuration failed",
        5 => "no IP address could be obtained",
        6 => "the IP address lease expired",
        7 => "a password is needed",
        8 => "the network disconnected us (often a wrong password)",
        9 => "the Wi-Fi configuration was rejected",
        10 => "Wi-Fi authentication failed",
        11 => "Wi-Fi authentication timed out (wrong password or weak signal)",
        15 => "DHCP couldn't start",
        16 => "DHCP error",
        17 => "DHCP failed — no address from the router",
        39 => "disconnected by user",
        40 => "the cable was unplugged",
        53 => "the network wasn't found (out of range or hidden?)",
        _ => return None,
    })
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct IpInfo {
    /// "192.168.1.20/24"
    pub addresses: Vec<String>,
    pub gateway: String,
    pub dns: Vec<String>,
    pub domains: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Device {
    pub path: String,
    pub iface: String,
    pub kind: DevKind,
    pub state: DevState,
    pub state_reason: u32,
    pub managed: bool,
    pub autoconnect: bool,
    pub driver: String,
    pub hw_addr: String,
    pub perm_hw_addr: String,
    pub mtu: u32,
    pub active: Option<String>,
    pub ip4: IpInfo,
    pub ip6: IpInfo,
    /// Wired: link speed (Mb/s) and cable carrier.
    pub speed: u32,
    pub carrier: Option<bool>,
    /// Wireless.
    pub access_points: Vec<String>,
    pub active_ap: Option<String>,
    pub bitrate_kbps: u32,
    pub last_scan_ms: i64,
    pub available_connections: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Security {
    Open,
    Owe,
    Wep,
    Wpa,
    Wpa2,
    Wpa2Wpa3,
    Wpa3,
    Enterprise,
}

impl Security {
    pub fn from_flags(flags: u32, wpa: u32, rsn: u32) -> Self {
        let any = wpa | rsn;
        if any & 0x200 != 0 || any & 0x2000 != 0 {
            Self::Enterprise
        } else if any & 0x400 != 0 && any & 0x100 != 0 {
            Self::Wpa2Wpa3
        } else if any & 0x400 != 0 {
            Self::Wpa3
        } else if rsn & 0x100 != 0 {
            Self::Wpa2
        } else if wpa & 0x100 != 0 {
            Self::Wpa
        } else if any & 0x1800 != 0 {
            Self::Owe
        } else if flags & 0x1 != 0 {
            Self::Wep
        } else {
            Self::Open
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Owe => "enhanced open",
            Self::Wep => "WEP",
            Self::Wpa => "WPA",
            Self::Wpa2 => "WPA2",
            Self::Wpa2Wpa3 => "WPA2/3",
            Self::Wpa3 => "WPA3",
            Self::Enterprise => "802.1X",
        }
    }
    pub fn needs_password(self) -> bool {
        matches!(self, Self::Wep | Self::Wpa | Self::Wpa2 | Self::Wpa2Wpa3 | Self::Wpa3)
    }
    pub fn is_open(self) -> bool {
        matches!(self, Self::Open | Self::Owe)
    }
    /// NM `802-11-wireless-security.key-mgmt` to use when creating a profile.
    pub fn key_mgmt(self) -> Option<&'static str> {
        match self {
            Self::Open => None,
            Self::Owe => Some("owe"),
            Self::Wep => Some("none"),
            Self::Wpa | Self::Wpa2 | Self::Wpa2Wpa3 => Some("wpa-psk"),
            Self::Wpa3 => Some("sae"),
            Self::Enterprise => Some("wpa-eap"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AccessPoint {
    pub path: String,
    pub ssid: String,
    pub ssid_bytes: Vec<u8>,
    pub bssid: String,
    pub strength: u8,
    pub freq: u32,
    pub security: Security,
    pub max_bitrate_kbps: u32,
    pub mode: u32,
}

pub fn band(freq: u32) -> &'static str {
    match freq {
        2400..=2500 => "2.4 GHz",
        4900..=5900 => "5 GHz",
        5925..=7125 => "6 GHz",
        _ => "?",
    }
}

pub fn channel(freq: u32) -> u32 {
    match freq {
        2484 => 14,
        2412..=2472 => (freq - 2407) / 5,
        5000..=5900 => (freq - 5000) / 5,
        5955..=7115 => (freq - 5950) / 5,
        _ => 0,
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ActiveConn {
    pub path: String,
    pub conn_path: String,
    pub id: String,
    pub uuid: String,
    pub kind: String,
    pub devices: Vec<String>,
    /// 1 activating, 2 activated, 3 deactivating, 4 deactivated
    pub state: u32,
    pub default4: bool,
    pub vpn: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Profile {
    pub path: String,
    pub uuid: String,
    pub id: String,
    /// NM connection.type, e.g. "802-11-wireless", "802-3-ethernet", "wireguard", "vpn".
    pub kind: String,
    pub iface: String,
    pub autoconnect: bool,
    pub priority: i64,
    pub ssid: Option<String>,
    /// Last successful activation (unix seconds), 0 = never.
    pub timestamp: u64,
    pub filename: String,
    pub unsaved: bool,
    pub settings: Settings,
    /// Filled in from the active connection list.
    pub active_state: Option<u32>,
    pub active_devices: Vec<String>,
}

impl Profile {
    pub fn from_settings(path: &str, s: &Settings, conn_props: Option<&Dict>) -> Self {
        let c = s.get("connection").cloned().unwrap_or_default();
        let ssid = s.get("802-11-wireless").and_then(|w| w.get("ssid")).and_then(Val::bytes).map(ssid_to_string);
        Self {
            path: path.to_string(),
            uuid: c.s("uuid"),
            id: c.s("id"),
            kind: c.s("type"),
            iface: c.s("interface-name"),
            autoconnect: c.opt_b("autoconnect").unwrap_or(true),
            priority: c.i("autoconnect-priority"),
            ssid,
            timestamp: c.get("timestamp").and_then(Val::i64).unwrap_or(0).max(0) as u64,
            filename: conn_props.map(|p| p.s("Filename")).unwrap_or_default(),
            unsaved: conn_props.is_some_and(|p| p.b("Unsaved")),
            settings: s.clone(),
            active_state: None,
            active_devices: Vec::new(),
        }
    }

    pub fn kind_label(&self) -> &'static str {
        kind_label(&self.kind)
    }

    pub fn is_active(&self) -> bool {
        matches!(self.active_state, Some(1 | 2))
    }

    pub fn is_wifi(&self) -> bool {
        self.kind == "802-11-wireless"
    }

    pub fn wifi_mode(&self) -> String {
        self.settings.get("802-11-wireless").map(|w| w.s("mode")).unwrap_or_default()
    }

    /// Short summary of the IPv4 setup, e.g. "DHCP" or "static 10.0.0.5/24".
    pub fn ipv4_summary(&self) -> String {
        let Some(ip) = self.settings.get("ipv4") else { return "—".into() };
        match ip.s("method").as_str() {
            "auto" | "" => "automatic (DHCP)".into(),
            "manual" => {
                let addrs: Vec<String> = ip
                    .get("address-data")
                    .map(|v| v.dict_list().iter().map(|d| format!("{}/{}", d.s("address"), d.u("prefix"))).collect())
                    .unwrap_or_default();
                format!("static {}", addrs.join(", "))
            }
            "shared" => "shared to other computers".into(),
            "link-local" => "link-local only".into(),
            "disabled" => "disabled".into(),
            m => m.to_string(),
        }
    }
}

pub fn kind_label(kind: &str) -> &'static str {
    match kind {
        "802-11-wireless" => "Wi-Fi",
        "802-3-ethernet" => "Ethernet",
        "wireguard" => "WireGuard",
        "vpn" => "VPN",
        "bridge" => "Bridge",
        "bond" => "Bond",
        "vlan" => "VLAN",
        "loopback" => "Loopback",
        "gsm" | "cdma" => "Mobile broadband",
        "bluetooth" => "Bluetooth",
        "tun" => "TUN/TAP",
        "dummy" => "Dummy",
        _ => "Other",
    }
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Snapshot {
    pub general: General,
    pub devices: Vec<Device>,
    pub aps: BTreeMap<String, AccessPoint>,
    pub active: Vec<ActiveConn>,
    pub profiles: Vec<Profile>,
}

pub fn ip6_from_bytes(b: &[u8]) -> Option<String> {
    let arr: [u8; 16] = b.try_into().ok()?;
    Some(std::net::Ipv6Addr::from(arr).to_string())
}

pub fn kind_rank(k: &str) -> u8 {
    match k {
        "802-3-ethernet" => 0,
        "802-11-wireless" => 1,
        "wireguard" | "vpn" => 2,
        _ => 3,
    }
}

/// One row in the Wi-Fi list: all access points sharing an SSID, merged.
#[derive(Clone, Debug, PartialEq)]
pub struct Network {
    pub ssid: String,
    pub ssid_bytes: Vec<u8>,
    pub strength: u8,
    pub security: Security,
    pub bands: BTreeSet<&'static str>,
    /// Strongest AP (used for connecting and details).
    pub best_ap: String,
    pub ap_count: usize,
    /// Saved profile for this SSID, if any (best by priority, then last used).
    pub profile: Option<String>,
    pub connected: bool,
    pub connecting: bool,
}

/// Group a Wi-Fi device's access points into networks.
pub fn networks(snap: &Snapshot, device_path: &str) -> Vec<Network> {
    let Some(dev) = snap.devices.iter().find(|d| d.path == device_path) else { return Vec::new() };
    let active_ssid = dev.active_ap.as_ref().and_then(|p| snap.aps.get(p)).map(|a| a.ssid_bytes.clone());
    let mut by_ssid: BTreeMap<Vec<u8>, Network> = BTreeMap::new();
    for ap in dev.access_points.iter().filter_map(|p| snap.aps.get(p)) {
        if ap.ssid_bytes.is_empty() {
            continue; // hidden network beacon; reachable via "connect to hidden"
        }
        let n = by_ssid.entry(ap.ssid_bytes.clone()).or_insert_with(|| Network {
            ssid: ap.ssid.clone(),
            ssid_bytes: ap.ssid_bytes.clone(),
            strength: 0,
            security: ap.security,
            bands: BTreeSet::new(),
            best_ap: ap.path.clone(),
            ap_count: 0,
            profile: None,
            connected: false,
            connecting: false,
        });
        n.ap_count += 1;
        n.bands.insert(band(ap.freq));
        if ap.strength > n.strength {
            n.strength = ap.strength;
            n.best_ap = ap.path.clone();
            n.security = ap.security;
        }
    }
    let mut out: Vec<Network> = by_ssid.into_values().collect();
    for n in &mut out {
        let mut cands: Vec<&Profile> = snap
            .profiles
            .iter()
            .filter(|p| p.is_wifi() && p.wifi_mode() != "ap" && p.ssid.as_deref() == Some(n.ssid.as_str()))
            .filter(|p| p.iface.is_empty() || p.iface == dev.iface)
            .collect();
        cands.sort_by_key(|p| (std::cmp::Reverse(p.is_active()), std::cmp::Reverse(p.priority), std::cmp::Reverse(p.timestamp)));
        n.profile = cands.first().map(|p| p.path.clone());
        if active_ssid.as_ref() == Some(&n.ssid_bytes) {
            n.connected = dev.state == DevState::Connected;
            n.connecting = dev.state.busy();
        }
    }
    out.sort_by(|a, b| {
        (!(a.connected || a.connecting), a.profile.is_none(), std::cmp::Reverse(a.strength), a.ssid.to_lowercase())
            .cmp(&(!(b.connected || b.connecting), b.profile.is_none(), std::cmp::Reverse(b.strength), b.ssid.to_lowercase()))
    });
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn security_classification() {
        assert_eq!(Security::from_flags(0, 0, 0), Security::Open);
        assert_eq!(Security::from_flags(1, 0, 0), Security::Wep);
        assert_eq!(Security::from_flags(1, 0, 0x188), Security::Wpa2);
        assert_eq!(Security::from_flags(1, 0x188, 0), Security::Wpa);
        assert_eq!(Security::from_flags(1, 0, 0x588), Security::Wpa2Wpa3);
        assert_eq!(Security::from_flags(1, 0, 0x488), Security::Wpa3);
        assert_eq!(Security::from_flags(1, 0, 0x288), Security::Enterprise);
        assert_eq!(Security::from_flags(0, 0, 0x808), Security::Owe);
    }

    #[test]
    fn channels_and_bands() {
        assert_eq!(channel(2412), 1);
        assert_eq!(channel(2437), 6);
        assert_eq!(channel(5180), 36);
        assert_eq!(channel(5955), 1);
        assert_eq!(band(5500), "5 GHz");
        assert_eq!(band(2462), "2.4 GHz");
    }
}
