//! Typed view of NetworkManager state, parsed from an ObjectManager snapshot
//! (`Objects`) plus each saved connection's settings. Pure code: no D-Bus here.

use std::collections::{BTreeMap, BTreeSet};

use super::val::{ssid_to_string, Dict, DictExt, Objects, Settings, Val};

pub const NM: &str = "org.freedesktop.NetworkManager";
pub const NM_PATH: &str = "/org/freedesktop/NetworkManager";
const IF_DEVICE: &str = "org.freedesktop.NetworkManager.Device";
const IF_WIRELESS: &str = "org.freedesktop.NetworkManager.Device.Wireless";
const IF_WIRED: &str = "org.freedesktop.NetworkManager.Device.Wired";
const IF_AP: &str = "org.freedesktop.NetworkManager.AccessPoint";
const IF_ACTIVE: &str = "org.freedesktop.NetworkManager.Connection.Active";
const IF_IP4: &str = "org.freedesktop.NetworkManager.IP4Config";
const IF_IP6: &str = "org.freedesktop.NetworkManager.IP6Config";
const IF_SETTINGS: &str = "org.freedesktop.NetworkManager.Settings";
const IF_CONN: &str = "org.freedesktop.NetworkManager.Settings.Connection";

#[derive(Clone, Debug, Default, PartialEq)]
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

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
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

#[derive(Clone, Debug, Default, PartialEq)]
pub struct IpInfo {
    /// "192.168.1.20/24"
    pub addresses: Vec<String>,
    pub gateway: String,
    pub dns: Vec<String>,
    pub domains: Vec<String>,
}

#[derive(Clone, Debug, PartialEq)]
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
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

#[derive(Clone, Debug, PartialEq)]
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

#[derive(Clone, Debug, PartialEq)]
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

#[derive(Clone, Debug, PartialEq)]
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

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Snapshot {
    pub general: General,
    pub devices: Vec<Device>,
    pub aps: BTreeMap<String, AccessPoint>,
    pub active: Vec<ActiveConn>,
    pub profiles: Vec<Profile>,
}

fn ip_info(objs: &Objects, path: Option<String>, v6: bool) -> IpInfo {
    let Some(p) = path else { return IpInfo::default() };
    let Some(cfg) = objs.get(&p).and_then(|o| o.get(if v6 { IF_IP6 } else { IF_IP4 })) else {
        return IpInfo::default();
    };
    let addresses = cfg
        .get("AddressData")
        .map(|v| v.dict_list().iter().map(|d| format!("{}/{}", d.s("address"), d.u("prefix"))).collect())
        .unwrap_or_default();
    let dns = if v6 {
        match cfg.get("Nameservers") {
            Some(Val::BytesList(list)) => list.iter().filter_map(|b| ip6_from_bytes(b)).collect(),
            _ => Vec::new(),
        }
    } else {
        cfg.get("NameserverData").map(|v| v.dict_list().iter().map(|d| d.s("address")).collect()).unwrap_or_default()
    };
    IpInfo { addresses, gateway: cfg.s("Gateway"), dns, domains: cfg.get("Domains").map(Val::str_list).unwrap_or_default() }
}

pub fn ip6_from_bytes(b: &[u8]) -> Option<String> {
    let arr: [u8; 16] = b.try_into().ok()?;
    Some(std::net::Ipv6Addr::from(arr).to_string())
}

/// Build a snapshot from ObjectManager data plus cached connection settings.
pub fn parse(objs: &Objects, settings: &BTreeMap<String, Settings>) -> Snapshot {
    let empty = Dict::new();
    let nm = objs.get(NM_PATH).and_then(|o| o.get(NM)).unwrap_or(&empty);
    let nms = objs.get(&format!("{NM_PATH}/Settings")).and_then(|o| o.get(IF_SETTINGS)).unwrap_or(&empty);
    let general = General {
        version: nm.s("Version"),
        hostname: nms.s("Hostname"),
        networking_enabled: nm.b("NetworkingEnabled"),
        wifi_enabled: nm.b("WirelessEnabled"),
        wifi_hw_enabled: nm.opt_b("WirelessHardwareEnabled").unwrap_or(true),
        wwan_enabled: nm.b("WwanEnabled"),
        wwan_hw_enabled: nm.b("WwanHardwareEnabled"),
        connectivity: Connectivity::from_u32(nm.u("Connectivity")),
        connectivity_check_enabled: nm.b("ConnectivityCheckEnabled"),
        state: nm.u("State"),
        wifi_backend: None,
    };

    let mut devices = Vec::new();
    let mut aps = BTreeMap::new();
    let mut active = Vec::new();
    for (path, ifaces) in objs {
        if let Some(d) = ifaces.get(IF_DEVICE) {
            let reason = match d.get("StateReason") {
                Some(Val::U32List(v)) => v.get(1).copied().unwrap_or(0),
                _ => 0,
            };
            let mut dev = Device {
                path: path.clone(),
                iface: d.s("Interface"),
                kind: DevKind::from_u32(d.u("DeviceType")),
                state: DevState::from_u32(d.u("State")),
                state_reason: reason,
                managed: d.b("Managed"),
                autoconnect: d.b("Autoconnect"),
                driver: d.s("Driver"),
                hw_addr: d.s("HwAddress"),
                perm_hw_addr: String::new(),
                mtu: d.u("Mtu"),
                active: d.path("ActiveConnection"),
                ip4: ip_info(objs, d.path("Ip4Config"), false),
                ip6: ip_info(objs, d.path("Ip6Config"), true),
                speed: 0,
                carrier: None,
                access_points: Vec::new(),
                active_ap: None,
                bitrate_kbps: 0,
                last_scan_ms: 0,
                available_connections: d.paths("AvailableConnections"),
            };
            if let Some(w) = ifaces.get(IF_WIRELESS) {
                dev.access_points = w.paths("AccessPoints");
                dev.active_ap = w.path("ActiveAccessPoint");
                dev.bitrate_kbps = w.u("Bitrate");
                dev.last_scan_ms = w.i("LastScan");
                dev.perm_hw_addr = w.s("PermHwAddress");
            }
            if let Some(w) = ifaces.get(IF_WIRED) {
                dev.speed = w.u("Speed");
                dev.carrier = w.opt_b("Carrier");
                dev.perm_hw_addr = w.s("PermHwAddress");
            }
            devices.push(dev);
        }
        if let Some(a) = ifaces.get(IF_AP) {
            let ssid_bytes = a.get("Ssid").and_then(Val::bytes).map(<[u8]>::to_vec).unwrap_or_default();
            aps.insert(
                path.clone(),
                AccessPoint {
                    path: path.clone(),
                    ssid: ssid_to_string(&ssid_bytes),
                    ssid_bytes,
                    bssid: a.s("HwAddress"),
                    strength: a.u("Strength").min(100) as u8,
                    freq: a.u("Frequency"),
                    security: Security::from_flags(a.u("Flags"), a.u("WpaFlags"), a.u("RsnFlags")),
                    max_bitrate_kbps: a.u("MaxBitrate"),
                    mode: a.u("Mode"),
                },
            );
        }
        if let Some(a) = ifaces.get(IF_ACTIVE) {
            active.push(ActiveConn {
                path: path.clone(),
                conn_path: a.s("Connection"),
                id: a.s("Id"),
                uuid: a.s("Uuid"),
                kind: a.s("Type"),
                devices: a.paths("Devices"),
                state: a.u("State"),
                default4: a.b("Default"),
                vpn: a.b("Vpn"),
            });
        }
    }
    // Loopback first is noise; sort by kind then name.
    devices.sort_by(|a, b| (a.kind, &a.iface).cmp(&(b.kind, &b.iface)));

    let mut profiles: Vec<Profile> = settings
        .iter()
        .map(|(p, s)| Profile::from_settings(p, s, objs.get(p).and_then(|o| o.get(IF_CONN))))
        .collect();
    for prof in &mut profiles {
        if let Some(a) = active.iter().find(|a| a.conn_path == prof.path) {
            prof.active_state = Some(a.state);
            prof.active_devices = a
                .devices
                .iter()
                .filter_map(|dp| devices.iter().find(|d| &d.path == dp).map(|d| d.iface.clone()))
                .collect();
        }
    }
    profiles.sort_by_key(|a| (!a.is_active(), kind_rank(&a.kind), a.id.to_lowercase()));
    Snapshot { general, devices, aps, active, profiles }
}

fn kind_rank(k: &str) -> u8 {
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

/// Find `wifi.backend=` in NetworkManager's config files (best effort, read-only).
pub fn detect_wifi_backend() -> Option<String> {
    let mut files = vec![std::path::PathBuf::from("/etc/NetworkManager/NetworkManager.conf")];
    for dir in ["/usr/lib/NetworkManager/conf.d", "/etc/NetworkManager/conf.d", "/run/NetworkManager/conf.d"] {
        if let Ok(rd) = std::fs::read_dir(dir) {
            let mut v: Vec<_> = rd.flatten().map(|e| e.path()).filter(|p| p.extension().is_some_and(|e| e == "conf")).collect();
            v.sort();
            files.extend(v);
        }
    }
    let mut found = None;
    for f in files {
        if let Ok(text) = std::fs::read_to_string(&f)
            && let Some(v) = parse_wifi_backend(&text) {
                found = Some(v); // later files override earlier ones
            }
    }
    found
}

pub fn parse_wifi_backend(text: &str) -> Option<String> {
    let mut section = String::new();
    let mut found = None;
    for line in text.lines() {
        let l = line.trim();
        if l.starts_with('[') && l.ends_with(']') {
            section = l[1..l.len() - 1].trim().to_string();
        } else if (section == "device" || section.starts_with("device-"))
            && let Some(v) = l.strip_prefix("wifi.backend") {
                let v = v.trim_start().strip_prefix('=').map(str::trim);
                if let Some(v) = v.filter(|v| !v.is_empty()) {
                    found = Some(v.to_string());
                }
            }
    }
    found
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

    #[test]
    fn wifi_backend_detection() {
        assert_eq!(parse_wifi_backend("[device]\nwifi.backend=iwd\n"), Some("iwd".into()));
        assert_eq!(parse_wifi_backend("[main]\nwifi.backend=iwd\n"), None);
        assert_eq!(parse_wifi_backend("[device-wlan]\nwifi.backend = wpa_supplicant\n"), Some("wpa_supplicant".into()));
    }

    fn ap(ssid: &str, strength: u32, freq: u32, rsn: u32) -> BTreeMap<String, Dict> {
        let mut d = Dict::new();
        d.insert("Ssid".into(), Val::Bytes(ssid.as_bytes().to_vec()));
        d.insert("Strength".into(), Val::U8(strength as u8));
        d.insert("Frequency".into(), Val::U32(freq));
        d.insert("Flags".into(), Val::U32(1));
        d.insert("WpaFlags".into(), Val::U32(0));
        d.insert("RsnFlags".into(), Val::U32(rsn));
        d.insert("HwAddress".into(), Val::Str("00:11:22:33:44:55".into()));
        BTreeMap::from([(IF_AP.to_string(), d)])
    }

    #[test]
    fn parse_and_group_networks() {
        let mut objs = Objects::new();
        let mut nm = Dict::new();
        nm.insert("Version".into(), Val::Str("1.52.0".into()));
        nm.insert("WirelessEnabled".into(), Val::Bool(true));
        nm.insert("Connectivity".into(), Val::U32(4));
        objs.insert(NM_PATH.into(), BTreeMap::from([(NM.to_string(), nm)]));
        let mut dev = Dict::new();
        dev.insert("Interface".into(), Val::Str("wlan0".into()));
        dev.insert("DeviceType".into(), Val::U32(2));
        dev.insert("State".into(), Val::U32(100));
        dev.insert("StateReason".into(), Val::U32List(vec![100, 0]));
        let mut w = Dict::new();
        w.insert("AccessPoints".into(), Val::PathList(vec!["/ap/1".into(), "/ap/2".into(), "/ap/3".into(), "/ap/4".into()]));
        w.insert("ActiveAccessPoint".into(), Val::Path("/ap/2".into()));
        objs.insert("/dev/wlan0".into(), BTreeMap::from([(IF_DEVICE.to_string(), dev), (IF_WIRELESS.to_string(), w)]));
        objs.insert("/ap/1".into(), ap("Home", 40, 2437, 0x188));
        objs.insert("/ap/2".into(), ap("Home", 80, 5180, 0x188));
        objs.insert("/ap/3".into(), ap("Cafe", 90, 2412, 0));
        objs.insert("/ap/4".into(), ap("", 70, 2412, 0x188));

        let mut s = Settings::new();
        let mut c = Dict::new();
        c.insert("id".into(), Val::Str("Home".into()));
        c.insert("type".into(), Val::Str("802-11-wireless".into()));
        c.insert("uuid".into(), Val::Str("u1".into()));
        s.insert("connection".into(), c);
        let mut wl = Dict::new();
        wl.insert("ssid".into(), Val::Bytes(b"Home".to_vec()));
        s.insert("802-11-wireless".into(), wl);
        let settings = BTreeMap::from([("/conn/1".to_string(), s)]);

        let snap = parse(&objs, &settings);
        assert_eq!(snap.general.connectivity, Connectivity::Full);
        assert_eq!(snap.devices.len(), 1);
        let nets = networks(&snap, "/dev/wlan0");
        assert_eq!(nets.len(), 2, "hidden SSID skipped, Home merged");
        assert_eq!(nets[0].ssid, "Home");
        assert!(nets[0].connected);
        assert_eq!(nets[0].strength, 80);
        assert_eq!(nets[0].ap_count, 2);
        assert_eq!(nets[0].bands.len(), 2);
        assert_eq!(nets[0].profile.as_deref(), Some("/conn/1"));
        assert_eq!(nets[1].ssid, "Cafe");
        assert_eq!(nets[1].security, Security::Wep);
    }
}
