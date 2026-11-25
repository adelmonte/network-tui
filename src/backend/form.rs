//! Connection profile editor model: NM settings <-> editable fields.
//!
//! Round-trips are conservative: we start from the profile's existing
//! settings and only touch keys the editor owns, so options set elsewhere
//! (nmcli, nm-connection-editor) survive an edit.

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, Ipv6Addr};

use super::val::{ssid_to_string, Dict, DictExt, Settings, Val};

/// Editable fields. (Names mirror NM terms like "key-mgmt"/"private-key".)
#[allow(clippy::enum_variant_names)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Key {
    // general
    Id,
    Iface,
    Autoconnect,
    Priority,
    AllUsers,
    Mac,
    MacCustom,
    Mtu,
    Controller,
    PortType,
    // wifi
    Ssid,
    WifiMode,
    Band,
    Channel,
    Hidden,
    Powersave,
    // security
    KeyMgmt,
    Psk,
    EapMethod,
    Identity,
    AnonIdentity,
    EapPassword,
    Phase2,
    CaCert,
    DomainMatch,
    ClientCert,
    PrivateKey,
    PrivateKeyPassword,
    // ipv4
    V4Method,
    V4Addresses,
    V4Gateway,
    V4Dns,
    V4Search,
    V4Routes,
    V4IgnoreAutoDns,
    V4IgnoreAutoRoutes,
    V4NeverDefault,
    V4Required,
    V4RouteMetric,
    // ipv6
    V6Method,
    V6Addresses,
    V6Gateway,
    V6Dns,
    V6Search,
    V6Routes,
    V6IgnoreAutoDns,
    V6NeverDefault,
    V6Privacy,
    // vlan / bridge / bond
    VlanParent,
    VlanId,
    Stp,
    BridgePriority,
    BondMode,
    BondMiimon,
    // wireguard
    WgPrivateKey,
    WgListenPort,
    PeerPublicKey,
    PeerEndpoint,
    PeerAllowedIps,
    PeerPsk,
    PeerKeepalive,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    Text(String),
    Secret(String),
    Bool(bool),
    /// (stored value, label) options and the selected index.
    Choice(Vec<(&'static str, &'static str)>, usize),
}

impl Value {
    pub fn text(&self) -> &str {
        match self {
            Value::Text(s) | Value::Secret(s) => s,
            _ => "",
        }
    }
    pub fn choice(&self) -> &str {
        match self {
            Value::Choice(o, i) => o.get(*i).map(|x| x.0).unwrap_or(""),
            _ => "",
        }
    }
    pub fn bool(&self) -> bool {
        matches!(self, Value::Bool(true))
    }
}

#[derive(Clone, Debug)]
pub struct Field {
    pub key: Key,
    pub section: &'static str,
    pub label: &'static str,
    pub help: &'static str,
    pub value: Value,
}

#[derive(Clone, Debug)]
pub struct Form {
    /// NM connection.type
    pub kind: String,
    pub fields: Vec<Field>,
    pub base: Settings,
    pub is_new: bool,
}

const MAC_CHOICES: &[(&str, &str)] = &[
    ("", "default"),
    ("permanent", "permanent (hardware)"),
    ("preserve", "keep current"),
    ("stable", "stable random per network"),
    ("random", "new random each time"),
    ("custom", "custom…"),
];
const V4_METHODS: &[(&str, &str)] = &[
    ("auto", "automatic (DHCP)"),
    ("manual", "manual"),
    ("link-local", "link-local only"),
    ("shared", "share with other computers"),
    ("disabled", "disabled"),
];
const V6_METHODS: &[(&str, &str)] = &[
    ("auto", "automatic"),
    ("dhcp", "DHCPv6 only"),
    ("manual", "manual"),
    ("link-local", "link-local only"),
    ("shared", "share with other computers"),
    ("ignore", "ignore (leave to others)"),
    ("disabled", "disabled"),
];
const KEY_MGMT: &[(&str, &str)] = &[
    ("", "none (open)"),
    ("owe", "enhanced open (OWE)"),
    ("wpa-psk", "WPA/WPA2 personal"),
    ("sae", "WPA3 personal"),
    ("wpa-eap", "WPA/WPA2/WPA3 enterprise"),
    ("none", "WEP (insecure)"),
];
const EAP: &[(&str, &str)] = &[("peap", "PEAP"), ("ttls", "TTLS"), ("tls", "TLS (certificate)"), ("pwd", "PWD")];
const PHASE2: &[(&str, &str)] = &[("mschapv2", "MSCHAPv2"), ("pap", "PAP"), ("gtc", "GTC"), ("mschap", "MSCHAP")];
const WIFI_MODE: &[(&str, &str)] = &[("infrastructure", "client"), ("ap", "hotspot (access point)"), ("adhoc", "ad-hoc")];
const BAND: &[(&str, &str)] = &[("", "automatic"), ("bg", "2.4 GHz"), ("a", "5 GHz")];
const POWERSAVE: &[(&str, &str)] = &[("0", "default"), ("2", "off (lower latency)"), ("3", "on (save battery)")];
const PRIVACY: &[(&str, &str)] = &[
    ("-1", "default"),
    ("0", "off"),
    ("1", "on, prefer real address"),
    ("2", "on, prefer temporary address"),
];
const PORT_TYPE: &[(&str, &str)] = &[("", "none"), ("bridge", "bridge port"), ("bond", "bond member")];
const BOND_MODES: &[(&str, &str)] = &[
    ("active-backup", "active-backup (failover)"),
    ("balance-rr", "round-robin"),
    ("802.3ad", "802.3ad (LACP)"),
    ("balance-xor", "balance-xor"),
    ("broadcast", "broadcast"),
    ("balance-tlb", "balance-tlb"),
    ("balance-alb", "balance-alb"),
];

fn choice(opts: &'static [(&'static str, &'static str)], cur: &str) -> Value {
    Value::Choice(opts.to_vec(), opts.iter().position(|o| o.0 == cur).unwrap_or(0))
}

fn get<'a>(s: &'a Settings, setting: &str) -> Option<&'a Dict> {
    s.get(setting)
}

fn gs(s: &Settings, setting: &str, key: &str) -> String {
    get(s, setting).map(|d| d.s(key)).unwrap_or_default()
}

fn gb(s: &Settings, setting: &str, key: &str, default: bool) -> bool {
    get(s, setting).and_then(|d| d.opt_b(key)).unwrap_or(default)
}

fn gi(s: &Settings, setting: &str, key: &str) -> Option<i64> {
    get(s, setting).and_then(|d| d.get(key)).and_then(Val::i64)
}

fn num_text(v: Option<i64>) -> String {
    v.filter(|n| *n != 0).map(|n| n.to_string()).unwrap_or_default()
}

fn ip4_from_u32(n: u32) -> Ipv4Addr {
    Ipv4Addr::from(n.to_le_bytes()) // NM stores IPv4 in network byte order
}

fn ip4_to_u32(a: Ipv4Addr) -> u32 {
    u32::from_le_bytes(a.octets())
}

fn addr_list(s: &Settings, setting: &str) -> String {
    get(s, setting)
        .and_then(|d| d.get("address-data"))
        .map(|v| v.dict_list().iter().map(|a| format!("{}/{}", a.s("address"), a.u("prefix"))).collect::<Vec<_>>().join(", "))
        .unwrap_or_default()
}

fn route_list(s: &Settings, setting: &str) -> String {
    get(s, setting)
        .and_then(|d| d.get("route-data"))
        .map(|v| {
            v.dict_list()
                .iter()
                .map(|r| {
                    let mut t = format!("{}/{}", r.s("dest"), r.u("prefix"));
                    let nh = r.s("next-hop");
                    if !nh.is_empty() {
                        t.push_str(&format!(" via {nh}"));
                    }
                    if r.contains_key("metric") {
                        t.push_str(&format!(" metric {}", r.u("metric")));
                    }
                    t
                })
                .collect::<Vec<_>>()
                .join(", ")
        })
        .unwrap_or_default()
}

fn dns4_list(s: &Settings) -> String {
    match get(s, "ipv4").and_then(|d| d.get("dns")) {
        Some(Val::U32List(v)) => v.iter().map(|n| ip4_from_u32(*n).to_string()).collect::<Vec<_>>().join(", "),
        _ => String::new(),
    }
}

fn dns6_list(s: &Settings) -> String {
    match get(s, "ipv6").and_then(|d| d.get("dns")) {
        Some(Val::BytesList(v)) => v.iter().filter_map(|b| super::model::ip6_from_bytes(b)).collect::<Vec<_>>().join(", "),
        _ => String::new(),
    }
}

fn cert_path(s: &Settings, key: &str) -> String {
    match get(s, "802-1x").and_then(|d| d.get(key)) {
        Some(Val::Bytes(b)) => {
            let t = String::from_utf8_lossy(b).trim_end_matches('\0').to_string();
            t.strip_prefix("file://").map(str::to_string).unwrap_or(t)
        }
        _ => String::new(),
    }
}

fn first_peer(s: &Settings) -> Dict {
    get(s, "wireguard").and_then(|d| d.get("peers")).and_then(|p| p.dict_list().first().cloned()).unwrap_or_default()
}

impl Form {
    /// Fields shown for this connection type, populated from `s`.
    pub fn from_settings(s: &Settings, is_new: bool) -> Self {
        let kind = gs(s, "connection", "type");
        let mut f: Vec<Field> = Vec::new();
        let mut add = |key, section, label, help, value| f.push(Field { key, section, label, help, value });
        use Key::*;
        use Value::*;

        add(Id, "General", "Name", "shown in lists; doesn't affect the network", Text(gs(s, "connection", "id")));
        let dev_setting = if kind == "802-11-wireless" { "802-11-wireless" } else { "802-3-ethernet" };
        let iface_help = "only use this device (empty = any)";
        add(Iface, "General", "Device", iface_help, Text(gs(s, "connection", "interface-name")));
        add(Autoconnect, "General", "Connect automatically", "", Bool(gb(s, "connection", "autoconnect", true)));
        add(Priority, "General", "Priority", "higher wins when several could connect", Text(num_text(gi(s, "connection", "autoconnect-priority"))));
        let perms = get(s, "connection").and_then(|d| d.get("permissions")).map(Val::str_list).unwrap_or_default();
        add(AllUsers, "General", "Available to all users", "", Bool(perms.is_empty()));
        if matches!(kind.as_str(), "802-11-wireless" | "802-3-ethernet") {
            let mac = gs(s, dev_setting, "assigned-mac-address");
            let (sel, custom) = if MAC_CHOICES.iter().any(|c| c.0 == mac) { (mac.clone(), String::new()) } else { ("custom".into(), mac) };
            add(Mac, "General", "MAC address", "random/stable hide your hardware address from networks", choice(MAC_CHOICES, &sel));
            add(MacCustom, "General", "Custom MAC", "aa:bb:cc:dd:ee:ff", Text(custom));
            add(Mtu, "General", "MTU", "empty = automatic", Text(num_text(gi(s, dev_setting, "mtu"))));
        }
        if kind == "802-3-ethernet" {
            let master = { let m = gs(s, "connection", "master"); if m.is_empty() { gs(s, "connection", "controller") } else { m } };
            let st = { let t = gs(s, "connection", "slave-type"); if t.is_empty() { gs(s, "connection", "port-type") } else { t } };
            add(PortType, "General", "Use as", "", choice(PORT_TYPE, &st));
            add(Controller, "General", "Bridge/bond", "interface name of the bridge or bond", Text(master));
        }

        if kind == "802-11-wireless" {
            let ssid = get(s, "802-11-wireless").and_then(|d| d.get("ssid")).and_then(Val::bytes).map(ssid_to_string).unwrap_or_default();
            add(Ssid, "Wi-Fi", "Network name (SSID)", "", Text(ssid));
            add(WifiMode, "Wi-Fi", "Mode", "", choice(WIFI_MODE, &{ let m = gs(s, "802-11-wireless", "mode"); if m.is_empty() { "infrastructure".into() } else { m } }));
            add(Band, "Wi-Fi", "Band", "", choice(BAND, &gs(s, "802-11-wireless", "band")));
            add(Channel, "Wi-Fi", "Channel", "hotspot only; empty = automatic", Text(num_text(gi(s, "802-11-wireless", "channel"))));
            add(Hidden, "Wi-Fi", "Hidden network", "probe for it even when it doesn't broadcast", Bool(gb(s, "802-11-wireless", "hidden", false)));
            add(Powersave, "Wi-Fi", "Power saving", "", choice(POWERSAVE, &gi(s, "802-11-wireless", "powersave").unwrap_or(0).to_string()));

            let km = if s.contains_key("802-11-wireless-security") { gs(s, "802-11-wireless-security", "key-mgmt") } else { String::new() };
            add(KeyMgmt, "Security", "Security", "", choice(KEY_MGMT, &km));
            let psk = { let p = gs(s, "802-11-wireless-security", "psk"); if p.is_empty() { gs(s, "802-11-wireless-security", "wep-key0") } else { p } };
            add(Psk, "Security", "Password", "", Secret(psk));
            let eap = get(s, "802-1x").and_then(|d| d.get("eap")).map(Val::str_list).and_then(|v| v.first().cloned()).unwrap_or_else(|| "peap".into());
            add(EapMethod, "Security", "EAP method", "", choice(EAP, &eap));
            add(Identity, "Security", "Username", "", Text(gs(s, "802-1x", "identity")));
            add(EapPassword, "Security", "Password", "", Secret(gs(s, "802-1x", "password")));
            add(AnonIdentity, "Security", "Anonymous identity", "optional, e.g. anonymous@example.org", Text(gs(s, "802-1x", "anonymous-identity")));
            add(Phase2, "Security", "Inner method", "", choice(PHASE2, &gs(s, "802-1x", "phase2-auth")));
            add(CaCert, "Security", "CA certificate", "path to file; empty = don't verify (unsafe)", Text(cert_path(s, "ca-cert")));
            add(DomainMatch, "Security", "Server domain", "e.g. radius.example.org — protects against fake networks", Text(gs(s, "802-1x", "domain-suffix-match")));
            add(ClientCert, "Security", "Client certificate", "path to file", Text(cert_path(s, "client-cert")));
            add(PrivateKey, "Security", "Private key", "path to file", Text(cert_path(s, "private-key")));
            add(PrivateKeyPassword, "Security", "Key password", "", Secret(gs(s, "802-1x", "private-key-password")));
        }

        if kind == "vlan" {
            add(VlanParent, "VLAN", "Parent device", "e.g. enp3s0", Text(gs(s, "vlan", "parent")));
            add(VlanId, "VLAN", "VLAN id", "1–4094", Text(num_text(gi(s, "vlan", "id"))));
        }
        if kind == "bridge" {
            add(Stp, "Bridge", "Spanning tree (STP)", "", Bool(gb(s, "bridge", "stp", true)));
            add(BridgePriority, "Bridge", "STP priority", "empty = default (32768)", Text(num_text(gi(s, "bridge", "priority"))));
        }
        if kind == "bond" {
            let opts = match get(s, "bond").and_then(|d| d.get("options")) {
                Some(Val::StrMap(m)) => m.clone(),
                _ => BTreeMap::new(),
            };
            add(BondMode, "Bond", "Mode", "", choice(BOND_MODES, opts.get("mode").map(String::as_str).unwrap_or("active-backup")));
            add(BondMiimon, "Bond", "Link check (ms)", "miimon; 100 is typical", Text(opts.get("miimon").cloned().unwrap_or_else(|| "100".into())));
        }
        if kind == "wireguard" {
            add(WgPrivateKey, "WireGuard", "Private key", "base64, from `wg genkey`", Secret(gs(s, "wireguard", "private-key")));
            add(WgListenPort, "WireGuard", "Listen port", "empty = random", Text(num_text(gi(s, "wireguard", "listen-port"))));
            let p = first_peer(s);
            add(PeerPublicKey, "WireGuard peer", "Public key", "", Text(p.s("public-key")));
            add(PeerEndpoint, "WireGuard peer", "Endpoint", "host:port", Text(p.s("endpoint")));
            add(PeerAllowedIps, "WireGuard peer", "Allowed IPs", "0.0.0.0/0, ::/0 = route everything", Text(p.get("allowed-ips").map(Val::str_list).unwrap_or_default().join(", ")));
            add(PeerPsk, "WireGuard peer", "Preshared key", "optional", Secret(p.s("preshared-key")));
            add(PeerKeepalive, "WireGuard peer", "Keepalive (s)", "25 helps behind NAT; empty = off", Text(num_text(p.get("persistent-keepalive").and_then(Val::i64))));
        }

        if !matches!(kind.as_str(), "loopback") {
            let m4 = { let m = gs(s, "ipv4", "method"); if m.is_empty() { (if kind == "wireguard" { "disabled" } else { "auto" }).into() } else { m } };
            add(V4Method, "IPv4", "Method", "", choice(V4_METHODS, &m4));
            add(V4Addresses, "IPv4", "Addresses", "192.168.1.10/24, …", Text(addr_list(s, "ipv4")));
            add(V4Gateway, "IPv4", "Gateway", "", Text(gs(s, "ipv4", "gateway")));
            add(V4Dns, "IPv4", "DNS servers", "comma separated, e.g. 1.1.1.1, 9.9.9.9", Text(dns4_list(s)));
            add(V4Search, "IPv4", "Search domains", "", Text(get(s, "ipv4").and_then(|d| d.get("dns-search")).map(Val::str_list).unwrap_or_default().join(", ")));
            add(V4Routes, "IPv4", "Extra routes", "10.0.0.0/8 via 192.168.1.1 metric 100, …", Text(route_list(s, "ipv4")));
            add(V4IgnoreAutoDns, "IPv4", "Ignore DNS from DHCP", "use only the servers above", Bool(gb(s, "ipv4", "ignore-auto-dns", false)));
            add(V4IgnoreAutoRoutes, "IPv4", "Ignore routes from DHCP", "", Bool(gb(s, "ipv4", "ignore-auto-routes", false)));
            add(V4NeverDefault, "IPv4", "Never use as default route", "only reach this network's own addresses through it", Bool(gb(s, "ipv4", "never-default", false)));
            add(V4Required, "IPv4", "Require IPv4", "fail if no IPv4 address", Bool(!gb(s, "ipv4", "may-fail", true)));
            add(V4RouteMetric, "IPv4", "Route metric", "lower = preferred; empty = default", Text(gi(s, "ipv4", "route-metric").filter(|n| *n >= 0).map(|n| n.to_string()).unwrap_or_default()));

            let m6 = { let m = gs(s, "ipv6", "method"); if m.is_empty() { (if kind == "wireguard" { "disabled" } else { "auto" }).into() } else { m } };
            add(V6Method, "IPv6", "Method", "", choice(V6_METHODS, &m6));
            add(V6Addresses, "IPv6", "Addresses", "fd00::10/64, …", Text(addr_list(s, "ipv6")));
            add(V6Gateway, "IPv6", "Gateway", "", Text(gs(s, "ipv6", "gateway")));
            add(V6Dns, "IPv6", "DNS servers", "", Text(dns6_list(s)));
            add(V6Search, "IPv6", "Search domains", "", Text(get(s, "ipv6").and_then(|d| d.get("dns-search")).map(Val::str_list).unwrap_or_default().join(", ")));
            add(V6Routes, "IPv6", "Extra routes", "", Text(route_list(s, "ipv6")));
            add(V6IgnoreAutoDns, "IPv6", "Ignore automatic DNS", "", Bool(gb(s, "ipv6", "ignore-auto-dns", false)));
            add(V6NeverDefault, "IPv6", "Never use as default route", "", Bool(gb(s, "ipv6", "never-default", false)));
            add(V6Privacy, "IPv6", "Privacy extensions", "temporary addresses make you harder to track", choice(PRIVACY, &gi(s, "ipv6", "ip6-privacy").unwrap_or(-1).to_string()));
        }
        Self { kind, fields: f, base: s.clone(), is_new }
    }

    /// Merge secrets fetched with GetSecrets into the form (only fills empty
    /// secret fields, so nothing the user already typed is overwritten).
    pub fn apply_secrets(&mut self, setting: &str, values: &Dict) {
        let base = self.base.entry(setting.to_string()).or_default();
        for (k, v) in values {
            if k == "peers" {
                // WireGuard peer secrets arrive as a peers list: merge by public key.
                if let (Some(Val::DictList(have)), Val::DictList(got)) = (base.get_mut("peers"), v) {
                    for g in got {
                        if let Some(h) = have.iter_mut().find(|h| h.s("public-key") == g.s("public-key")) {
                            for (gk, gv) in g {
                                h.entry(gk.clone()).or_insert_with(|| gv.clone());
                            }
                        }
                    }
                }
                continue;
            }
            base.insert(k.clone(), v.clone());
        }
        let fill = |fields: &mut Vec<Field>, key: Key, val: String| {
            if let Some(f) = fields.iter_mut().find(|f| f.key == key)
                && let Value::Secret(cur) = &mut f.value
                    && cur.is_empty() && !val.is_empty() {
                        *cur = val;
                    }
        };
        let b = self.base.clone();
        match setting {
            "802-11-wireless-security" => {
                let psk = { let p = gs(&b, setting, "psk"); if p.is_empty() { gs(&b, setting, "wep-key0") } else { p } };
                fill(&mut self.fields, Key::Psk, psk);
            }
            "802-1x" => {
                fill(&mut self.fields, Key::EapPassword, gs(&b, setting, "password"));
                fill(&mut self.fields, Key::PrivateKeyPassword, gs(&b, setting, "private-key-password"));
            }
            "wireguard" => {
                fill(&mut self.fields, Key::WgPrivateKey, gs(&b, setting, "private-key"));
                fill(&mut self.fields, Key::PeerPsk, first_peer(&b).s("preshared-key"));
            }
            _ => {}
        }
    }

    /// Which settings hold secrets for this profile (to fetch before editing).
    pub fn secret_settings(&self) -> Vec<&'static str> {
        let mut v = Vec::new();
        if self.base.contains_key("802-11-wireless-security") {
            v.push("802-11-wireless-security");
        }
        if self.base.contains_key("802-1x") {
            v.push("802-1x");
        }
        if self.base.contains_key("wireguard") {
            v.push("wireguard");
        }
        v
    }

    pub fn get(&self, k: Key) -> Option<&Value> {
        self.fields.iter().find(|f| f.key == k).map(|f| &f.value)
    }

    fn t(&self, k: Key) -> String {
        self.get(k).map(|v| v.text().trim().to_string()).unwrap_or_default()
    }
    fn c(&self, k: Key) -> String {
        self.get(k).map(|v| v.choice().to_string()).unwrap_or_default()
    }
    fn b(&self, k: Key) -> bool {
        self.get(k).is_some_and(Value::bool)
    }

    /// Whether a field should be shown given the other values.
    pub fn visible(&self, k: Key) -> bool {
        use Key::*;
        let km = self.c(KeyMgmt);
        let eap = self.c(EapMethod);
        let manual4 = self.c(V4Method) == "manual";
        let auto4 = self.c(V4Method) == "auto";
        let manual6 = self.c(V6Method) == "manual";
        let auto6 = matches!(self.c(V6Method).as_str(), "auto" | "dhcp");
        let v6_on = !matches!(self.c(V6Method).as_str(), "ignore" | "disabled");
        let v4_on = self.c(V4Method) != "disabled";
        let port = !self.c(PortType).is_empty();
        match k {
            MacCustom => self.c(Mac) == "custom",
            Controller => port,
            Channel => self.c(WifiMode) != "infrastructure",
            Psk => matches!(km.as_str(), "wpa-psk" | "sae" | "none"),
            EapMethod | Identity | DomainMatch | CaCert => km == "wpa-eap",
            EapPassword | AnonIdentity => km == "wpa-eap" && eap != "tls",
            Phase2 => km == "wpa-eap" && matches!(eap.as_str(), "peap" | "ttls"),
            ClientCert | PrivateKey | PrivateKeyPassword => km == "wpa-eap" && eap == "tls",
            V4Method | V6Method => !port,
            V4Addresses | V4Gateway => !port && manual4,
            V4Dns | V4Search | V4Routes | V4RouteMetric | V4NeverDefault | V4Required => !port && v4_on && self.c(V4Method) != "link-local",
            V4IgnoreAutoDns | V4IgnoreAutoRoutes => !port && auto4,
            V6Addresses | V6Gateway => !port && manual6,
            V6Dns | V6Search | V6Routes | V6NeverDefault => !port && v6_on && self.c(V6Method) != "link-local",
            V6IgnoreAutoDns => !port && auto6,
            V6Privacy => !port && v6_on,
            _ => true,
        }
    }

    pub fn visible_fields(&self) -> Vec<usize> {
        (0..self.fields.len()).filter(|&i| self.visible(self.fields[i].key)).collect()
    }

    /// Build NM settings. Errors are (field, message) for inline display.
    pub fn to_settings(&self) -> Result<Settings, Vec<(Key, String)>> {
        use Key::*;
        let mut errs: Vec<(Key, String)> = Vec::new();
        let mut s = self.base.clone();
        let kind = self.kind.clone();
        let set = |s: &mut Settings, setting: &str, key: &str, v: Option<Val>| {
            let d = s.entry(setting.to_string()).or_default();
            match v {
                Some(v) => {
                    d.insert(key.to_string(), v);
                }
                None => {
                    d.remove(key);
                }
            }
        };
        let opt_str = |v: String| if v.is_empty() { None } else { Some(Val::Str(v)) };
        let num = |k: Key, lo: i64, hi: i64, errs: &mut Vec<(Key, String)>| -> Option<i64> {
            let t = self.t(k);
            if t.is_empty() {
                return None;
            }
            match t.parse::<i64>() {
                Ok(n) if (lo..=hi).contains(&n) => Some(n),
                _ => {
                    errs.push((k, format!("must be a number from {lo} to {hi}")));
                    None
                }
            }
        };

        // connection
        let id = self.t(Id);
        if id.is_empty() {
            errs.push((Id, "a name is required".into()));
        }
        set(&mut s, "connection", "id", Some(Val::Str(id)));
        set(&mut s, "connection", "type", Some(Val::Str(kind.clone())));
        if gs(&s, "connection", "uuid").is_empty() {
            set(&mut s, "connection", "uuid", Some(Val::Str(new_uuid())));
        }
        set(&mut s, "connection", "interface-name", opt_str(self.t(Iface)));
        set(&mut s, "connection", "autoconnect", Some(Val::Bool(self.b(Autoconnect))));
        set(&mut s, "connection", "autoconnect-priority", num(Priority, -999, 999, &mut errs).map(|n| Val::I32(n as i32)));
        if self.b(AllUsers) {
            set(&mut s, "connection", "permissions", None);
        } else if get(&s, "connection").and_then(|d| d.get("permissions")).map(Val::str_list).unwrap_or_default().is_empty() {
            let user = std::env::var("USER").unwrap_or_default();
            set(&mut s, "connection", "permissions", Some(Val::StrList(vec![format!("user:{user}:")])));
        }

        let dev_setting = if kind == "802-11-wireless" { "802-11-wireless" } else { "802-3-ethernet" };
        if self.get(Mac).is_some() {
            let mac = match self.c(Mac).as_str() {
                "custom" => {
                    let m = self.t(MacCustom);
                    if parse_mac(&m).is_none() {
                        errs.push((MacCustom, "expected aa:bb:cc:dd:ee:ff".into()));
                    }
                    Some(Val::Str(m))
                }
                "" => None,
                other => Some(Val::Str(other.to_string())),
            };
            set(&mut s, dev_setting, "assigned-mac-address", mac);
            set(&mut s, dev_setting, "cloned-mac-address", None); // legacy key would override
            set(&mut s, dev_setting, "mtu", num(Mtu, 576, 9000, &mut errs).map(|n| Val::U32(n as u32)));
        }
        if self.get(PortType).is_some() {
            for k in ["controller", "port-type"] {
                set(&mut s, "connection", k, None);
            }
            let pt = self.c(PortType);
            if pt.is_empty() {
                set(&mut s, "connection", "master", None);
                set(&mut s, "connection", "slave-type", None);
            } else {
                let c = self.t(Controller);
                if c.is_empty() {
                    errs.push((Controller, "name the bridge or bond, e.g. br0".into()));
                }
                set(&mut s, "connection", "master", Some(Val::Str(c)));
                set(&mut s, "connection", "slave-type", Some(Val::Str(pt)));
                s.remove("ipv4");
                s.remove("ipv6");
            }
        }

        if kind == "802-11-wireless" {
            let ssid = self.get(Ssid).map(|v| v.text().to_string()).unwrap_or_default();
            if ssid.is_empty() || ssid.len() > 32 {
                errs.push((Ssid, "1–32 bytes".into()));
            }
            set(&mut s, "802-11-wireless", "ssid", Some(Val::Bytes(ssid.into_bytes())));
            set(&mut s, "802-11-wireless", "mode", Some(Val::Str(self.c(WifiMode))));
            set(&mut s, "802-11-wireless", "band", opt_str(self.c(Band)));
            let ch = if self.c(WifiMode) == "infrastructure" { None } else { num(Channel, 1, 196, &mut errs) };
            set(&mut s, "802-11-wireless", "channel", ch.map(|n| Val::U32(n as u32)));
            if ch.is_some() && self.c(Band).is_empty() {
                errs.push((Band, "pick a band when setting a channel".into()));
            }
            set(&mut s, "802-11-wireless", "hidden", Some(Val::Bool(self.b(Hidden))));
            set(&mut s, "802-11-wireless", "powersave", Some(Val::U32(self.c(Powersave).parse().unwrap_or(0))));

            let km = self.c(KeyMgmt);
            if km.is_empty() {
                s.remove("802-11-wireless-security");
                s.remove("802-1x");
            } else {
                set(&mut s, "802-11-wireless-security", "key-mgmt", Some(Val::Str(km.clone())));
                let pw = self.get(Psk).map(|v| v.text().to_string()).unwrap_or_default();
                match km.as_str() {
                    "wpa-psk" | "sae" => {
                        if !(8..=63).contains(&pw.len()) && !(pw.len() == 64 && pw.chars().all(|c| c.is_ascii_hexdigit())) {
                            errs.push((Psk, "8–63 characters".into()));
                        }
                        set(&mut s, "802-11-wireless-security", "psk", Some(Val::Str(pw)));
                        set(&mut s, "802-11-wireless-security", "wep-key0", None);
                        s.remove("802-1x");
                    }
                    "none" => {
                        set(&mut s, "802-11-wireless-security", "wep-key0", Some(Val::Str(pw)));
                        set(&mut s, "802-11-wireless-security", "wep-key-type", Some(Val::U32(1)));
                        set(&mut s, "802-11-wireless-security", "psk", None);
                        s.remove("802-1x");
                    }
                    "owe" => {
                        set(&mut s, "802-11-wireless-security", "psk", None);
                        s.remove("802-1x");
                    }
                    "wpa-eap" => {
                        set(&mut s, "802-11-wireless-security", "psk", None);
                        let eap = self.c(EapMethod);
                        set(&mut s, "802-1x", "eap", Some(Val::StrList(vec![eap.clone()])));
                        let ident = self.t(Identity);
                        if ident.is_empty() {
                            errs.push((Identity, "required".into()));
                        }
                        set(&mut s, "802-1x", "identity", Some(Val::Str(ident)));
                        set(&mut s, "802-1x", "domain-suffix-match", opt_str(self.t(DomainMatch)));
                        set(&mut s, "802-1x", "ca-cert", cert_val(&self.t(CaCert)));
                        if eap == "tls" {
                            set(&mut s, "802-1x", "client-cert", cert_val(&self.t(ClientCert)));
                            set(&mut s, "802-1x", "private-key", cert_val(&self.t(PrivateKey)));
                            set(&mut s, "802-1x", "private-key-password", opt_str(self.get(PrivateKeyPassword).map(|v| v.text().to_string()).unwrap_or_default()));
                            set(&mut s, "802-1x", "password", None);
                            set(&mut s, "802-1x", "phase2-auth", None);
                        } else {
                            set(&mut s, "802-1x", "password", opt_str(self.get(EapPassword).map(|v| v.text().to_string()).unwrap_or_default()));
                            set(&mut s, "802-1x", "anonymous-identity", opt_str(self.t(AnonIdentity)));
                            let p2 = if matches!(eap.as_str(), "peap" | "ttls") { opt_str(self.c(Phase2)) } else { None };
                            set(&mut s, "802-1x", "phase2-auth", p2);
                        }
                    }
                    _ => {}
                }
            }
        }

        if kind == "vlan" {
            let parent = self.t(VlanParent);
            if parent.is_empty() {
                errs.push((VlanParent, "required".into()));
            }
            set(&mut s, "vlan", "parent", Some(Val::Str(parent)));
            match num(VlanId, 1, 4094, &mut errs) {
                Some(n) => set(&mut s, "vlan", "id", Some(Val::U32(n as u32))),
                None if self.t(VlanId).is_empty() => errs.push((VlanId, "required".into())),
                None => {}
            }
        }
        if kind == "bridge" {
            set(&mut s, "bridge", "stp", Some(Val::Bool(self.b(Stp))));
            set(&mut s, "bridge", "priority", num(BridgePriority, 0, 65535, &mut errs).map(|n| Val::U32(n as u32)));
        }
        if kind == "bond" {
            let mut opts = match get(&s, "bond").and_then(|d| d.get("options")) {
                Some(Val::StrMap(m)) => m.clone(),
                _ => BTreeMap::new(),
            };
            opts.insert("mode".into(), self.c(BondMode));
            match num(BondMiimon, 0, 100_000, &mut errs) {
                Some(n) => opts.insert("miimon".into(), n.to_string()),
                None => opts.remove("miimon"),
            };
            set(&mut s, "bond", "options", Some(Val::StrMap(opts)));
        }
        if kind == "wireguard" {
            let pk = self.get(WgPrivateKey).map(|v| v.text().trim().to_string()).unwrap_or_default();
            if !is_wg_key(&pk) {
                errs.push((WgPrivateKey, "expected a 44-character base64 key".into()));
            }
            set(&mut s, "wireguard", "private-key", Some(Val::Str(pk)));
            set(&mut s, "wireguard", "listen-port", num(WgListenPort, 1, 65535, &mut errs).map(|n| Val::U32(n as u32)));
            let mut peers: Vec<Dict> = get(&s, "wireguard").and_then(|d| d.get("peers")).map(|p| p.dict_list().to_vec()).unwrap_or_default();
            let mut p = peers.first().cloned().unwrap_or_default();
            let pubk = self.t(PeerPublicKey);
            if !is_wg_key(&pubk) {
                errs.push((PeerPublicKey, "expected a 44-character base64 key".into()));
            }
            p.insert("public-key".into(), Val::Str(pubk));
            let ep = self.t(PeerEndpoint);
            if !ep.is_empty() && !ep.contains(':') {
                errs.push((PeerEndpoint, "expected host:port".into()));
            }
            opt_set(&mut p, "endpoint", opt_str(ep));
            let allowed = split_list(&self.t(PeerAllowedIps));
            for a in &allowed {
                if parse_cidr(a).is_none() {
                    errs.push((PeerAllowedIps, format!("“{a}” isn't an address/prefix")));
                }
            }
            p.insert("allowed-ips".into(), Val::StrList(allowed));
            opt_set(&mut p, "preshared-key", opt_str(self.get(PeerPsk).map(|v| v.text().trim().to_string()).unwrap_or_default()));
            opt_set(&mut p, "persistent-keepalive", num(PeerKeepalive, 1, 65535, &mut errs).map(|n| Val::U32(n as u32)));
            if peers.is_empty() {
                peers.push(p);
            } else {
                peers[0] = p;
            }
            set(&mut s, "wireguard", "peers", Some(Val::DictList(peers)));
        }

        if self.get(V4Method).is_some() && self.c(PortType).is_empty() {
            self.ip_to_settings(&mut s, false, &mut errs);
            self.ip_to_settings(&mut s, true, &mut errs);
        }

        if errs.is_empty() {
            Ok(s)
        } else {
            Err(errs)
        }
    }

    fn ip_to_settings(&self, s: &mut Settings, v6: bool, errs: &mut Vec<(Key, String)>) {
        use Key::*;
        let (setting, km, ka, kg, kd, ks, kr) = if v6 {
            ("ipv6", V6Method, V6Addresses, V6Gateway, V6Dns, V6Search, V6Routes)
        } else {
            ("ipv4", V4Method, V4Addresses, V4Gateway, V4Dns, V4Search, V4Routes)
        };
        let method = self.c(km);
        let d = s.entry(setting.to_string()).or_default();
        // Legacy keys override the modern ones if sent, so always drop them.
        for k in ["addresses", "routes", "dns-data"] {
            d.remove(k);
        }
        d.insert("method".into(), Val::Str(method.clone()));

        let mut addrs = Vec::new();
        for a in split_list(&self.t(ka)) {
            match parse_cidr(&a) {
                Some((ip, prefix)) if ip.is_ipv6() == v6 => {
                    let mut m = Dict::new();
                    m.insert("address".into(), Val::Str(ip.to_string()));
                    m.insert("prefix".into(), Val::U32(prefix));
                    addrs.push(m);
                }
                _ => errs.push((ka, format!("“{a}” should look like {}", if v6 { "fd00::2/64" } else { "192.168.1.10/24" }))),
            }
        }
        if method == "manual" && addrs.is_empty() && errs.iter().all(|e| e.0 != ka) {
            errs.push((ka, "manual needs at least one address".into()));
        }
        if method == "manual" {
            d.insert("address-data".into(), Val::DictList(addrs));
            let gw = self.t(kg);
            if gw.is_empty() {
                d.remove("gateway");
            } else if gw.parse::<std::net::IpAddr>().map(|ip| ip.is_ipv6() == v6).unwrap_or(false) {
                d.insert("gateway".into(), Val::Str(gw));
            } else {
                errs.push((kg, "not a valid address".into()));
            }
        } else {
            d.remove("address-data");
            d.remove("gateway");
        }

        let dns = split_list(&self.t(kd));
        if v6 {
            let mut list = Vec::new();
            for x in &dns {
                match x.parse::<Ipv6Addr>() {
                    Ok(ip) => list.push(ip.octets().to_vec()),
                    Err(_) => errs.push((kd, format!("“{x}” isn't an IPv6 address"))),
                }
            }
            opt_set(d, "dns", if list.is_empty() { None } else { Some(Val::BytesList(list)) });
        } else {
            let mut list = Vec::new();
            for x in &dns {
                match x.parse::<Ipv4Addr>() {
                    Ok(ip) => list.push(ip4_to_u32(ip)),
                    Err(_) => errs.push((kd, format!("“{x}” isn't an IPv4 address"))),
                }
            }
            opt_set(d, "dns", if list.is_empty() { None } else { Some(Val::U32List(list)) });
        }
        let search = split_list(&self.t(ks));
        opt_set(d, "dns-search", if search.is_empty() { None } else { Some(Val::StrList(search)) });

        let mut routes = Vec::new();
        for r in split_list(&self.t(kr)) {
            match parse_route(&r, v6) {
                Some(m) => routes.push(m),
                None => errs.push((kr, format!("“{r}”: use dest/prefix [via gateway] [metric N]"))),
            }
        }
        opt_set(d, "route-data", if routes.is_empty() { None } else { Some(Val::DictList(routes)) });

        if v6 {
            d.insert("ignore-auto-dns".into(), Val::Bool(self.b(V6IgnoreAutoDns)));
            d.insert("never-default".into(), Val::Bool(self.b(V6NeverDefault)));
            d.insert("ip6-privacy".into(), Val::I32(self.c(V6Privacy).parse().unwrap_or(-1)));
        } else {
            d.insert("ignore-auto-dns".into(), Val::Bool(self.b(V4IgnoreAutoDns)));
            d.insert("ignore-auto-routes".into(), Val::Bool(self.b(V4IgnoreAutoRoutes)));
            d.insert("never-default".into(), Val::Bool(self.b(V4NeverDefault)));
            d.insert("may-fail".into(), Val::Bool(!self.b(V4Required)));
            let t = self.t(V4RouteMetric);
            if t.is_empty() {
                d.insert("route-metric".into(), Val::I64(-1));
            } else {
                match t.parse::<u32>() {
                    Ok(n) => {
                        d.insert("route-metric".into(), Val::I64(n as i64));
                    }
                    Err(_) => errs.push((V4RouteMetric, "must be a number".into())),
                }
            }
        }
    }
}

fn opt_set(d: &mut Dict, k: &str, v: Option<Val>) {
    match v {
        Some(v) => {
            d.insert(k.to_string(), v);
        }
        None => {
            d.remove(k);
        }
    }
}

pub fn split_list(s: &str) -> Vec<String> {
    s.split([',', ';', '\n']).map(str::trim).filter(|x| !x.is_empty()).map(str::to_string).collect()
}

pub fn parse_cidr(s: &str) -> Option<(std::net::IpAddr, u32)> {
    let (ip, prefix) = match s.split_once('/') {
        Some((ip, p)) => (ip.trim().parse::<std::net::IpAddr>().ok()?, p.trim().parse::<u32>().ok()?),
        None => {
            let ip: std::net::IpAddr = s.trim().parse().ok()?;
            (ip, if ip.is_ipv6() { 128 } else { 32 })
        }
    };
    let max = if ip.is_ipv6() { 128 } else { 32 };
    (prefix <= max).then_some((ip, prefix))
}

fn parse_route(s: &str, v6: bool) -> Option<Dict> {
    let mut parts = s.split_whitespace();
    let (dest, prefix) = parse_cidr(parts.next()?)?;
    if dest.is_ipv6() != v6 {
        return None;
    }
    let mut m = Dict::new();
    m.insert("dest".into(), Val::Str(dest.to_string()));
    m.insert("prefix".into(), Val::U32(prefix));
    while let Some(word) = parts.next() {
        match word {
            "via" => {
                let nh: std::net::IpAddr = parts.next()?.parse().ok()?;
                if nh.is_ipv6() != v6 {
                    return None;
                }
                m.insert("next-hop".into(), Val::Str(nh.to_string()));
            }
            "metric" => {
                m.insert("metric".into(), Val::U32(parts.next()?.parse().ok()?));
            }
            _ => return None,
        }
    }
    Some(m)
}

pub fn parse_mac(s: &str) -> Option<[u8; 6]> {
    let parts: Vec<&str> = s.split([':', '-']).collect();
    if parts.len() != 6 {
        return None;
    }
    let mut out = [0u8; 6];
    for (i, p) in parts.iter().enumerate() {
        if p.len() != 2 {
            return None;
        }
        out[i] = u8::from_str_radix(p, 16).ok()?;
    }
    Some(out)
}

fn is_wg_key(k: &str) -> bool {
    k.len() == 44 && k.ends_with('=') && k[..43].chars().all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/')
}

fn cert_val(path: &str) -> Option<Val> {
    if path.is_empty() {
        return None;
    }
    let mut b = format!("file://{path}").into_bytes();
    b.push(0);
    Some(Val::Bytes(b))
}

/// Random UUID v4 for new profiles.
pub fn new_uuid() -> String {
    let mut b = [0u8; 16];
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        use std::io::Read;
        let _ = f.read_exact(&mut b);
    } else {
        let t = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
        b = t.to_le_bytes();
    }
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h: String = b.iter().map(|x| format!("{x:02x}")).collect();
    format!("{}-{}-{}-{}-{}", &h[0..8], &h[8..12], &h[12..16], &h[16..20], &h[20..32])
}

/// Skeleton settings for a brand-new profile of `kind`.
pub fn new_settings(kind: &str, name: &str) -> Settings {
    let mut s = Settings::new();
    let mut c = Dict::new();
    c.insert("id".into(), Val::Str(name.to_string()));
    c.insert("type".into(), Val::Str(kind.to_string()));
    c.insert("uuid".into(), Val::Str(new_uuid()));
    c.insert("autoconnect".into(), Val::Bool(kind != "wireguard"));
    s.insert("connection".into(), c);
    match kind {
        "802-11-wireless" => {
            let mut w = Dict::new();
            w.insert("mode".into(), Val::Str("infrastructure".into()));
            s.insert("802-11-wireless".into(), w);
        }
        "802-3-ethernet" => {
            s.insert("802-3-ethernet".into(), Dict::new());
        }
        "bond" => {
            let mut b = Dict::new();
            b.insert("options".into(), Val::StrMap(BTreeMap::from([("mode".into(), "active-backup".into()), ("miimon".into(), "100".into())])));
            s.insert("bond".into(), b);
            s.get_mut("connection").expect("set above").insert("interface-name".into(), Val::Str("bond0".into()));
        }
        "bridge" => {
            s.insert("bridge".into(), Dict::new());
            s.get_mut("connection").expect("set above").insert("interface-name".into(), Val::Str("br0".into()));
        }
        "vlan" => {
            s.insert("vlan".into(), Dict::new());
        }
        "wireguard" => {
            s.insert("wireguard".into(), Dict::new());
            s.get_mut("connection").expect("set above").insert("interface-name".into(), Val::Str("wg0".into()));
            let mut v4 = Dict::new();
            v4.insert("method".into(), Val::Str("manual".into()));
            s.insert("ipv4".into(), v4);
            let mut v6 = Dict::new();
            v6.insert("method".into(), Val::Str("disabled".into()));
            s.insert("ipv6".into(), v6);
        }
        _ => {}
    }
    s
}

/// Settings for a Wi-Fi hotspot (access point mode, shared IPv4).
pub fn hotspot_settings(ssid: &str, password: &str, band: &str, iface: &str) -> Settings {
    let mut s = new_settings("802-11-wireless", "Hotspot");
    s.get_mut("connection").expect("set").insert("autoconnect".into(), Val::Bool(false));
    if !iface.is_empty() {
        s.get_mut("connection").expect("set").insert("interface-name".into(), Val::Str(iface.into()));
    }
    let w = s.get_mut("802-11-wireless").expect("set");
    w.insert("ssid".into(), Val::Bytes(ssid.as_bytes().to_vec()));
    w.insert("mode".into(), Val::Str("ap".into()));
    if !band.is_empty() {
        w.insert("band".into(), Val::Str(band.into()));
    }
    let mut sec = Dict::new();
    sec.insert("key-mgmt".into(), Val::Str("wpa-psk".into()));
    sec.insert("psk".into(), Val::Str(password.into()));
    // WPA2-only (CCMP): the most compatible secure hotspot setting.
    sec.insert("proto".into(), Val::StrList(vec!["rsn".into()]));
    sec.insert("pairwise".into(), Val::StrList(vec!["ccmp".into()]));
    sec.insert("group".into(), Val::StrList(vec!["ccmp".into()]));
    s.insert("802-11-wireless-security".into(), sec);
    let mut v4 = Dict::new();
    v4.insert("method".into(), Val::Str("shared".into()));
    s.insert("ipv4".into(), v4);
    let mut v6 = Dict::new();
    v6.insert("method".into(), Val::Str("ignore".into()));
    s.insert("ipv6".into(), v6);
    s
}

/// Settings to join a Wi-Fi network for the first time.
pub fn wifi_join_settings(ssid: &str, key_mgmt: Option<&str>, password: &str, hidden: bool) -> Settings {
    let mut s = new_settings("802-11-wireless", ssid);
    let w = s.get_mut("802-11-wireless").expect("set");
    w.insert("ssid".into(), Val::Bytes(ssid.as_bytes().to_vec()));
    if hidden {
        w.insert("hidden".into(), Val::Bool(true));
    }
    if let Some(km) = key_mgmt {
        let mut sec = Dict::new();
        sec.insert("key-mgmt".into(), Val::Str(km.into()));
        match km {
            "wpa-psk" | "sae" => {
                sec.insert("psk".into(), Val::Str(password.into()));
            }
            "none" => {
                sec.insert("wep-key0".into(), Val::Str(password.into()));
                sec.insert("wep-key-type".into(), Val::U32(1));
            }
            _ => {}
        }
        s.insert("802-11-wireless-security".into(), sec);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(form: &mut Form, k: Key, v: Value) {
        form.fields.iter_mut().find(|f| f.key == k).unwrap().value = v;
    }

    fn pick(form: &mut Form, k: Key, val: &str) {
        let f = form.fields.iter_mut().find(|f| f.key == k).unwrap();
        if let Value::Choice(opts, i) = &mut f.value {
            *i = opts.iter().position(|o| o.0 == val).unwrap();
        }
    }

    fn existing_wifi() -> Settings {
        let mut s = wifi_join_settings("Home", Some("wpa-psk"), "hunter22", false);
        // Something set by another tool that we don't model:
        s.get_mut("802-11-wireless").unwrap().insert("seen-bssids".into(), Val::StrList(vec!["aa".into()]));
        let mut v4 = Dict::new();
        v4.insert("method".into(), Val::Str("auto".into()));
        v4.insert("addresses".into(), Val::Other("legacy".into()));
        v4.insert("dns".into(), Val::U32List(vec![ip4_to_u32("1.1.1.1".parse().unwrap())]));
        s.insert("ipv4".into(), v4);
        s
    }

    #[test]
    fn round_trip_keeps_unknown_keys() {
        let s = existing_wifi();
        let form = Form::from_settings(&s, false);
        assert_eq!(form.get(Key::Ssid).unwrap().text(), "Home");
        assert_eq!(form.get(Key::Psk).unwrap().text(), "hunter22");
        assert_eq!(form.get(Key::V4Dns).unwrap().text(), "1.1.1.1");
        let out = form.to_settings().unwrap();
        assert!(out["802-11-wireless"].contains_key("seen-bssids"));
        assert!(!out["ipv4"].contains_key("addresses"), "legacy key must be dropped");
        assert_eq!(out["ipv4"]["dns"], Val::U32List(vec![ip4_to_u32("1.1.1.1".parse().unwrap())]));
    }

    #[test]
    fn static_ipv4_and_routes() {
        let mut form = Form::from_settings(&existing_wifi(), false);
        pick(&mut form, Key::V4Method, "manual");
        assert!(form.visible(Key::V4Addresses));
        assert!(!form.visible(Key::V4IgnoreAutoDns));
        set(&mut form, Key::V4Addresses, Value::Text("192.168.1.50/24".into()));
        set(&mut form, Key::V4Gateway, Value::Text("192.168.1.1".into()));
        set(&mut form, Key::V4Routes, Value::Text("10.0.0.0/8 via 192.168.1.254 metric 50".into()));
        let out = form.to_settings().unwrap();
        let ip = &out["ipv4"];
        assert_eq!(ip["method"], Val::Str("manual".into()));
        let a = &ip["address-data"].dict_list()[0];
        assert_eq!(a.s("address"), "192.168.1.50");
        assert_eq!(a.u("prefix"), 24);
        let r = &ip["route-data"].dict_list()[0];
        assert_eq!(r.s("next-hop"), "192.168.1.254");
        assert_eq!(r.u("metric"), 50);
    }

    #[test]
    fn validation_errors_point_at_fields() {
        let mut form = Form::from_settings(&existing_wifi(), false);
        pick(&mut form, Key::V4Method, "manual");
        set(&mut form, Key::V4Addresses, Value::Text("300.1.1.1/24".into()));
        set(&mut form, Key::V4Dns, Value::Text("not-an-ip".into()));
        set(&mut form, Key::Psk, Value::Secret("short".into()));
        let errs = form.to_settings().unwrap_err();
        let keys: Vec<Key> = errs.iter().map(|e| e.0).collect();
        assert!(keys.contains(&Key::V4Addresses));
        assert!(keys.contains(&Key::V4Dns));
        assert!(keys.contains(&Key::Psk));
    }

    #[test]
    fn switching_to_open_drops_security() {
        let mut form = Form::from_settings(&existing_wifi(), false);
        pick(&mut form, Key::KeyMgmt, "");
        assert!(!form.visible(Key::Psk));
        let out = form.to_settings().unwrap();
        assert!(!out.contains_key("802-11-wireless-security"));
    }

    #[test]
    fn mac_randomization() {
        let mut form = Form::from_settings(&existing_wifi(), false);
        pick(&mut form, Key::Mac, "stable");
        let out = form.to_settings().unwrap();
        assert_eq!(out["802-11-wireless"]["assigned-mac-address"], Val::Str("stable".into()));
        pick(&mut form, Key::Mac, "custom");
        set(&mut form, Key::MacCustom, Value::Text("zz:00".into()));
        assert!(form.to_settings().is_err());
    }

    #[test]
    fn wireguard_profile() {
        let s = new_settings("wireguard", "Office");
        let mut form = Form::from_settings(&s, true);
        assert_eq!(form.get(Key::V4Method).unwrap().choice(), "manual");
        set(&mut form, Key::WgPrivateKey, Value::Secret("yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=".into()));
        set(&mut form, Key::PeerPublicKey, Value::Text("xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=".into()));
        set(&mut form, Key::PeerEndpoint, Value::Text("vpn.example.org:51820".into()));
        set(&mut form, Key::PeerAllowedIps, Value::Text("10.8.0.0/24, ::/0".into()));
        set(&mut form, Key::V4Addresses, Value::Text("10.8.0.2/24".into()));
        set(&mut form, Key::PeerKeepalive, Value::Text("25".into()));
        let out = form.to_settings().unwrap();
        let peer = &out["wireguard"]["peers"].dict_list()[0];
        assert_eq!(peer.s("endpoint"), "vpn.example.org:51820");
        assert_eq!(peer.u("persistent-keepalive"), 25);
        assert_eq!(peer["allowed-ips"], Val::StrList(vec!["10.8.0.0/24".into(), "::/0".into()]));
    }

    #[test]
    fn secrets_fill_empty_fields_only() {
        let mut s = existing_wifi();
        s.get_mut("802-11-wireless-security").unwrap().remove("psk"); // GetSettings omits secrets
        let mut form = Form::from_settings(&s, false);
        assert_eq!(form.get(Key::Psk).unwrap().text(), "");
        let mut sec = Dict::new();
        sec.insert("psk".into(), Val::Str("from-nm-123".into()));
        form.apply_secrets("802-11-wireless-security", &sec);
        assert_eq!(form.get(Key::Psk).unwrap().text(), "from-nm-123");
        sec.insert("psk".into(), Val::Str("other".into()));
        form.apply_secrets("802-11-wireless-security", &sec);
        assert_eq!(form.get(Key::Psk).unwrap().text(), "from-nm-123");
    }

    #[test]
    fn helpers() {
        assert_eq!(parse_mac("AA:bb:01:02:03:04"), Some([0xaa, 0xbb, 1, 2, 3, 4]));
        assert!(parse_cidr("fd00::1/64").is_some());
        assert!(parse_cidr("10.0.0.1/33").is_none());
        assert_eq!(split_list(" a, b ;c,,"), vec!["a", "b", "c"]);
        let u = new_uuid();
        assert_eq!(u.len(), 36);
        assert_eq!(&u[14..15], "4");
        assert_eq!(ip4_from_u32(ip4_to_u32("192.168.1.2".parse().unwrap())).to_string(), "192.168.1.2");
    }

    #[test]
    fn port_profile_drops_ip() {
        let s = new_settings("802-3-ethernet", "eth port");
        let mut form = Form::from_settings(&s, true);
        pick(&mut form, Key::PortType, "bridge");
        assert!(!form.visible(Key::V4Method));
        assert!(form.to_settings().is_err(), "controller required");
        set(&mut form, Key::Controller, Value::Text("br0".into()));
        let out = form.to_settings().unwrap();
        assert_eq!(out["connection"]["slave-type"], Val::Str("bridge".into()));
        assert!(!out.contains_key("ipv4"));
    }
}
