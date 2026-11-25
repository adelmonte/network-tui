//! Demo backend: fake NetworkManager objects run through the *real* parser
//! (`model::parse`), so the demo exercises the same code paths as the real
//! thing. Includes deliberate failures and a password prompt to show off
//! error handling. Run with `--demo`.

use std::collections::BTreeMap;
use std::time::Duration;

use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
use tokio::time::sleep;

use super::form;
use super::model::{self, NM, NM_PATH};
use super::val::{Dict, DictExt, Objects, Settings, Val};
use super::{Cmd, Ev, Handle, SecretRequest};

const IF_DEVICE: &str = "org.freedesktop.NetworkManager.Device";
const IF_WIRELESS: &str = "org.freedesktop.NetworkManager.Device.Wireless";
const IF_WIRED: &str = "org.freedesktop.NetworkManager.Device.Wired";
const IF_AP: &str = "org.freedesktop.NetworkManager.AccessPoint";
const IF_ACTIVE: &str = "org.freedesktop.NetworkManager.Connection.Active";
const IF_IP4: &str = "org.freedesktop.NetworkManager.IP4Config";
const IF_IP6: &str = "org.freedesktop.NetworkManager.IP6Config";
const IF_SETTINGS: &str = "org.freedesktop.NetworkManager.Settings";

const WLAN: &str = "/org/freedesktop/NetworkManager/Devices/3";
const ETH: &str = "/org/freedesktop/NetworkManager/Devices/2";
const DOCKER: &str = "/org/freedesktop/NetworkManager/Devices/4";
const WG: &str = "/org/freedesktop/NetworkManager/Devices/9";

fn d(pairs: Vec<(&str, Val)>) -> Dict {
    pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect()
}
fn s(v: &str) -> Val {
    Val::Str(v.into())
}
fn p(v: &str) -> Val {
    Val::Path(v.into())
}

fn ap_obj(ssid: &str, strength: u8, freq: u32, rsn: u32, bssid: &str) -> BTreeMap<String, Dict> {
    let flags = if rsn == 0 { 0 } else { 1 };
    BTreeMap::from([(
        IF_AP.to_string(),
        d(vec![
            ("Ssid", Val::Bytes(ssid.as_bytes().to_vec())),
            ("Strength", Val::U8(strength)),
            ("Frequency", Val::U32(freq)),
            ("Flags", Val::U32(flags)),
            ("WpaFlags", Val::U32(0)),
            ("RsnFlags", Val::U32(rsn)),
            ("HwAddress", s(bssid)),
            ("MaxBitrate", Val::U32(if freq > 5000 { 866_000 } else { 144_000 })),
            ("Mode", Val::U32(2)),
        ]),
    )])
}

fn ip4(addr: &str, prefix: u32, gw: &str, dns: &[&str]) -> BTreeMap<String, Dict> {
    BTreeMap::from([(
        IF_IP4.to_string(),
        d(vec![
            ("AddressData", Val::DictList(vec![d(vec![("address", s(addr)), ("prefix", Val::U32(prefix))])])),
            ("Gateway", s(gw)),
            ("NameserverData", Val::DictList(dns.iter().map(|x| d(vec![("address", s(x))])).collect())),
            ("Domains", Val::StrList(vec!["lan".into()])),
        ]),
    )])
}

fn ip6(addr: &str) -> BTreeMap<String, Dict> {
    BTreeMap::from([(
        IF_IP6.to_string(),
        d(vec![
            ("AddressData", Val::DictList(vec![d(vec![("address", s(addr)), ("prefix", Val::U32(64))])])),
            ("Gateway", s("fe80::1")),
            ("Nameservers", Val::BytesList(vec![])),
        ]),
    )])
}

fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

fn wifi_profile(id: &str, ssid: &str, km: Option<&str>, pw: &str, ts: i64, prio: i32) -> Settings {
    let mut st = form::wifi_join_settings(ssid, km, pw, false);
    let c = st.get_mut("connection").expect("connection");
    c.insert("id".into(), s(id));
    c.insert("timestamp".into(), Val::U64(ts as u64));
    c.insert("autoconnect-priority".into(), Val::I32(prio));
    st.insert("ipv4".into(), d(vec![("method", s("auto"))]));
    st.insert("ipv6".into(), d(vec![("method", s("auto")), ("ip6-privacy", Val::I32(2))]));
    st.get_mut("802-11-wireless").expect("wifi").insert("assigned-mac-address".into(), s("stable"));
    st
}

struct Demo {
    ev: UnboundedSender<Ev>,
    objs: Objects,
    settings: BTreeMap<String, Settings>,
    next_id: u32,
    tick: u32,
    pending_secret: Option<(u64, String)>,
}

enum Later {
    WifiUp { ap: String, profile: String },
    WifiFail { reason: u32, label: String },
    EthUp,
    VpnUp(String),
    Rescan,
}

pub fn spawn() -> Handle {
    let (tx, cmd_rx) = unbounded_channel();
    let (ev_tx, rx) = unbounded_channel();
    tokio::spawn(run(cmd_rx, ev_tx));
    Handle { tx, rx }
}

async fn run(mut cmds: UnboundedReceiver<Cmd>, ev: UnboundedSender<Ev>) {
    let mut demo = Demo::new(ev);
    let (ltx, mut lrx) = unbounded_channel::<Later>();
    sleep(Duration::from_millis(120)).await;
    demo.publish();
    let mut t = tokio::time::interval(Duration::from_secs(4));
    loop {
        tokio::select! {
            c = cmds.recv() => match c { Some(c) => demo.command(c, &ltx), None => break },
            Some(l) = lrx.recv() => demo.later(l),
            _ = t.tick() => demo.drift(),
        }
    }
}

impl Demo {
    fn new(ev: UnboundedSender<Ev>) -> Self {
        let mut objs = Objects::new();
        objs.insert(
            NM_PATH.into(),
            BTreeMap::from([(
                NM.to_string(),
                d(vec![
                    ("Version", s("1.52.0")),
                    ("NetworkingEnabled", Val::Bool(true)),
                    ("WirelessEnabled", Val::Bool(true)),
                    ("WirelessHardwareEnabled", Val::Bool(true)),
                    ("WwanEnabled", Val::Bool(false)),
                    ("WwanHardwareEnabled", Val::Bool(false)),
                    ("Connectivity", Val::U32(4)),
                    ("ConnectivityCheckEnabled", Val::Bool(true)),
                    ("State", Val::U32(70)),
                ]),
            )]),
        );
        objs.insert("/org/freedesktop/NetworkManager/Settings".into(), BTreeMap::from([(IF_SETTINGS.to_string(), d(vec![("Hostname", s("archbox"))]))]));

        let aps = [
            ("Home-5G", 84, 5180, 0x588, "A4:2B:B0:11:22:31"),
            ("Home-5G", 61, 2437, 0x588, "A4:2B:B0:11:22:30"),
            ("Home-IoT", 58, 2412, 0x188, "A4:2B:B0:11:22:32"),
            ("Pixel 8", 71, 5745, 0x188, "F2:5C:77:A1:09:6D"),
            ("Neighbor's Wi-Fi", 39, 2462, 0x188, "10:13:31:AB:CD:01"),
            ("ACME-Corp", 47, 5500, 0x288, "00:3A:98:00:00:10"),
            ("CoffeeShop Free", 33, 2437, 0, "6C:F3:7F:41:00:02"),
            ("DIRECT-roku-112", 30, 2412, 0x188, "AE:3A:7A:01:02:03"),
            ("Library", 24, 5200, 0x488, "00:11:74:20:30:40"),
            ("", 52, 2462, 0x188, "C8:3A:35:00:00:99"),
        ];
        let mut ap_paths = Vec::new();
        for (i, (ssid, st, f, rsn, bssid)) in aps.iter().enumerate() {
            let path = format!("/org/freedesktop/NetworkManager/AccessPoint/{}", i + 1);
            objs.insert(path.clone(), ap_obj(ssid, *st, *f, *rsn, bssid));
            ap_paths.push(path);
        }

        let mut settings = BTreeMap::new();
        let home = "/org/freedesktop/NetworkManager/Settings/1";
        settings.insert(home.to_string(), wifi_profile("Home-5G", "Home-5G", Some("wpa-psk"), "correct horse battery", now() - 600, 10));
        settings.insert("/org/freedesktop/NetworkManager/Settings/2".to_string(), wifi_profile("Pixel 8 hotspot", "Pixel 8", Some("wpa-psk"), "outdated-pass", now() - 3 * 86_400, 0));
        settings.insert("/org/freedesktop/NetworkManager/Settings/3".to_string(), wifi_profile("Cabin", "LakeCabin", Some("wpa-psk"), "fishing2024", now() - 140 * 86_400, 0));
        let mut wired = form::new_settings("802-3-ethernet", "Wired connection 1");
        wired.get_mut("connection").expect("c").insert("timestamp".into(), Val::U64((now() - 30) as u64));
        wired.insert("ipv4".into(), d(vec![("method", s("auto"))]));
        wired.insert("ipv6".into(), d(vec![("method", s("auto"))]));
        settings.insert("/org/freedesktop/NetworkManager/Settings/4".to_string(), wired);
        let mut wg = form::new_settings("wireguard", "Office VPN");
        wg.get_mut("wireguard").expect("wg").insert("private-key".into(), s("yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk="));
        wg.get_mut("wireguard").expect("wg").insert(
            "peers".into(),
            Val::DictList(vec![d(vec![
                ("public-key", s("xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=")),
                ("endpoint", s("vpn.example.org:51820")),
                ("allowed-ips", Val::StrList(vec!["10.20.0.0/16".into()])),
                ("persistent-keepalive", Val::U32(25)),
            ])]),
        );
        wg.get_mut("ipv4").expect("v4").insert("address-data".into(), Val::DictList(vec![d(vec![("address", s("10.20.0.7")), ("prefix", Val::U32(16))])]));
        settings.insert("/org/freedesktop/NetworkManager/Settings/5".to_string(), wg);

        // Devices
        objs.insert(
            ETH.into(),
            BTreeMap::from([
                (
                    IF_DEVICE.to_string(),
                    d(vec![
                        ("Interface", s("enp3s0")),
                        ("DeviceType", Val::U32(1)),
                        ("State", Val::U32(100)),
                        ("StateReason", Val::U32List(vec![100, 0])),
                        ("Managed", Val::Bool(true)),
                        ("Autoconnect", Val::Bool(true)),
                        ("Driver", s("r8169")),
                        ("HwAddress", s("D8:BB:C1:5A:77:02")),
                        ("Mtu", Val::U32(1500)),
                        ("ActiveConnection", p("/org/freedesktop/NetworkManager/ActiveConnection/1")),
                        ("Ip4Config", p("/org/freedesktop/NetworkManager/IP4Config/1")),
                        ("Ip6Config", p("/org/freedesktop/NetworkManager/IP6Config/1")),
                    ]),
                ),
                (IF_WIRED.to_string(), d(vec![("Speed", Val::U32(1000)), ("Carrier", Val::Bool(true)), ("PermHwAddress", s("D8:BB:C1:5A:77:02"))])),
            ]),
        );
        objs.insert(
            WLAN.into(),
            BTreeMap::from([
                (
                    IF_DEVICE.to_string(),
                    d(vec![
                        ("Interface", s("wlan0")),
                        ("DeviceType", Val::U32(2)),
                        ("State", Val::U32(100)),
                        ("StateReason", Val::U32List(vec![100, 0])),
                        ("Managed", Val::Bool(true)),
                        ("Autoconnect", Val::Bool(true)),
                        ("Driver", s("iwlwifi")),
                        ("HwAddress", s("3E:91:4A:07:6B:D2")),
                        ("Mtu", Val::U32(1500)),
                        ("ActiveConnection", p("/org/freedesktop/NetworkManager/ActiveConnection/2")),
                        ("Ip4Config", p("/org/freedesktop/NetworkManager/IP4Config/2")),
                        ("Ip6Config", p("/org/freedesktop/NetworkManager/IP6Config/2")),
                    ]),
                ),
                (
                    IF_WIRELESS.to_string(),
                    d(vec![
                        ("AccessPoints", Val::PathList(ap_paths.clone())),
                        ("ActiveAccessPoint", p(&ap_paths[0])),
                        ("Bitrate", Val::U32(866_700)),
                        ("PermHwAddress", s("A0:59:50:E4:12:7C")),
                        ("LastScan", Val::I64(1000)),
                    ]),
                ),
            ]),
        );
        objs.insert(
            DOCKER.into(),
            BTreeMap::from([(
                IF_DEVICE.to_string(),
                d(vec![
                    ("Interface", s("docker0")),
                    ("DeviceType", Val::U32(13)),
                    ("State", Val::U32(10)),
                    ("Managed", Val::Bool(false)),
                    ("Driver", s("bridge")),
                    ("HwAddress", s("02:42:6F:1C:9A:10")),
                    ("Mtu", Val::U32(1500)),
                ]),
            )]),
        );
        objs.insert("/org/freedesktop/NetworkManager/IP4Config/1".into(), ip4("192.168.1.23", 24, "192.168.1.1", &["192.168.1.1"]));
        objs.insert("/org/freedesktop/NetworkManager/IP6Config/1".into(), ip6("fd12:3456:789a::23"));
        objs.insert("/org/freedesktop/NetworkManager/IP4Config/2".into(), ip4("192.168.1.57", 24, "192.168.1.1", &["192.168.1.1", "9.9.9.9"]));
        objs.insert("/org/freedesktop/NetworkManager/IP6Config/2".into(), ip6("fd12:3456:789a::57"));

        let mut demo = Self { ev, objs, settings, next_id: 20, tick: 0, pending_secret: None };
        demo.set_active("/org/freedesktop/NetworkManager/ActiveConnection/1", "/org/freedesktop/NetworkManager/Settings/4", ETH, 2, true);
        demo.set_active("/org/freedesktop/NetworkManager/ActiveConnection/2", home, WLAN, 2, false);
        demo
    }

    fn set_active(&mut self, path: &str, conn: &str, dev: &str, state: u32, default: bool) {
        let c = self.settings.get(conn).cloned().unwrap_or_default().get("connection").cloned().unwrap_or_default();
        self.objs.insert(
            path.into(),
            BTreeMap::from([(
                IF_ACTIVE.to_string(),
                d(vec![
                    ("Connection", p(conn)),
                    ("Id", s(&c.s("id"))),
                    ("Uuid", s(&c.s("uuid"))),
                    ("Type", s(&c.s("type"))),
                    ("Devices", Val::PathList(vec![dev.into()])),
                    ("State", Val::U32(state)),
                    ("Default", Val::Bool(default)),
                    ("Vpn", Val::Bool(false)),
                ]),
            )]),
        );
    }

    fn publish(&self) {
        let mut snap = model::parse(&self.objs, &self.settings);
        snap.general.wifi_backend = Some("iwd".into());
        let _ = self.ev.send(Ev::Snapshot(Box::new(snap)));
    }

    fn dev_mut(&mut self, dev: &str, iface: &str) -> &mut Dict {
        self.objs.get_mut(dev).expect("device").get_mut(iface).expect("iface")
    }

    fn set_dev_state(&mut self, dev: &str, state: u32, reason: u32) {
        let dd = self.dev_mut(dev, IF_DEVICE);
        dd.insert("State".into(), Val::U32(state));
        dd.insert("StateReason".into(), Val::U32List(vec![state, reason]));
        if state != 100 {
            for k in ["ActiveConnection", "Ip4Config", "Ip6Config"] {
                if state <= 30 || state == 120 {
                    dd.insert(k.into(), p("/"));
                }
            }
        }
    }

    fn active_of(&self, dev: &str) -> Option<String> {
        self.objs.get(dev)?.get(IF_DEVICE)?.path("ActiveConnection")
    }

    fn drop_active(&mut self, dev: &str) {
        if let Some(a) = self.active_of(dev) {
            self.objs.remove(&a);
        }
        if dev == WLAN {
            self.dev_mut(WLAN, IF_WIRELESS).insert("ActiveAccessPoint".into(), p("/"));
        }
    }

    fn new_path(&mut self, kind: &str) -> String {
        self.next_id += 1;
        format!("/org/freedesktop/NetworkManager/{kind}/{}", self.next_id)
    }

    fn drift(&mut self) {
        self.tick += 1;
        let t = self.tick;
        for (path, o) in self.objs.iter_mut() {
            if let Some(a) = o.get_mut(IF_AP) {
                let st = a.u("Strength") as i32;
                let j = ((t as i32 * 13 + path.len() as i32 * 7) % 7) - 3;
                a.insert("Strength".into(), Val::U8((st + j).clamp(15, 95) as u8));
            }
        }
        self.publish();
    }

    fn later(&mut self, l: Later) {
        match l {
            Later::WifiUp { ap, profile } => {
                let act = self.new_path("ActiveConnection");
                self.set_active(&act, &profile, WLAN, 2, false);
                let ip = self.new_path("IP4Config");
                self.objs.insert(ip.clone(), ip4("192.168.43.112", 24, "192.168.43.1", &["192.168.43.1"]));
                let dd = self.dev_mut(WLAN, IF_DEVICE);
                dd.insert("ActiveConnection".into(), p(&act));
                dd.insert("Ip4Config".into(), p(&ip));
                self.set_dev_state(WLAN, 100, 0);
                self.dev_mut(WLAN, IF_WIRELESS).insert("ActiveAccessPoint".into(), p(&ap));
                if let Some(c) = self.settings.get_mut(&profile).and_then(|s| s.get_mut("connection")) {
                    c.insert("timestamp".into(), Val::U64(now() as u64));
                }
                let name = self.settings.get(&profile).and_then(|s| s.get("connection")).map(|c| c.s("id")).unwrap_or_default();
                let _ = self.ev.send(Ev::Busy { key: WLAN.into(), label: name.clone(), on: false });
                let _ = self.ev.send(Ev::Ok(format!("Connected to {name}")));
            }
            Later::WifiFail { reason, label } => {
                self.drop_active(WLAN);
                self.set_dev_state(WLAN, 120, reason);
                let _ = self.ev.send(Ev::Busy { key: WLAN.into(), label, on: false });
                self.publish();
                self.set_dev_state(WLAN, 30, reason);
            }
            Later::EthUp => {
                let act = "/org/freedesktop/NetworkManager/ActiveConnection/1";
                self.set_active(act, "/org/freedesktop/NetworkManager/Settings/4", ETH, 2, true);
                let dd = self.dev_mut(ETH, IF_DEVICE);
                dd.insert("ActiveConnection".into(), p(act));
                dd.insert("Ip4Config".into(), p("/org/freedesktop/NetworkManager/IP4Config/1"));
                self.set_dev_state(ETH, 100, 0);
            }
            Later::VpnUp(profile) => {
                let act = self.new_path("ActiveConnection");
                self.objs.insert(
                    WG.into(),
                    BTreeMap::from([(
                        IF_DEVICE.to_string(),
                        d(vec![
                            ("Interface", s("wg0")),
                            ("DeviceType", Val::U32(29)),
                            ("State", Val::U32(100)),
                            ("Managed", Val::Bool(true)),
                            ("Driver", s("wireguard")),
                            ("Mtu", Val::U32(1420)),
                            ("ActiveConnection", p(&act)),
                            ("Ip4Config", p("/org/freedesktop/NetworkManager/IP4Config/9")),
                        ]),
                    )]),
                );
                self.objs.insert("/org/freedesktop/NetworkManager/IP4Config/9".into(), ip4("10.20.0.7", 16, "", &[]));
                self.set_active(&act, &profile, WG, 2, false);
                let _ = self.ev.send(Ev::Busy { key: profile.clone(), label: "Office VPN".into(), on: false });
                let _ = self.ev.send(Ev::Ok("Connected to Office VPN".into()));
            }
            Later::Rescan => {
                let path = "/org/freedesktop/NetworkManager/AccessPoint/50".to_string();
                if !self.objs.contains_key(&path) {
                    self.objs.insert(path.clone(), ap_obj("Galaxy A54", 44, 2437, 0x188, "9A:00:11:22:33:44"));
                    if let Some(Val::PathList(l)) = self.dev_mut(WLAN, IF_WIRELESS).get_mut("AccessPoints") {
                        l.push(path);
                    }
                }
                self.dev_mut(WLAN, IF_WIRELESS).insert("LastScan".into(), Val::I64(5000));
            }
        }
        self.publish();
    }

    fn ap_ssid(&self, ap: &str) -> String {
        self.objs.get(ap).and_then(|o| o.get(IF_AP)).and_then(|a| a.get("Ssid")).and_then(Val::bytes).map(|b| String::from_utf8_lossy(b).to_string()).unwrap_or_default()
    }

    fn command(&mut self, c: Cmd, ltx: &UnboundedSender<Later>) {
        let delay = |ltx: &UnboundedSender<Later>, ms: u64, l: Later| {
            let ltx = ltx.clone();
            tokio::spawn(async move {
                sleep(Duration::from_millis(ms)).await;
                let _ = ltx.send(l);
            });
        };
        match c {
            Cmd::Scan(_) => {
                let _ = self.ev.send(Ev::Info("Scanning…".into()));
                delay(ltx, 1500, Later::Rescan);
            }
            Cmd::ConnectWifi { ap, profile, settings, label, .. } => {
                self.drop_active(WLAN);
                self.set_dev_state(WLAN, 40, 0);
                let _ = self.ev.send(Ev::Busy { key: WLAN.into(), label: label.clone(), on: true });
                let ssid = self.ap_ssid(&ap);
                let profile = match (profile, settings) {
                    (Some(p), _) => p,
                    (None, Some(s)) => {
                        let path = self.new_path("Settings");
                        self.settings.insert(path.clone(), s);
                        path
                    }
                    (None, None) => return,
                };
                if ssid == "Neighbor's Wi-Fi" {
                    delay(ltx, 2500, Later::WifiFail { reason: 11, label });
                } else if ssid == "Pixel 8" && self.settings.get(&profile).and_then(|s| s.get("802-11-wireless-security")).map(|w| w.s("psk")) == Some("outdated-pass".into()) {
                    // Saved password is stale: NM asks the agent for a new one.
                    self.set_dev_state(WLAN, 60, 0);
                    let id = 1000 + self.next_id as u64;
                    self.pending_secret = Some((id, profile.clone()));
                    let _ = self.ev.send(Ev::SecretRequest {
                        id,
                        req: SecretRequest { conn_id: "Pixel 8 hotspot".into(), setting: "802-11-wireless-security".into(), key: "psk".into(), retry: true },
                    });
                } else {
                    delay(ltx, 1400, Later::WifiUp { ap, profile });
                }
            }
            Cmd::SecretReply { id, secrets } => {
                let Some((pid, profile)) = self.pending_secret.take() else { return };
                if pid != id {
                    return;
                }
                match secrets {
                    Some(sec) => {
                        if let Some(w) = self.settings.get_mut(&profile).and_then(|s| s.get_mut("802-11-wireless-security")) {
                            w.extend(sec);
                        }
                        self.set_dev_state(WLAN, 50, 0);
                        let ap = "/org/freedesktop/NetworkManager/AccessPoint/4".to_string();
                        delay(ltx, 1200, Later::WifiUp { ap, profile });
                    }
                    None => delay(ltx, 10, Later::WifiFail { reason: 7, label: "Pixel 8 hotspot".into() }),
                }
            }
            Cmd::Activate { profile, label, .. } => {
                let kind = self.settings.get(&profile).and_then(|s| s.get("connection")).map(|c| c.s("type")).unwrap_or_default();
                let _ = self.ev.send(Ev::Busy { key: profile.clone(), label: label.clone(), on: true });
                match kind.as_str() {
                    "wireguard" => delay(ltx, 900, Later::VpnUp(profile)),
                    "802-3-ethernet" => {
                        let _ = self.ev.send(Ev::Busy { key: profile, label, on: false });
                        self.set_dev_state(ETH, 70, 0);
                        delay(ltx, 900, Later::EthUp);
                    }
                    "802-11-wireless" => {
                        let ssid = self.settings.get(&profile).and_then(|s| s.get("802-11-wireless")).and_then(|w| w.get("ssid")).and_then(Val::bytes).map(|b| String::from_utf8_lossy(b).to_string()).unwrap_or_default();
                        let _ = self.ev.send(Ev::Busy { key: profile.clone(), label: label.clone(), on: false });
                        let ap = self.objs.iter().find(|(_, o)| o.get(IF_AP).and_then(|a| a.get("Ssid")).and_then(Val::bytes) == Some(ssid.as_bytes())).map(|(p, _)| p.clone());
                        match ap {
                            Some(ap) => self.command(Cmd::ConnectWifi { device: WLAN.into(), ap, profile: Some(profile), settings: None, label }, ltx),
                            None => {
                                let _ = self.ev.send(Ev::Error(format!("{label}: the network wasn't found (out of range or hidden?)")));
                            }
                        }
                    }
                    _ => {
                        let _ = self.ev.send(Ev::Busy { key: profile, label: label.clone(), on: false });
                        let _ = self.ev.send(Ev::Error(format!("{label}: demo can't activate this type")));
                    }
                }
            }
            Cmd::Deactivate { active, label } => {
                let dev = self.objs.get(&active).and_then(|o| o.get(IF_ACTIVE)).map(|a| a.paths("Devices")).and_then(|v| v.first().cloned());
                self.objs.remove(&active);
                if let Some(dev) = dev {
                    if dev == WG {
                        self.objs.remove(WG);
                    } else {
                        if dev == WLAN {
                            self.dev_mut(WLAN, IF_WIRELESS).insert("ActiveAccessPoint".into(), p("/"));
                        }
                        self.set_dev_state(&dev, 30, 39);
                    }
                }
                let _ = self.ev.send(Ev::Ok(format!("Disconnected {label}")));
            }
            Cmd::DisconnectDevice { device, label } => {
                self.drop_active(&device);
                self.set_dev_state(&device, 30, 39);
                let _ = self.ev.send(Ev::Ok(format!("Disconnected {label}")));
            }
            Cmd::AddProfile { settings, activate_on } => {
                let name = settings.get("connection").map(|c| c.s("id")).unwrap_or_default();
                let path = self.new_path("Settings");
                let is_ap = settings.get("802-11-wireless").map(|w| w.s("mode")) == Some("ap".into());
                self.settings.insert(path.clone(), settings);
                let _ = self.ev.send(Ev::Ok(format!("Saved {name}")));
                if activate_on.is_some() && is_ap {
                    self.drop_active(WLAN);
                    let act = self.new_path("ActiveConnection");
                    self.set_active(&act, &path, WLAN, 2, false);
                    self.dev_mut(WLAN, IF_DEVICE).insert("ActiveConnection".into(), p(&act));
                    self.set_dev_state(WLAN, 100, 0);
                    let _ = self.ev.send(Ev::Ok(format!("Hotspot {name} is up")));
                }
            }
            Cmd::UpdateProfile { path, settings } => {
                let name = settings.get("connection").map(|c| c.s("id")).unwrap_or_default();
                self.settings.insert(path, settings);
                let _ = self.ev.send(Ev::Ok(format!("Saved {name}")));
            }
            Cmd::DeleteProfile { path, label } => {
                self.settings.remove(&path);
                let actives: Vec<String> = self.objs.iter().filter(|(_, o)| o.get(IF_ACTIVE).is_some_and(|a| a.s("Connection") == path)).map(|(k, _)| k.clone()).collect();
                for a in actives {
                    self.command(Cmd::Deactivate { active: a, label: label.clone() }, ltx);
                }
                let _ = self.ev.send(Ev::Ok(format!("Forgot {label}")));
            }
            Cmd::GetSecrets { path, setting } => {
                let values = self.settings.get(&path).and_then(|s| s.get(&setting)).cloned().unwrap_or_default();
                let _ = self.ev.send(Ev::Secrets { path, setting, values });
            }
            Cmd::SetWifiEnabled(on) => {
                self.objs.get_mut(NM_PATH).and_then(|o| o.get_mut(NM)).expect("nm").insert("WirelessEnabled".into(), Val::Bool(on));
                if on {
                    self.set_dev_state(WLAN, 30, 0);
                } else {
                    self.drop_active(WLAN);
                    self.set_dev_state(WLAN, 20, 0);
                }
            }
            Cmd::SetWwanEnabled(on) => {
                self.objs.get_mut(NM_PATH).and_then(|o| o.get_mut(NM)).expect("nm").insert("WwanEnabled".into(), Val::Bool(on));
            }
            Cmd::SetNetworkingEnabled(on) => {
                self.objs.get_mut(NM_PATH).and_then(|o| o.get_mut(NM)).expect("nm").insert("NetworkingEnabled".into(), Val::Bool(on));
                let _ = self.ev.send(Ev::Info(format!("Networking {}", if on { "enabled" } else { "disabled" })));
            }
            Cmd::SetHostname(h) => {
                self.objs.get_mut("/org/freedesktop/NetworkManager/Settings").and_then(|o| o.get_mut(IF_SETTINGS)).expect("settings").insert("Hostname".into(), s(&h));
                let _ = self.ev.send(Ev::Ok(format!("Hostname set to {h}")));
            }
            Cmd::CheckConnectivity => {
                let _ = self.ev.send(Ev::Info("Connectivity: online".into()));
            }
            Cmd::SetManaged { device, on } => {
                self.dev_mut(&device, IF_DEVICE).insert("Managed".into(), Val::Bool(on));
                self.set_dev_state(&device, if on { 30 } else { 10 }, 0);
            }
            Cmd::SetDeviceAutoconnect { device, on } => {
                self.dev_mut(&device, IF_DEVICE).insert("Autoconnect".into(), Val::Bool(on));
            }
            Cmd::Import { kind, file } => {
                let _ = self.ev.send(Ev::Info(format!("Demo: would run `nmcli connection import type {kind} file {file}`")));
            }
        }
        self.publish();
    }
}
