//! Build the [`Snapshot`] clients see from the daemon's live state.

use std::collections::BTreeMap;

use crate::backend::model::{self, AccessPoint, ActiveConn, DevKind, DevState, Device, General, IpInfo, Profile, Security, Snapshot};
use crate::backend::val::ssid_to_string;

use super::store::{self, ssid_of};
use super::{act_path, dev_path, prof_path, sys, Daemon, Extra, PendingSecret};

fn dev_kind(k: &str) -> DevKind {
    match k {
        "ether" => DevKind::Ethernet,
        "wlan" => DevKind::Wifi,
        "wireguard" => DevKind::WireGuard,
        "bridge" => DevKind::Bridge,
        "bond" => DevKind::Bond,
        "vlan" => DevKind::Vlan,
        "tun" => DevKind::Tun,
        "loopback" => DevKind::Loopback,
        _ => DevKind::Other,
    }
}

fn profile_kind(k: DevKind) -> &'static str {
    match k {
        DevKind::Ethernet => "802-3-ethernet",
        DevKind::Wifi => "802-11-wireless",
        DevKind::WireGuard => "wireguard",
        DevKind::Bridge => "bridge",
        DevKind::Bond => "bond",
        DevKind::Vlan => "vlan",
        _ => "",
    }
}

fn iwd_security(kind: &str) -> Security {
    match kind {
        "psk" => Security::Wpa2,
        "8021x" => Security::Enterprise,
        "wep" => Security::Wep,
        _ => Security::Open,
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

impl Daemon {
    pub(super) fn snapshot(&self) -> Snapshot {
        let (wifi_soft, wifi_hard, _) = sys::rfkill("wlan");
        let (wwan_soft, wwan_hard, wwan_any) = sys::rfkill("wwan");
        let general = General {
            version: env!("CARGO_PKG_VERSION").to_string(),
            hostname: sys::hostname(),
            networking_enabled: self.store.state.networking,
            wifi_enabled: !wifi_soft && !wifi_hard,
            wifi_hw_enabled: !wifi_hard,
            wwan_enabled: wwan_any && !wwan_soft && !wwan_hard,
            wwan_hw_enabled: wwan_any && !wwan_hard,
            connectivity: self.connectivity,
            connectivity_check_enabled: true,
            state: if !self.store.state.networking {
                10
            } else if self.links.primary().is_some() {
                70
            } else {
                20
            },
            wifi_backend: Some(if self.iwd.is_some() && !self.iw.devices.is_empty() { "iwd" } else { "iwd (not running)" }.into()),
        };

        let primary = self.links.primary();
        let (dns, domains) = sys::resolv();
        let mut aps: BTreeMap<String, AccessPoint> = BTreeMap::new();
        let mut active: Vec<ActiveConn> = Vec::new();
        let mut devices = Vec::new();

        for l in self.links.links.values() {
            if l.kind == "loopback" {
                continue;
            }
            let kind = dev_kind(&l.kind);
            let ours = self.actives.values().find(|a| a.iface == l.name);
            let wired_like = matches!(kind, DevKind::Ethernet | DevKind::Wifi);
            let managed = !self.store.state.unmanaged.contains(&l.name) && (wired_like || ours.is_some());
            let iwd_dev = self.iw.device(&l.name);
            let mut d = Device {
                path: dev_path(&l.name),
                iface: l.name.clone(),
                kind,
                state: DevState::Disconnected,
                state_reason: self.reasons.get(&l.name).copied().unwrap_or(0),
                managed,
                autoconnect: !self.store.state.no_autoconnect.contains(&l.name),
                driver: super::link::driver(&l.name),
                hw_addr: l.mac.clone(),
                perm_hw_addr: if l.perm_mac.is_empty() { l.mac.clone() } else { l.perm_mac.clone() },
                mtu: l.mtu,
                active: None,
                ip4: IpInfo::default(),
                ip6: IpInfo::default(),
                speed: 0,
                carrier: None,
                access_points: Vec::new(),
                active_ap: None,
                bitrate_kbps: 0,
                last_scan_ms: 0,
                available_connections: Vec::new(),
            };
            d.ip4.addresses = self.links.addrs_of(l.index, false);
            d.ip6.addresses = self.links.addrs_of(l.index, true);
            d.ip4.gateway = self.links.default_route(l.index, false).and_then(|r| r.gateway).map(|g| g.to_string()).unwrap_or_default();
            d.ip6.gateway = self.links.default_route(l.index, true).and_then(|r| r.gateway).map(|g| g.to_string()).unwrap_or_default();
            if primary == Some(l.index) {
                d.ip4.dns = dns.iter().filter(|s| !s.contains(':')).cloned().collect();
                d.ip6.dns = dns.iter().filter(|s| s.contains(':')).cloned().collect();
                d.ip4.domains = domains.clone();
            }
            if let Some(lease) = ours.and_then(|a| a.lease.as_ref())
                && d.ip4.dns.is_empty() {
                    d.ip4.dns = lease.dns.iter().map(|a| a.to_string()).collect();
                }

            match kind {
                DevKind::Ethernet => {
                    d.speed = super::link::speed(&l.name);
                    d.carrier = Some(l.carrier);
                    d.state = match ours.map(|a| a.state) {
                        Some(2) => DevState::Connected,
                        Some(_) => DevState::Connecting,
                        None if !l.carrier => DevState::Unavailable,
                        None => DevState::Disconnected,
                    };
                }
                DevKind::Wifi => self.wifi_device(&mut d, &mut aps, &mut active, primary == Some(l.index)),
                _ => {
                    d.state = match ours.map(|a| a.state) {
                        Some(2) => DevState::Connected,
                        Some(_) => DevState::Connecting,
                        None => DevState::Unmanaged,
                    };
                }
            }
            if !managed {
                d.state = DevState::Unmanaged;
            } else if iwd_dev.is_none() && kind == DevKind::Wifi && self.iwd.is_none() {
                d.state = DevState::Unavailable;
            }
            if let Some(a) = ours {
                d.active = Some(act_path(&a.uuid));
            }
            let pk = profile_kind(kind);
            if !pk.is_empty() {
                let visible: Vec<Vec<u8>> = aps.values().filter(|a| d.access_points.contains(&a.path)).map(|a| a.ssid_bytes.clone()).collect();
                let mut avail: Vec<(&String, i64, i64)> = self
                    .store
                    .profiles
                    .iter()
                    .filter(|(_, s)| store::kind(s) == pk)
                    .filter(|(_, s)| {
                        let i = store::iface(s);
                        i.is_empty() || i == l.name
                    })
                    .filter(|(_, s)| kind != DevKind::Wifi || store::is_hotspot(s) || ssid_of(s).is_some_and(|b| visible.contains(&b)))
                    .map(|(u, s)| {
                        let c = store::conn(s);
                        (u, crate::backend::val::DictExt::i(&c, "autoconnect-priority"), crate::backend::val::DictExt::i(&c, "timestamp"))
                    })
                    .collect();
                avail.sort_by_key(|(_, p, t)| (std::cmp::Reverse(*p), std::cmp::Reverse(*t)));
                d.available_connections = avail.into_iter().map(|(u, _, _)| prof_path(u)).collect();
            }
            devices.push(d);
        }

        for a in self.actives.values() {
            let index = self.links.index(&a.iface);
            let default4 = match a.extra {
                Extra::Wg { full4, .. } => full4,
                _ => index.is_some() && index == primary,
            };
            let s = self.store.profiles.get(&a.uuid);
            active.push(ActiveConn {
                path: act_path(&a.uuid),
                conn_path: prof_path(&a.uuid),
                id: s.map(store::id).unwrap_or_else(|| a.label.clone()),
                uuid: a.uuid.clone(),
                kind: a.kind.clone(),
                devices: if a.iface.is_empty() { Vec::new() } else { vec![dev_path(&a.iface)] },
                state: a.state,
                default4,
                vpn: a.kind == "vpn",
            });
        }

        let mut profiles: Vec<Profile> = self
            .store
            .profiles
            .iter()
            .map(|(u, s)| {
                let mut p = Profile::from_settings(&prof_path(u), &store::strip_secrets(s), None);
                p.filename = self.store.file_of(u).to_string_lossy().to_string();
                if let Some(a) = active.iter().find(|a| a.conn_path == p.path) {
                    p.active_state = Some(a.state);
                    p.active_devices = a.devices.iter().map(|d| d.trim_start_matches("/device/").to_string()).collect();
                }
                p
            })
            .collect();
        profiles.sort_by_key(|a| (!a.is_active(), model::kind_rank(&a.kind), a.id.to_lowercase()));
        devices.sort_by(|a, b| (a.kind, &a.iface).cmp(&(b.kind, &b.iface)));
        Snapshot { general, devices, aps, active, profiles }
    }

    fn wifi_device(&self, d: &mut Device, aps: &mut BTreeMap<String, AccessPoint>, active: &mut Vec<ActiveConn>, is_primary: bool) {
        let ifname = d.iface.clone();
        let Some(dev) = self.iw.device(&ifname) else {
            d.state = DevState::Unavailable;
            return;
        };
        if !dev.powered {
            d.state = DevState::Unavailable;
            return;
        }
        if let Some(h) = self.actives.values().find(|a| a.iface == ifname && store::kind_is_hotspot(&self.store, &a.uuid)) {
            d.state = if h.state == 2 { DevState::Connected } else { DevState::Connecting };
            return;
        }

        // Access points: the kernel's scan results, plus networks iwd still
        // lists whose BSSes have aged out of the kernel cache.
        let mut seen_ssids = Vec::new();
        if let Some(cache) = self.bss.get(&ifname) {
            for (b, _) in cache.values() {
                let path = format!("/ap/{ifname}/{}", b.bssid);
                seen_ssids.push(b.ssid.clone());
                d.access_points.push(path.clone());
                aps.insert(
                    path.clone(),
                    AccessPoint {
                        path,
                        ssid: ssid_to_string(&b.ssid),
                        ssid_bytes: b.ssid.clone(),
                        bssid: b.bssid.to_uppercase(),
                        strength: b.strength(),
                        freq: b.freq,
                        security: b.security,
                        max_bitrate_kbps: b.max_rate_kbps,
                        mode: 2,
                    },
                );
            }
        }
        for (np, dbm) in self.signals.get(&ifname).into_iter().flatten() {
            let Some(n) = self.iw.networks.get(np) else { continue };
            let bytes = n.name.as_bytes().to_vec();
            if seen_ssids.contains(&bytes) {
                continue;
            }
            let path = format!("/ap/{ifname}/net-{}", hex(&bytes));
            d.access_points.push(path.clone());
            aps.insert(
                path.clone(),
                AccessPoint {
                    path,
                    ssid: n.name.clone(),
                    ssid_bytes: bytes,
                    bssid: String::new(),
                    strength: (2 * (*dbm as i32 + 100)).clamp(0, 100) as u8,
                    freq: 0,
                    security: iwd_security(&n.kind),
                    max_bitrate_kbps: 0,
                    mode: 2,
                },
            );
        }

        let station = self.iw.stations.get(&dev.path);
        let current = self.iw.current_network(&ifname);
        let asking = self.secrets.values().any(|p| matches!(p, PendingSecret::Agent { .. })) && self.wifi_pending.contains_key(&ifname);
        d.state = match station.map(|s| s.state.as_str()) {
            _ if asking => DevState::NeedAuth,
            _ if self.wifi_pending.contains_key(&ifname) => DevState::Connecting,
            Some("connected") => DevState::Connected,
            Some("connecting" | "roaming") => DevState::Connecting,
            Some("disconnecting") => DevState::Disconnecting,
            None if dev.mode == "ap" => DevState::Disconnected,
            _ => DevState::Disconnected,
        };
        if let Some((bssid, rate)) = self.diag.get(&ifname) {
            d.bitrate_kbps = *rate;
            let p = format!("/ap/{ifname}/{bssid}");
            if aps.contains_key(&p) {
                d.active_ap = Some(p);
            }
        }
        if let Some(n) = current {
            let bytes = n.name.as_bytes();
            if d.active_ap.as_ref().is_none_or(|p| aps.get(p).is_none_or(|a| a.ssid_bytes != bytes)) {
                d.active_ap = d.access_points.iter().filter(|p| aps.get(*p).is_some_and(|a| a.ssid_bytes == bytes)).max_by_key(|p| aps[*p].strength).cloned();
            }
            let prof = self
                .wifi_pending
                .get(&ifname)
                .and_then(|p| self.store.profiles.get(&p.uuid))
                .filter(|s| ssid_of(s).as_deref() == Some(bytes))
                .or_else(|| self.store.by_ssid(bytes).into_iter().next());
            if let Some(s) = prof {
                let uuid = store::uuid(s);
                d.active = Some(act_path(&uuid));
                active.push(ActiveConn {
                    path: act_path(&uuid),
                    conn_path: prof_path(&uuid),
                    id: store::id(s),
                    uuid,
                    kind: "802-11-wireless".into(),
                    devices: vec![d.path.clone()],
                    state: if d.state == DevState::Connected { 2 } else { 1 },
                    default4: is_primary,
                    vpn: false,
                });
            }
        } else if let Some(p) = self.wifi_pending.get(&ifname)
            && let Some(s) = self.store.profiles.get(&p.uuid) {
                // Connecting, before iwd reports a network: point at it anyway.
                if let Some(bytes) = ssid_of(s) {
                    d.active_ap = d.access_points.iter().filter(|ap| aps.get(*ap).is_some_and(|a| a.ssid_bytes == bytes)).max_by_key(|ap| aps[*ap].strength).cloned();
                }
                d.active = Some(act_path(&p.uuid));
                active.push(ActiveConn {
                    path: act_path(&p.uuid),
                    conn_path: prof_path(&p.uuid),
                    id: store::id(s),
                    uuid: p.uuid.clone(),
                    kind: "802-11-wireless".into(),
                    devices: vec![d.path.clone()],
                    state: 1,
                    default4: false,
                    vpn: false,
                });
            }
    }
}
