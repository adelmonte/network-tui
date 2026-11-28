//! Wi-Fi through iwd: keeping profiles and iwd's files in step, connecting,
//! answering iwd's password requests, scanning, and hotspots.

use std::collections::BTreeSet;
use std::net::Ipv4Addr;
use std::time::Duration;

use tokio::sync::oneshot;
use tokio::time::Instant;

use crate::backend::val::{DictExt, Settings, Val};
use crate::backend::SecretRequest;

use super::store::{self, get_s, ssid_of};
use super::{dev_path, iwd, iwdfile, link, prof_path, sys, Active, Daemon, Extra, Internal, PendingSecret, WifiPending};

pub const HOTSPOT_ADDR: Ipv4Addr = Ipv4Addr::new(10, 42, 0, 1);
const HOTSPOT_NET: &str = "10.42.0.0/24";

impl Daemon {
    /// Import iwd networks we have no profile for, and give every Wi-Fi
    /// profile an iwd file.
    pub(super) fn sync_iwd_files(&mut self) {
        let have: BTreeSet<String> = self.store.profiles.values().filter(|s| store::is_wifi_client(s)).filter_map(|s| iwdfile::path_for(s).ok()).collect();
        for (path, ssid, ext, ini) in iwdfile::scan_dir() {
            if have.contains(&path) {
                continue;
            }
            let s = iwdfile::import(&ssid, &ext, &ini);
            tracing::info!("importing iwd network {}", store::id(&s));
            if let Err(e) = self.store.put(s) {
                tracing::warn!("saving imported profile: {e}");
            }
        }
        for s in self.store.profiles.values().filter(|s| store::is_wifi_client(s)) {
            if let Ok(p) = iwdfile::path_for(s)
                && !std::path::Path::new(&p).exists()
                && let Err(e) = iwdfile::write(s, None) {
                    tracing::warn!("{}: {e}", store::id(s));
                }
        }
    }

    pub(super) async fn do_refresh_iwd(&mut self) {
        let Some(i) = self.iwd.clone() else { return };
        let st = match i.state().await {
            Ok(st) => st,
            Err(e) => {
                tracing::debug!("iwd: {e}");
                self.iw = iwd::IwdState::default();
                self.dirty = true;
                return;
            }
        };
        let known_before: BTreeSet<String> = self.iw.known.values().map(|k| format!("{}.{}", k.name, k.kind)).collect();
        let known_now: BTreeSet<String> = st.known.values().map(|k| format!("{}.{}", k.name, k.kind)).collect();
        let mut rescan = Vec::new();
        for dev in &st.devices {
            let Some(station) = st.stations.get(&dev.path) else {
                self.signals.remove(&dev.name);
                continue;
            };
            if let Ok(list) = i.ordered_networks(&dev.path).await {
                self.signals.insert(dev.name.clone(), list);
            }
            let finished = self.was_scanning.contains(&dev.name) && !station.scanning;
            if finished || !self.bss.contains_key(&dev.name) {
                rescan.push(dev.name.clone());
            }
            if station.scanning {
                self.was_scanning.insert(dev.name.clone());
            } else {
                self.was_scanning.remove(&dev.name);
            }
            if station.state == "connected" {
                self.reasons.remove(&dev.name);
            }
        }
        self.iw = st;
        if known_before != known_now && !known_before.is_empty() {
            self.sync_iwd_files();
        }
        for ifname in rescan {
            self.refresh_bss(&ifname).await;
        }
        self.refresh_diag().await;
        self.dirty = true;
    }

    async fn refresh_bss(&mut self, ifname: &str) {
        let Some(index) = self.links.index(ifname) else { return };
        match super::scan::dump(index).await {
            Ok(list) => {
                let now = Instant::now();
                let cache = self.bss.entry(ifname.to_string()).or_default();
                for b in list {
                    cache.insert(b.bssid.clone(), (b, now));
                }
            }
            Err(e) => {
                tracing::debug!("nl80211 scan dump on {ifname}: {e}");
                self.bss.entry(ifname.to_string()).or_default();
            }
        }
    }

    pub(super) async fn refresh_diag(&mut self) {
        let Some(i) = self.iwd.clone() else { return };
        let devs: Vec<(String, String, bool)> = self
            .iw
            .devices
            .iter()
            .map(|d| (d.name.clone(), d.path.clone(), self.iw.stations.get(&d.path).is_some_and(|s| s.state == "connected")))
            .collect();
        for (name, path, connected) in devs {
            if !connected {
                self.diag.remove(&name);
                continue;
            }
            if let Ok(d) = i.diagnostics(&path).await {
                self.diag.insert(name, d);
            }
        }
    }

    pub(super) async fn background_scan(&mut self) {
        let Some(i) = self.iwd.clone() else { return };
        for (path, st) in &self.iw.stations {
            if !st.scanning && matches!(st.state.as_str(), "connected" | "disconnected") {
                let _ = i.scan(path).await;
            }
        }
    }

    pub(super) async fn scan(&mut self, client: u64, ifname: &str) {
        let Some(i) = self.iwd.clone() else { return self.err(client, "iwd isn't running") };
        let Some(dev) = self.iw.device(ifname).cloned() else { return self.err(client, format!("{ifname}: not a Wi-Fi device")) };
        if !self.iw.stations.contains_key(&dev.path) {
            return self.info(client, format!("{ifname} is in access point mode"));
        }
        if let Err(e) = i.scan(&dev.path).await {
            let (msg, code) = iwd::friendly(&e);
            if code != 4 || !msg.contains("busy") {
                self.err(client, format!("Scan: {msg}"));
            }
        }
    }

    /// Before saving a client Wi-Fi profile: iwd keeps one file per network,
    /// so other profiles for the same network are replaced by this one.
    pub(super) fn replace_same_ssid(&mut self, s: &Settings) -> Result<(), String> {
        let path = iwdfile::path_for(s)?;
        let me = store::uuid(s);
        let dups: Vec<String> = self
            .store
            .profiles
            .values()
            .filter(|o| store::is_wifi_client(o) && store::uuid(o) != me && iwdfile::path_for(o).ok().as_deref() == Some(&path))
            .map(store::uuid)
            .collect();
        for d in dups {
            self.store.remove(&d);
        }
        iwdfile::write(s, None).map(|_| ())
    }

    pub(super) async fn connect_wifi(&mut self, client: u64, ifname: String, ap: String, profile: Option<String>, settings: Option<Settings>, label: String) {
        let s = match (profile, settings) {
            (Some(p), _) => match self.profile_by_path(&p) {
                Some(s) => s,
                None => return self.err(client, format!("{label}: that profile no longer exists")),
            },
            (None, Some(mut s)) => {
                if store::uuid(&s).is_empty() {
                    s.entry("connection".into()).or_default().insert("uuid".into(), Val::Str(crate::backend::form::new_uuid()));
                }
                if let Err(e) = self.replace_same_ssid(&s) {
                    return self.err(client, format!("{label}: {e}"));
                }
                if let Err(e) = self.store.put(s.clone()) {
                    return self.err(client, format!("Saving {label}: {e}"));
                }
                s
            }
            (None, None) => return,
        };
        self.connect_profile_wifi(client, ifname, s, label, ap == "/").await;
    }

    pub(super) async fn connect_profile_wifi(&mut self, client: u64, ifname: String, s: Settings, label: String, hidden: bool) {
        if !self.store.state.networking {
            return self.err(client, "Networking is disabled");
        }
        let Some(i) = self.iwd.clone() else { return self.err(client, "iwd isn't running") };
        let Some(dev) = self.iw.device(&ifname).cloned() else { return self.err(client, format!("{ifname}: not a Wi-Fi device iwd knows about")) };
        if self.store.state.unmanaged.contains(&ifname) {
            return self.err(client, format!("{ifname} is unmanaged"));
        }
        if let Some(u) = self.hotspot_on(&ifname) {
            self.deactivate(&u, 39).await;
        }
        if let Err(e) = iwdfile::write(&s, None) {
            return self.err(client, format!("{label}: {e}"));
        }
        let uuid = store::uuid(&s);
        let ssid = String::from_utf8_lossy(&ssid_of(&s).unwrap_or_default()).to_string();
        let hidden = hidden || s.get("802-11-wireless").is_some_and(|w| w.b("hidden"));
        if let Some(old) = self.wifi_pending.remove(&ifname) {
            self.busy(old.client, &dev_path(&ifname), &old.label, false);
        }
        self.wifi_pending.insert(ifname.clone(), WifiPending { uuid: uuid.clone(), label: label.clone(), client, retried: false, secret_changed: false });
        self.reasons.remove(&ifname);
        self.busy(client, &dev_path(&ifname), &label, true);
        // Show "connecting" now so a quick failure still reads as one.
        self.publish();
        self.spawn_wifi_connect(i, dev.path, ifname, uuid, ssid, hidden);
    }

    fn spawn_wifi_connect(&self, i: iwd::Iwd, station: String, ifname: String, uuid: String, ssid: String, hidden: bool) {
        let net = self.iw.network_by_name(&ifname, &ssid).map(|(p, _)| p.clone());
        let tx = self.tx.clone();
        tokio::spawn(async move {
            let res = async {
                if let Some(p) = net {
                    return i.connect_network(&p).await;
                }
                if hidden {
                    return i.connect_hidden(&station, &ssid).await;
                }
                // iwd hasn't seen it yet: scan and wait for it to show up.
                let _ = i.scan(&station).await;
                for _ in 0..20 {
                    tokio::time::sleep(Duration::from_millis(500)).await;
                    if let Ok(st) = i.state().await
                        && let Some((p, _)) = st.network_by_name(&ifname, &ssid) {
                            return i.connect_network(p).await;
                        }
                }
                i.connect_hidden(&station, &ssid).await
            }
            .await;
            let _ = tx.send(Internal::WifiDone { ifname, uuid, res });
        });
    }

    pub(super) async fn on_wifi_done(&mut self, ifname: String, uuid: String, res: Result<(), zbus::Error>) {
        let Some(client) = self.wifi_pending.get(&ifname).filter(|p| p.uuid == uuid).map(|p| p.client) else { return };
        let can_ask = self.secret_client(Some(client)).is_some();
        let p = self.wifi_pending.get_mut(&ifname).expect("checked");
        self.dirty = true;
        match res {
            Ok(()) => {
                let p = self.wifi_pending.remove(&ifname).expect("checked");
                self.busy(p.client, &dev_path(&ifname), &p.label, false);
                self.ok(p.client, format!("Connected to {}", p.label));
                if p.secret_changed
                    && let Some(s) = self.store.profiles.get(&uuid) {
                        let _ = iwdfile::write(s, None);
                    }
                self.store.touch(&uuid);
                self.reasons.remove(&ifname);
            }
            Err(e) => {
                let (msg, code) = iwd::friendly(&e);
                tracing::info!("{ifname}: connecting to {} failed: {e}", p.label);
                let is_psk = self.store.profiles.get(&uuid).is_some_and(|s| iwdfile::ext_for(s) == Ok("psk"));
                if code == 8 && is_psk && !p.retried && can_ask {
                    // iwd asks its agent (us) for a new password on the next attempt.
                    p.retried = true;
                    if let (Some(i), Some(dev)) = (self.iwd.clone(), self.iw.device(&ifname).cloned()) {
                        let ssid = self.store.profiles.get(&uuid).and_then(ssid_of).map(|b| String::from_utf8_lossy(&b).to_string()).unwrap_or_default();
                        self.spawn_wifi_connect(i, dev.path, ifname, uuid, ssid, false);
                        return;
                    }
                }
                let p = self.wifi_pending.remove(&ifname).expect("checked");
                self.busy(p.client, &dev_path(&ifname), &p.label, false);
                if code != 39 {
                    self.reasons.insert(ifname.clone(), code);
                    if code == 4 {
                        self.err(p.client, format!("{}: {msg}", p.label));
                    }
                }
            }
        }
    }

    pub(super) fn on_agent(&mut self, network: String, ask: iwd::Ask, reply: oneshot::Sender<Option<Vec<String>>>) {
        let net = self.iw.networks.get(&network).cloned();
        let ifname = net.as_ref().and_then(|n| self.iw.devices.iter().find(|d| d.path == n.device)).map(|d| d.name.clone());
        let pending = ifname.as_ref().and_then(|i| self.wifi_pending.get(i));
        let client = pending.map(|p| p.client);
        let ssid = net.as_ref().map(|n| n.name.clone()).unwrap_or_default();
        let uuid = pending.map(|p| p.uuid.clone()).or_else(|| self.store.by_ssid(ssid.as_bytes()).first().map(|s| store::uuid(s)));
        let s = uuid.as_ref().and_then(|u| self.store.profiles.get(u));
        let (setting, key, user) = match &ask {
            iwd::Ask::Passphrase => ("802-11-wireless-security", "psk", None),
            iwd::Ask::PrivateKeyPassphrase => ("802-1x", "private-key-password", None),
            iwd::Ask::UserAndPassword => ("802-1x", "password", Some(s.map(|s| get_s(s, "802-1x", "identity")).unwrap_or_default())),
            iwd::Ask::Password(_) => ("802-1x", "password", None),
        };
        let retry = s.is_some_and(|s| !get_s(s, setting, key).is_empty());
        let conn_id = s.map(store::id).filter(|i| !i.is_empty()).unwrap_or_else(|| ssid.clone());
        if self.secret_client(client).is_none() {
            let _ = reply.send(None);
            return;
        }
        let req = SecretRequest { conn_id, setting: setting.into(), key: key.into(), retry };
        self.ask_secret(client, req, PendingSecret::Agent { reply, uuid, key: key.into(), user });
    }

    pub(super) async fn set_wifi(&mut self, client: u64, on: bool) {
        if !on {
            let hs: Vec<String> = self.actives.values().filter(|a| matches!(a.extra, Extra::Hotspot { .. })).map(|a| a.uuid.clone()).collect();
            for u in hs {
                self.deactivate(&u, 39).await;
            }
        }
        if let Err(e) = sys::set_rfkill("wlan", !on) {
            return self.err(client, format!("Wi-Fi radio: {e}"));
        }
        if on && let Some(i) = self.iwd.clone() {
            // iwd brings adapters back after an unblock, but not always powered.
            tokio::time::sleep(Duration::from_millis(400)).await;
            if let Ok(st) = i.state().await {
                for (path, a) in &st.adapters {
                    if !a.powered {
                        let _ = i.set_powered(path, true, true).await;
                    }
                }
                for d in &st.devices {
                    if !d.powered {
                        let _ = i.set_powered(&d.path, false, true).await;
                    }
                }
            }
        }
        self.refresh_iwd = true;
    }

    /// Connect each idle station to the best saved network in range (iwd
    /// stops auto-connecting after an explicit disconnect).
    pub(super) async fn wifi_autoconnect(&mut self) {
        let mut todo = Vec::new();
        for dev in &self.iw.devices {
            if self.iw.stations.get(&dev.path).is_none_or(|s| s.state != "disconnected") || self.store.state.unmanaged.contains(&dev.name) {
                continue;
            }
            let best = self.signals.get(&dev.name).into_iter().flatten().find_map(|(np, _)| {
                let n = self.iw.networks.get(np)?;
                self.store.by_ssid(n.name.as_bytes()).into_iter().find(|s| store::autoconnect(s)).cloned()
            });
            if let Some(s) = best {
                todo.push((dev.name.clone(), s));
            }
        }
        for (ifname, s) in todo {
            let label = store::id(&s);
            self.connect_profile_wifi(0, ifname, s, label, false).await;
        }
    }

    pub(super) async fn wifi_disconnect(&mut self, ifname: &str) {
        if let Some(p) = self.wifi_pending.remove(ifname) {
            self.busy(p.client, &dev_path(ifname), &p.label, false);
        }
        if let (Some(i), Some(dev)) = (self.iwd.clone(), self.iw.device(ifname).cloned())
            && self.iw.stations.contains_key(&dev.path) {
                let _ = i.disconnect(&dev.path).await;
            }
        self.reasons.insert(ifname.to_string(), 39);
        self.refresh_iwd = true;
    }

    pub(super) fn hotspot_on(&self, ifname: &str) -> Option<String> {
        self.actives.values().find(|a| a.iface == ifname && store::kind_is_hotspot(&self.store, &a.uuid)).map(|a| a.uuid.clone())
    }

    pub(super) fn start_hotspot(&mut self, client: u64, s: Settings, ifname: String, label: String) {
        let Some(i) = self.iwd.clone() else { return self.err(client, "iwd isn't running") };
        let Some(dev) = self.iw.device(&ifname).cloned() else { return self.err(client, format!("{ifname}: not a Wi-Fi device")) };
        let ssid = match iwdfile::write_ap(&s, HOTSPOT_ADDR) {
            Ok(n) => n,
            Err(e) => return self.err(client, format!("{label}: {e}")),
        };
        if let Some(p) = self.wifi_pending.remove(&ifname) {
            self.busy(p.client, &dev_path(&ifname), &p.label, false);
        }
        let uuid = store::uuid(&s);
        self.busy(client, &prof_path(&uuid), &label, true);
        self.actives.insert(
            uuid.clone(),
            Active { uuid: uuid.clone(), kind: store::kind(&s), iface: ifname.clone(), state: 1, task: None, client, label, extra: Extra::None, lease: None },
        );
        let tx = self.tx.clone();
        tokio::spawn(async move {
            let res = async {
                let fail = |e: zbus::Error| iwd::friendly(&e).0;
                i.set_mode(&dev.path, "ap").await.map_err(fail)?;
                for _ in 0..20 {
                    if i.state().await.is_ok_and(|st| st.aps.contains(&dev.path)) {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(150)).await;
                }
                if let Err(e) = i.ap_start_profile(&dev.path, &ssid).await {
                    let _ = i.set_mode(&dev.path, "station").await;
                    return Err(fail(e));
                }
                let prev = link::read_sys("/proc/sys/net/ipv4/ip_forward");
                let _ = link::sysctl("net/ipv4/ip_forward", "1");
                if let Err(e) = sys::nat_on(&ifname, HOTSPOT_NET).await {
                    tracing::warn!("hotspot NAT: {e}");
                    return Err(format!("the hotspot is up but can't share the connection: {e}"));
                }
                Ok(Extra::Hotspot { prev_forward: prev })
            }
            .await;
            let _ = tx.send(Internal::Activated { uuid, res });
        });
    }

    pub(super) async fn stop_hotspot(&mut self, a: &Active) {
        if let (Some(i), Some(dev)) = (self.iwd.clone(), self.iw.device(&a.iface).cloned()) {
            let _ = i.ap_stop(&dev.path).await;
            let _ = i.set_mode(&dev.path, "station").await;
        }
        sys::nat_off().await;
        if let Extra::Hotspot { prev_forward } = &a.extra
            && prev_forward == "0"
            && !self.actives.values().any(|o| matches!(o.extra, Extra::Hotspot { .. })) {
                let _ = link::sysctl("net/ipv4/ip_forward", "0");
            }
        self.refresh_iwd = true;
    }

    /// The device a saved Wi-Fi profile is connected (or connecting) with.
    pub(super) fn wifi_iface_for(&self, uuid: &str) -> Option<String> {
        let s = self.store.profiles.get(uuid)?;
        let ssid = ssid_of(s)?;
        self.iw.devices.iter().find(|d| self.iw.current_network(&d.name).is_some_and(|n| n.name.as_bytes() == ssid.as_slice())).map(|d| d.name.clone())
    }
}
