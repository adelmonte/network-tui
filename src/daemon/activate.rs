//! Bringing connections up and down: Ethernet with DHCP or static
//! addressing, VLANs, bridges, bonds, WireGuard and OpenVPN.

use std::net::IpAddr;

use futures::TryStreamExt;
use rtnetlink::packet_route::link::BondMode;
use rtnetlink::{LinkBond, LinkBridge, LinkVlan, LinkWireguard};

use crate::backend::form;
use crate::backend::model::kind_label;
use crate::backend::val::{Dict, DictExt, Settings, Val};
use crate::backend::SecretRequest;

use super::store::{self, get_s};
use super::{dhcp, link, prof_path, sys, vpn, wg, Active, Daemon, Extra, Internal, PendingSecret};

/// Default route metrics: wired beats Wi-Fi (iwd uses 300 and up).
const METRIC_WIRED: u32 = 100;
const METRIC_VIRTUAL: u32 = 50;

fn route_metric(s: &Settings, v6: bool, default: u32) -> u32 {
    let m = s.get(if v6 { "ipv6" } else { "ipv4" }).map(|d| d.i("route-metric")).unwrap_or(-1);
    if m >= 0 { m as u32 } else { default }
}

fn addresses(s: &Settings, v6: bool) -> Vec<(IpAddr, u8)> {
    s.get(if v6 { "ipv6" } else { "ipv4" })
        .and_then(|d| d.get("address-data"))
        .map(|v| v.dict_list().iter().filter_map(|a| Some((a.s("address").parse().ok()?, a.u("prefix") as u8))).collect())
        .unwrap_or_default()
}

fn static_routes(s: &Settings, v6: bool) -> Vec<(IpAddr, u8, Option<IpAddr>, u32)> {
    s.get(if v6 { "ipv6" } else { "ipv4" })
        .and_then(|d| d.get("route-data"))
        .map(|v| {
            v.dict_list()
                .iter()
                .filter_map(|r| Some((r.s("dest").parse().ok()?, r.u("prefix") as u8, r.s("next-hop").parse().ok(), r.u("metric"))))
                .collect()
        })
        .unwrap_or_default()
}

async fn index_of(nl: &rtnetlink::Handle, name: &str) -> Option<u32> {
    nl.link().get().match_name(name.to_string()).execute().try_next().await.ok().flatten().map(|m| m.header.index)
}

fn bond_mode(m: &str) -> BondMode {
    match m {
        "balance-rr" | "0" => BondMode::BalanceRr,
        "balance-xor" | "2" => BondMode::BalanceXor,
        "broadcast" | "3" => BondMode::Broadcast,
        "802.3ad" | "4" => BondMode::Ieee8023Ad,
        "balance-tlb" | "5" => BondMode::BalanceTlb,
        "balance-alb" | "6" => BondMode::BalanceAlb,
        _ => BondMode::ActiveBackup,
    }
}

fn bond_opts(s: &Settings) -> std::collections::BTreeMap<String, String> {
    match s.get("bond").and_then(|b| b.get("options")) {
        Some(Val::StrMap(m)) => m.clone(),
        _ => Default::default(),
    }
}

/// Create (or reuse) the kernel device for a virtual connection.
async fn create_virtual(nl: rtnetlink::Handle, s: Settings, ifname: String, parent: Option<u32>, ports: Vec<u32>) -> Result<Extra, String> {
    let ne = |e: rtnetlink::Error| e.to_string();
    let existing = index_of(&nl, &ifname).await;
    match store::kind(&s).as_str() {
        "wireguard" => {
            let mut cfg = wg::from_settings(&s).await?;
            let (full4, full6) = (cfg.full_tunnel(false), cfg.full_tunnel(true));
            if (full4 || full6) && cfg.fwmark == 0 {
                cfg.fwmark = wg::TABLE;
            }
            if let Some(i) = existing {
                link::delete(&nl, i).await.map_err(ne)?;
            }
            link::add_link(&nl, LinkWireguard::new(&ifname).build()).await.map_err(|e| format!("creating {ifname}: {e} (is the wireguard module available?)"))?;
            let index = index_of(&nl, &ifname).await.ok_or("the WireGuard device vanished")?;
            let res = async {
                wg::configure(&ifname, &cfg).await?;
                let mtu = s.get("wireguard").map(|w| w.u("mtu")).filter(|m| *m > 0).unwrap_or(1420);
                link::set_mtu(&nl, index, mtu).await.map_err(ne)?;
                for v6 in [false, true] {
                    for (ip, pfx) in addresses(&s, v6) {
                        link::add_addr(&nl, index, ip, pfx).await.map_err(ne)?;
                    }
                }
                link::set_up(&nl, index, true).await.map_err(ne)?;
                for p in &cfg.peers {
                    for (ip, pfx) in &p.allowed {
                        let table = if *pfx == 0 { wg::TABLE } else { 254 };
                        let net = mask(*ip, *pfx);
                        link::add_route(&nl, link::route_msg(index, net, *pfx, None, 0, table)).await.map_err(ne)?;
                    }
                }
                for (ip, pfx, gw, m) in static_routes(&s, false).into_iter().chain(static_routes(&s, true)) {
                    link::add_route(&nl, link::route_msg(index, ip, pfx, gw, m, 254)).await.map_err(ne)?;
                }
                if full4 {
                    wg::add_rules(&nl, false).await?;
                }
                if full6 {
                    wg::add_rules(&nl, true).await?;
                }
                Ok::<_, String>(())
            }
            .await;
            if let Err(e) = res {
                let _ = link::delete(&nl, index).await;
                wg::del_rules(&nl).await;
                return Err(e);
            }
            Ok(Extra::Wg { full4, full6 })
        }
        "vlan" => {
            if existing.is_none() {
                let parent = parent.ok_or("the VLAN's parent interface doesn't exist")?;
                let id = s.get("vlan").map(|v| v.u("id")).unwrap_or(0);
                if !(1..4095).contains(&id) {
                    return Err("VLAN id must be 1–4094".into());
                }
                link::set_up(&nl, parent, true).await.map_err(ne)?;
                link::add_link(&nl, LinkVlan::new(&ifname, parent, id as u16).build()).await.map_err(ne)?;
            }
            Ok(Extra::None)
        }
        "bridge" => {
            if existing.is_none() {
                link::add_link(&nl, LinkBridge::new(&ifname).build()).await.map_err(ne)?;
            }
            let b = s.get("bridge").cloned().unwrap_or_default();
            let stp = b.opt_b("stp").unwrap_or(true);
            let _ = std::fs::write(format!("/sys/class/net/{ifname}/bridge/stp_state"), if stp { "1" } else { "0" });
            if b.contains_key("priority") {
                let _ = std::fs::write(format!("/sys/class/net/{ifname}/bridge/priority"), b.u("priority").to_string());
            }
            attach_ports(&nl, &ifname, &ports, false).await?;
            Ok(Extra::None)
        }
        "bond" => {
            if existing.is_none() {
                let o = bond_opts(&s);
                let miimon = o.get("miimon").and_then(|m| m.parse().ok()).unwrap_or(100);
                let msg = LinkBond::new(&ifname).mode(bond_mode(o.get("mode").map(String::as_str).unwrap_or(""))).miimon(miimon).build();
                link::add_link(&nl, msg).await.map_err(ne)?;
            }
            attach_ports(&nl, &ifname, &ports, true).await?;
            Ok(Extra::None)
        }
        k => Err(format!("can't create {} devices", kind_label(k))),
    }
}

async fn attach_ports(nl: &rtnetlink::Handle, ifname: &str, ports: &[u32], down_first: bool) -> Result<(), String> {
    let ctrl = index_of(nl, ifname).await.ok_or_else(|| format!("{ifname} vanished"))?;
    for p in ports {
        if down_first {
            let _ = link::set_up(nl, *p, false).await;
        }
        link::set_controller(nl, *p, Some(ctrl)).await.map_err(|e| e.to_string())?;
        link::set_up(nl, *p, true).await.map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// The network address of `ip/prefix` (the kernel rejects host bits in routes).
fn mask(ip: IpAddr, prefix: u8) -> IpAddr {
    match ip {
        IpAddr::V4(a) => {
            let m = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix.min(32)) };
            IpAddr::V4((u32::from(a) & m).into())
        }
        IpAddr::V6(a) => {
            let m = if prefix == 0 { 0 } else { u128::MAX << (128 - prefix.min(128) as u32) };
            IpAddr::V6((u128::from(a) & m).into())
        }
    }
}

impl Daemon {
    pub(super) async fn activate(&mut self, client: u64, s: Settings, dev: Option<String>, label: String) {
        if !self.store.state.networking {
            return self.err(client, "Networking is disabled");
        }
        let uuid = store::uuid(&s);
        let kind = store::kind(&s);
        if self.actives.get(&uuid).is_some_and(|a| a.state >= 1) {
            return self.info(client, format!("{label} is already active"));
        }
        let bound = store::iface(&s);
        let dev = dev.filter(|d| !d.is_empty()).or_else(|| (!bound.is_empty()).then(|| bound.clone()));
        match kind.as_str() {
            "802-11-wireless" => {
                let Some(ifname) = dev.or_else(|| self.iw.devices.first().map(|d| d.name.clone())) else {
                    return self.err(client, "No Wi-Fi device");
                };
                if store::is_hotspot(&s) {
                    self.start_hotspot(client, s, ifname, label);
                } else {
                    self.connect_profile_wifi(client, ifname, s, label, false).await;
                }
            }
            "802-3-ethernet" => {
                if !get_s(&s, "connection", "master").is_empty() {
                    return self.info(client, format!("{label} is a port of a bridge or bond — activate that instead"));
                }
                let ifname = dev.or_else(|| {
                    self.links
                        .links
                        .values()
                        .filter(|l| l.kind == "ether" && !self.store.state.unmanaged.contains(&l.name))
                        .max_by_key(|l| l.carrier)
                        .map(|l| l.name.clone())
                });
                let Some(ifname) = ifname else { return self.err(client, "No Ethernet device") };
                self.deactivate_iface(&ifname).await;
                self.wired_blocked.remove(&ifname);
                self.start_l3(client, s, ifname, label).await;
            }
            "wireguard" | "vlan" | "bridge" | "bond" => self.activate_virtual(client, s, dev, label),
            "vpn" => self.activate_vpn(client, s, label),
            k => self.err(client, format!("{label}: {} connections aren't supported", kind_label(k))),
        }
    }

    fn insert_active(&mut self, client: u64, s: &Settings, iface: &str, label: &str) -> String {
        let uuid = store::uuid(s);
        self.busy(client, &prof_path(&uuid), label, true);
        self.actives.insert(
            uuid.clone(),
            Active { uuid: uuid.clone(), kind: store::kind(s), iface: iface.to_string(), state: 1, task: None, client, label: label.to_string(), extra: Extra::None, lease: None },
        );
        self.dirty = true;
        uuid
    }

    fn activate_virtual(&mut self, client: u64, s: Settings, dev: Option<String>, label: String) {
        let kind = store::kind(&s);
        let ifname = dev.unwrap_or_else(|| match kind.as_str() {
            "wireguard" => "wg0".into(),
            "bridge" => "br0".into(),
            "bond" => "bond0".into(),
            _ => {
                let v = s.get("vlan").cloned().unwrap_or_default();
                format!("{}.{}", self.vlan_parent(&v), v.u("id"))
            }
        });
        if ifname.len() > 15 {
            return self.err(client, format!("{label}: interface name “{ifname}” is too long (15 characters max)"));
        }
        let parent = (kind == "vlan").then(|| self.links.index(&self.vlan_parent(&s.get("vlan").cloned().unwrap_or_default()))).flatten();
        let uuid = store::uuid(&s);
        let ports: Vec<u32> = self
            .store
            .profiles
            .values()
            .filter(|p| {
                let m = get_s(p, "connection", "master");
                !m.is_empty() && (m == ifname || m == uuid) && store::autoconnect(p)
            })
            .filter_map(|p| self.links.index(&store::iface(p)))
            .collect();
        let uuid = self.insert_active(client, &s, &ifname, &label);
        let (nl, tx) = (self.nl.clone(), self.tx.clone());
        tokio::spawn(async move {
            let res = create_virtual(nl, s, ifname, parent, ports).await;
            let _ = tx.send(Internal::Activated { uuid, res });
        });
    }

    /// A VLAN's parent may be named by interface or by profile UUID.
    fn vlan_parent(&self, v: &Dict) -> String {
        let p = v.s("parent");
        match self.store.profiles.get(&p) {
            Some(s) => store::iface(s),
            None => p,
        }
    }

    fn activate_vpn(&mut self, client: u64, s: Settings, label: String) {
        let config = vpn::data(&s, "config");
        if config.is_empty() || !std::path::Path::new(&config).exists() {
            return self.err(client, format!("{label}: the OpenVPN config file is missing"));
        }
        let uuid = self.insert_active(client, &s, "", &label);
        let mut auth = None;
        if vpn::wants_auth(std::path::Path::new(&config)) {
            let (user, pass) = (vpn::data(&s, "username"), vpn::secret(&s, "password"));
            let missing = if user.is_empty() {
                Some("username")
            } else if pass.is_empty() {
                Some("password")
            } else {
                None
            };
            if let Some(key) = missing {
                let req = SecretRequest { conn_id: label.clone(), setting: "vpn".into(), key: key.into(), retry: false };
                if !self.ask_secret(Some(client), req, PendingSecret::Vpn { uuid: uuid.clone(), key: key.into() }) {
                    self.fail_activation(&uuid, "needs a username and password".into(), 7);
                }
                return;
            }
            auth = Some((user, pass));
        }
        let task = vpn::spawn(uuid.clone(), config, auth, self.tx.clone());
        if let Some(a) = self.actives.get_mut(&uuid) {
            a.task = Some(task);
        }
    }

    pub(super) fn on_vpn(&mut self, uuid: String, ev: vpn::VpnEv) {
        let Some(a) = self.actives.get_mut(&uuid) else { return };
        self.dirty = true;
        match ev {
            vpn::VpnEv::Started(pid) => a.extra = Extra::Vpn { pid: Some(pid) },
            vpn::VpnEv::Device(d) => a.iface = d,
            vpn::VpnEv::Up => self.finish_activation(&uuid),
            vpn::VpnEv::Down(reason) => {
                let a = self.actives.remove(&uuid).expect("checked");
                if a.state == 1 {
                    self.busy(a.client, &prof_path(&uuid), &a.label, false);
                    self.err(a.client, format!("{}: {reason}", a.label));
                } else {
                    let msg = format!("{} disconnected: {reason}", a.label);
                    for c in self.clients.keys() {
                        self.info(*c, msg.clone());
                    }
                }
            }
        }
    }

    /// IP configuration for a wired-style interface; the connection becomes
    /// active once it has an address (now for static, later for DHCP).
    pub(super) async fn start_l3(&mut self, client: u64, s: Settings, ifname: String, label: String) {
        let uuid = self.insert_active(client, &s, &ifname, &label);
        self.configure_ip(&uuid).await;
    }

    pub(super) async fn configure_ip(&mut self, uuid: &str) {
        let Some(a) = self.actives.get(uuid) else { return };
        let ifname = a.iface.clone();
        let Some(s) = self.store.profiles.get(uuid).cloned() else { return };
        let Some(l) = self.links.by_name(&ifname).cloned() else {
            return self.fail_activation(uuid, format!("{ifname} doesn't exist"), 4);
        };
        let res = self.configure_link(&s, &l).await;
        if let Err(e) = res {
            return self.fail_activation(uuid, e, 4);
        }
        let v4 = get_s(&s, "ipv4", "method");
        match v4.as_str() {
            "auto" | "" => {
                let mac = form::parse_mac(&l.mac).unwrap_or_default();
                let task = dhcp::spawn(ifname, mac, sys::hostname(), self.tx.clone());
                if let Some(a) = self.actives.get_mut(uuid) {
                    a.task = Some(task);
                }
            }
            "shared" => self.fail_activation(uuid, "sharing over Ethernet isn't supported yet".into(), 4),
            _ => {
                self.apply_static_routes(&s, l.index).await;
                self.finish_activation(uuid);
            }
        }
    }

    async fn configure_link(&mut self, s: &Settings, l: &link::Link) -> Result<(), String> {
        let ne = |e: rtnetlink::Error| e.to_string();
        let nl = self.nl.clone();
        let eth = s.get("802-3-ethernet").cloned().unwrap_or_default();
        if let Some(mac) = form::parse_mac(&eth.s("assigned-mac-address"))
            && !l.mac.eq_ignore_ascii_case(&eth.s("assigned-mac-address")) {
                let _ = link::set_up(&nl, l.index, false).await;
                link::set_mac(&nl, l.index, mac).await.map_err(ne)?;
            }
        if eth.u("mtu") > 0 {
            link::set_mtu(&nl, l.index, eth.u("mtu")).await.map_err(ne)?;
        }
        link::set_up(&nl, l.index, true).await.map_err(ne)?;

        let v6 = get_s(s, "ipv6", "method");
        let conf = format!("net/ipv6/conf/{}", l.name);
        match v6.as_str() {
            "disabled" => {
                let _ = link::sysctl(&format!("{conf}/disable_ipv6"), "1");
            }
            "ignore" => {}
            m => {
                let _ = link::sysctl(&format!("{conf}/disable_ipv6"), "0");
                let _ = link::sysctl(&format!("{conf}/accept_ra"), if m == "manual" { "0" } else { "2" });
                if let p @ 0..=2 = s.get("ipv6").map(|d| d.i("ip6-privacy")).unwrap_or(-1) {
                    let _ = link::sysctl(&format!("{conf}/use_tempaddr"), &p.to_string());
                }
                if m == "manual" {
                    for (ip, pfx) in addresses(s, true) {
                        link::add_addr(&nl, l.index, ip, pfx).await.map_err(ne)?;
                    }
                    let gw = get_s(s, "ipv6", "gateway");
                    if let Ok(gw) = gw.parse::<IpAddr>()
                        && !s.get("ipv6").is_some_and(|d| d.b("never-default")) {
                            let dflt: IpAddr = std::net::Ipv6Addr::UNSPECIFIED.into();
                            link::add_route(&nl, link::route_msg(l.index, dflt, 0, Some(gw), route_metric(s, true, METRIC_WIRED), 254)).await.map_err(ne)?;
                        }
                }
            }
        }

        if get_s(s, "ipv4", "method") == "manual" {
            link::flush_addrs(&nl, l.index, Some(false)).await.map_err(ne)?;
            for (ip, pfx) in addresses(s, false) {
                link::add_addr(&nl, l.index, ip, pfx).await.map_err(ne)?;
            }
            let gw = get_s(s, "ipv4", "gateway");
            if let Ok(gw) = gw.parse::<IpAddr>()
                && !s.get("ipv4").is_some_and(|d| d.b("never-default")) {
                    let dflt: IpAddr = std::net::Ipv4Addr::UNSPECIFIED.into();
                    let metric = route_metric(s, false, if l.kind == "ether" { METRIC_WIRED } else { METRIC_VIRTUAL });
                    link::add_route(&nl, link::route_msg(l.index, dflt, 0, Some(gw), metric, 254)).await.map_err(ne)?;
                }
        }
        Ok(())
    }

    async fn apply_static_routes(&self, s: &Settings, index: u32) {
        for v6 in [false, true] {
            for (ip, pfx, gw, m) in static_routes(s, v6) {
                if let Err(e) = link::add_route(&self.nl, link::route_msg(index, mask(ip, pfx), pfx, gw, m, 254)).await {
                    tracing::warn!("route {ip}/{pfx}: {e}");
                }
            }
        }
    }

    pub(super) async fn on_dhcp(&mut self, iface: String, ev: dhcp::DhcpEv) {
        let Some(uuid) = self.actives.values().find(|a| a.iface == iface && a.task.is_some()).map(|a| a.uuid.clone()) else { return };
        let Some(s) = self.store.profiles.get(&uuid).cloned() else { return };
        let Some(index) = self.links.index(&iface) else { return };
        self.dirty = true;
        match ev {
            dhcp::DhcpEv::Bound(lease) => {
                let nl = self.nl.clone();
                let v4 = s.get("ipv4").cloned().unwrap_or_default();
                let old = self.actives.get(&uuid).and_then(|a| a.lease.clone());
                if old.as_ref().is_some_and(|o| o.addr != lease.addr || o.prefix != lease.prefix) {
                    let _ = link::flush_routes(&nl, index).await;
                    let _ = link::flush_addrs(&nl, index, Some(false)).await;
                }
                if let Err(e) = link::add_addr(&nl, index, lease.addr.into(), lease.prefix).await {
                    tracing::warn!("{iface}: adding {}: {e}", lease.addr);
                }
                // Extra addresses from the profile alongside the lease.
                for (ip, pfx) in addresses(&s, false) {
                    let _ = link::add_addr(&nl, index, ip, pfx).await;
                }
                let metric = route_metric(&s, false, METRIC_WIRED);
                let classless = !v4.b("ignore-auto-routes") && !lease.routes.is_empty();
                if classless {
                    // RFC 3442: with classless routes, the router option is ignored.
                    for (d, p, gw) in &lease.routes {
                        if *p == 0 && v4.b("never-default") {
                            continue;
                        }
                        let gw = (!gw.is_unspecified()).then_some(IpAddr::V4(*gw));
                        let _ = link::add_route(&nl, link::route_msg(index, IpAddr::V4(*d), *p, gw, metric, 254)).await;
                    }
                } else if let Some(r) = lease.router
                    && !v4.b("never-default") {
                        let dflt: IpAddr = std::net::Ipv4Addr::UNSPECIFIED.into();
                        let _ = link::add_route(&nl, link::route_msg(index, dflt, 0, Some(r.into()), metric, 254)).await;
                    }
                if let Some(m) = lease.mtu
                    && m >= 576
                    && get_s(&s, "802-3-ethernet", "mtu").is_empty()
                    && s.get("802-3-ethernet").is_none_or(|e| e.u("mtu") == 0) {
                        let _ = link::set_mtu(&nl, index, m as u32).await;
                    }
                self.apply_static_routes(&s, index).await;
                let first = self.actives.get(&uuid).is_some_and(|a| a.state == 1);
                if let Some(a) = self.actives.get_mut(&uuid) {
                    a.lease = Some(lease);
                }
                if first {
                    self.finish_activation(&uuid);
                }
            }
            dhcp::DhcpEv::Lost(msg) => {
                let Some(a) = self.actives.get_mut(&uuid) else { return };
                let (client, label, was) = (a.client, a.label.clone(), a.state);
                a.state = 1;
                a.lease = None;
                if was == 2 {
                    let _ = link::flush_routes(&self.nl, index).await;
                    let _ = link::flush_addrs(&self.nl, index, Some(false)).await;
                }
                self.reasons.insert(iface, 17);
                self.err(client, format!("{label}: {msg} — still trying"));
            }
        }
    }

    pub(super) async fn on_activated(&mut self, uuid: String, res: Result<Extra, String>) {
        let Some(a) = self.actives.get_mut(&uuid) else { return };
        self.dirty = true;
        match res {
            Ok(extra) => {
                a.extra = extra;
                if matches!(a.kind.as_str(), "vlan" | "bridge" | "bond") {
                    self.refresh_links_now().await;
                    self.configure_ip(&uuid).await;
                } else {
                    self.finish_activation(&uuid);
                }
            }
            Err(e) => self.fail_activation(&uuid, e, 4),
        }
    }

    async fn refresh_links_now(&mut self) {
        if let Ok(l) = link::dump(&self.nl).await {
            self.links = l;
        }
    }

    pub(super) fn finish_activation(&mut self, uuid: &str) {
        let Some(a) = self.actives.get_mut(uuid) else { return };
        a.state = 2;
        let (client, label, iface) = (a.client, a.label.clone(), a.iface.clone());
        let msg = if matches!(a.extra, Extra::Hotspot { .. }) { format!("Hotspot {label} is up") } else { format!("Connected {label}") };
        self.busy(client, &prof_path(uuid), &label, false);
        self.ok(client, msg);
        self.reasons.remove(&iface);
        self.store.touch(uuid);
        self.dirty = true;
    }

    pub(super) fn fail_activation(&mut self, uuid: &str, msg: String, code: u32) {
        let Some(mut a) = self.actives.remove(uuid) else { return };
        if let Some(t) = a.task.take() {
            t.abort();
        }
        self.busy(a.client, &prof_path(uuid), &a.label, false);
        self.err(a.client, format!("{}: {msg}", a.label));
        if !a.iface.is_empty() {
            self.reasons.insert(a.iface.clone(), code);
        }
        self.dirty = true;
    }

    /// Take a connection down. Returns false if it wasn't active.
    pub(super) async fn deactivate(&mut self, uuid: &str, reason: u32) -> bool {
        let Some(mut a) = self.actives.remove(uuid) else {
            if let Some(ifname) = self.wifi_pending.iter().find(|(_, p)| p.uuid == uuid).map(|(i, _)| i.clone()).or_else(|| self.wifi_iface_for(uuid)) {
                self.wifi_disconnect(&ifname).await;
                return true;
            }
            return false;
        };
        self.dirty = true;
        if a.state == 1 {
            self.busy(a.client, &prof_path(uuid), &a.label, false);
        }
        let nl = self.nl.clone();
        let index = self.links.index(&a.iface);
        match a.kind.as_str() {
            "802-3-ethernet" => {
                if let Some(t) = a.task.take() {
                    t.abort();
                }
                if let Some(i) = index {
                    let _ = link::flush_routes(&nl, i).await;
                    let _ = link::flush_addrs(&nl, i, None).await;
                }
                if reason == 39 {
                    self.wired_blocked.insert(a.iface.clone());
                }
            }
            "wireguard" | "vlan" | "bridge" | "bond" => {
                if let Some(t) = a.task.take() {
                    t.abort();
                }
                if let Some(i) = index {
                    let _ = link::delete(&nl, i).await;
                }
                if matches!(a.extra, Extra::Wg { full4: true, .. } | Extra::Wg { full6: true, .. }) {
                    wg::del_rules(&nl).await;
                }
            }
            "vpn" => match a.extra {
                // Let openvpn tear down its own routes; its task reports the exit.
                Extra::Vpn { pid: Some(pid) } => unsafe {
                    libc::kill(pid as i32, libc::SIGTERM);
                },
                _ => {
                    if let Some(t) = a.task.take() {
                        t.abort();
                    }
                }
            },
            "802-11-wireless" => self.stop_hotspot(&a).await,
            _ => {}
        }
        if !a.iface.is_empty() {
            self.reasons.insert(a.iface.clone(), reason);
        }
        true
    }

    pub(super) async fn deactivate_iface(&mut self, ifname: &str) {
        let on: Vec<String> = self.actives.values().filter(|a| a.iface == ifname).map(|a| a.uuid.clone()).collect();
        for u in on {
            self.deactivate(&u, 39).await;
        }
    }

    pub(super) async fn disconnect_device(&mut self, ifname: &str) {
        if self.iw.device(ifname).is_some() && self.hotspot_on(ifname).is_none() {
            self.wifi_disconnect(ifname).await;
        } else {
            self.deactivate_iface(ifname).await;
        }
        if self.links.by_name(ifname).is_some_and(|l| l.kind == "ether") {
            self.wired_blocked.insert(ifname.to_string());
        }
    }

    pub(super) async fn networking_off(&mut self) {
        let all: Vec<String> = self.actives.keys().cloned().collect();
        for u in all {
            self.deactivate(&u, 39).await;
        }
        let wifi: Vec<String> = self.iw.devices.iter().map(|d| d.name.clone()).collect();
        for w in wifi {
            self.wifi_disconnect(&w).await;
        }
    }

    /// Bring up a saved profile on every cabled, idle Ethernet port.
    pub(super) async fn autoconnect_wired(&mut self) {
        if !self.store.state.networking {
            return;
        }
        let st = &self.store.state;
        let idle: Vec<String> = self
            .links
            .links
            .values()
            .filter(|l| l.kind == "ether" && l.carrier && l.controller.is_none())
            .filter(|l| !st.unmanaged.contains(&l.name) && !st.no_autoconnect.contains(&l.name) && !self.wired_blocked.contains(&l.name))
            .filter(|l| !self.actives.values().any(|a| a.iface == l.name))
            .map(|l| l.name.clone())
            .collect();
        for ifname in idle {
            let mut cands: Vec<&Settings> = self
                .store
                .profiles
                .values()
                .filter(|s| store::kind(s) == "802-3-ethernet" && store::autoconnect(s) && get_s(s, "connection", "master").is_empty())
                .filter(|s| {
                    let i = store::iface(s);
                    i.is_empty() || i == ifname
                })
                .collect();
            cands.sort_by_key(|s| {
                let c = store::conn(s);
                (std::cmp::Reverse(c.i("autoconnect-priority")), std::cmp::Reverse(c.i("timestamp")))
            });
            let s = match cands.first() {
                Some(s) => (*s).clone(),
                None => {
                    self.store.state.wired_counter += 1;
                    self.store.save_state();
                    let mut s = form::new_settings("802-3-ethernet", &format!("Wired connection {}", self.store.state.wired_counter));
                    s.get_mut("connection").expect("set").insert("interface-name".into(), Val::Str(ifname.clone()));
                    if let Err(e) = self.store.put(s.clone()) {
                        tracing::warn!("saving a wired profile: {e}");
                    }
                    s
                }
            };
            let label = store::id(&s);
            tracing::info!("{ifname}: cable connected, activating {label}");
            self.start_l3(0, s, ifname, label).await;
        }
    }

    /// Bring up virtual connections marked auto-connect (at startup and
    /// when networking is switched back on).
    pub(super) async fn autoconnect_virtual(&mut self) {
        if !self.store.state.networking {
            return;
        }
        let order = |k: &str| match k {
            "bridge" | "bond" => 0,
            "vlan" => 1,
            _ => 2,
        };
        let mut todo: Vec<Settings> = self
            .store
            .profiles
            .values()
            .filter(|s| matches!(store::kind(s).as_str(), "bridge" | "bond" | "vlan" | "wireguard") && store::autoconnect(s))
            .filter(|s| !self.actives.contains_key(&store::uuid(s)))
            .cloned()
            .collect();
        todo.sort_by_key(|s| order(&store::kind(s)));
        for s in todo {
            let label = store::id(&s);
            self.activate(0, s, None, label).await;
        }
    }
}
