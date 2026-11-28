//! Kernel network state over rtnetlink: interfaces, addresses and routes,
//! plus the changes the daemon makes to them.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use futures::TryStreamExt;
use rtnetlink::packet_route::address::{AddressAttribute, AddressMessage};
use rtnetlink::packet_route::link::{InfoKind, LinkAttribute, LinkFlags, LinkInfo, LinkLayerType, LinkMessage};
use rtnetlink::packet_route::route::{RouteAddress, RouteAttribute, RouteMessage, RouteProtocol, RouteScope, RouteType};
use rtnetlink::packet_route::AddressFamily;
use rtnetlink::{Handle, LinkUnspec, MulticastGroup, RouteMessageBuilder};
use tokio::sync::mpsc::UnboundedSender;

use super::Internal;

/// Routes we install are tagged with this protocol number so we can find them again.
pub const PROTO: u8 = 99;

#[derive(Clone, Debug, PartialEq)]
pub struct Link {
    pub index: u32,
    pub name: String,
    /// "ether", "wlan", "wireguard", "bridge", "bond", "vlan", "tun", "loopback", or the kernel kind.
    pub kind: String,
    pub mac: String,
    pub perm_mac: String,
    pub mtu: u32,
    pub up: bool,
    pub carrier: bool,
    pub controller: Option<u32>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Addr {
    pub index: u32,
    pub ip: IpAddr,
    pub prefix: u8,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Route {
    pub index: u32,
    pub dest: IpAddr,
    pub prefix: u8,
    pub gateway: Option<IpAddr>,
    pub metric: u32,
    pub table: u32,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Links {
    pub links: BTreeMap<u32, Link>,
    pub addrs: Vec<Addr>,
    pub routes: Vec<Route>,
}

impl Links {
    pub fn by_name(&self, name: &str) -> Option<&Link> {
        self.links.values().find(|l| l.name == name)
    }

    pub fn index(&self, name: &str) -> Option<u32> {
        self.by_name(name).map(|l| l.index)
    }

    pub fn addrs_of(&self, index: u32, v6: bool) -> Vec<String> {
        self.addrs.iter().filter(|a| a.index == index && a.ip.is_ipv6() == v6).map(|a| format!("{}/{}", a.ip, a.prefix)).collect()
    }

    /// Default route through this interface (main table), lowest metric first.
    pub fn default_route(&self, index: u32, v6: bool) -> Option<&Route> {
        self.routes.iter().filter(|r| r.index == index && r.prefix == 0 && r.dest.is_ipv6() == v6 && r.table == 254).min_by_key(|r| r.metric)
    }

    /// The interface carrying the system's preferred IPv4 default route.
    pub fn primary(&self) -> Option<u32> {
        self.routes.iter().filter(|r| r.prefix == 0 && r.dest.is_ipv4() && r.table == 254).min_by_key(|r| r.metric).map(|r| r.index)
    }
}

fn mac_str(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02X}")).collect::<Vec<_>>().join(":")
}

fn parse_link(m: &LinkMessage) -> Link {
    let mut l = Link {
        index: m.header.index,
        name: String::new(),
        kind: String::new(),
        mac: String::new(),
        perm_mac: String::new(),
        mtu: 0,
        up: m.header.flags.contains(LinkFlags::Up),
        carrier: m.header.flags.contains(LinkFlags::LowerUp),
        controller: None,
    };
    for a in &m.attributes {
        match a {
            LinkAttribute::IfName(n) => l.name = n.clone(),
            LinkAttribute::Address(b) => l.mac = mac_str(b),
            LinkAttribute::PermAddress(b) => l.perm_mac = mac_str(b),
            LinkAttribute::Mtu(v) => l.mtu = *v,
            LinkAttribute::Controller(c) => l.controller = Some(*c),
            LinkAttribute::LinkInfo(infos) => {
                for i in infos {
                    if let LinkInfo::Kind(k) = i {
                        l.kind = match k {
                            InfoKind::Wireguard => "wireguard".into(),
                            InfoKind::Bridge => "bridge".into(),
                            InfoKind::Bond => "bond".into(),
                            InfoKind::Vlan => "vlan".into(),
                            InfoKind::Tun => "tun".into(),
                            other => other.to_string(),
                        };
                    }
                }
            }
            _ => {}
        }
    }
    if l.kind.is_empty() {
        l.kind = if m.header.link_layer_type == LinkLayerType::Loopback {
            "loopback".into()
        } else if std::path::Path::new(&format!("/sys/class/net/{}/wireless", l.name)).exists()
            || std::path::Path::new(&format!("/sys/class/net/{}/phy80211", l.name)).exists()
        {
            "wlan".into()
        } else if m.header.link_layer_type == LinkLayerType::Ether {
            "ether".into()
        } else if m.header.link_layer_type == LinkLayerType::None {
            "tun".into()
        } else {
            "other".into()
        };
    }
    l
}

fn parse_addr(m: &AddressMessage) -> Option<Addr> {
    let mut ip = None;
    for a in &m.attributes {
        match a {
            // For point-to-point links Local is ours and Address is the peer.
            AddressAttribute::Local(i) => ip = Some(*i),
            AddressAttribute::Address(i) if ip.is_none() => ip = Some(*i),
            _ => {}
        }
    }
    Some(Addr { index: m.header.index, ip: ip?, prefix: m.header.prefix_len })
}

fn route_ip(a: &RouteAddress) -> Option<IpAddr> {
    match a {
        RouteAddress::Inet(v) => Some(IpAddr::V4(*v)),
        RouteAddress::Inet6(v) => Some(IpAddr::V6(*v)),
        _ => None,
    }
}

fn parse_route(m: &RouteMessage) -> Option<Route> {
    if m.header.kind != RouteType::Unicast {
        return None;
    }
    let v6 = m.header.address_family == AddressFamily::Inet6;
    let mut r = Route {
        index: 0,
        dest: if v6 { IpAddr::V6(Ipv6Addr::UNSPECIFIED) } else { IpAddr::V4(Ipv4Addr::UNSPECIFIED) },
        prefix: m.header.destination_prefix_length,
        gateway: None,
        metric: 0,
        table: m.header.table as u32,
    };
    for a in &m.attributes {
        match a {
            RouteAttribute::Destination(d) => r.dest = route_ip(d)?,
            RouteAttribute::Gateway(g) => r.gateway = route_ip(g),
            RouteAttribute::Oif(i) => r.index = *i,
            RouteAttribute::Priority(p) => r.metric = *p,
            RouteAttribute::Table(t) => r.table = *t,
            _ => {}
        }
    }
    (r.index != 0).then_some(r)
}

pub fn connect() -> std::io::Result<Handle> {
    let (conn, handle, _) = rtnetlink::new_connection()?;
    tokio::spawn(conn);
    Ok(handle)
}

/// Nudge the daemon whenever links, addresses or routes change.
pub fn watch(tx: UnboundedSender<Internal>) -> std::io::Result<()> {
    let groups = [MulticastGroup::Link, MulticastGroup::Ipv4Ifaddr, MulticastGroup::Ipv6Ifaddr, MulticastGroup::Ipv4Route, MulticastGroup::Ipv6Route];
    let (conn, _handle, mut msgs) = rtnetlink::new_multicast_connection(&groups)?;
    tokio::spawn(conn);
    tokio::spawn(async move {
        while futures::StreamExt::next(&mut msgs).await.is_some() {
            if tx.send(Internal::LinksChanged).is_err() {
                break;
            }
        }
    });
    Ok(())
}

pub async fn dump(h: &Handle) -> Result<Links, rtnetlink::Error> {
    let mut out = Links::default();
    let mut s = h.link().get().execute();
    while let Some(m) = s.try_next().await? {
        let l = parse_link(&m);
        out.links.insert(l.index, l);
    }
    let mut s = h.address().get().execute();
    while let Some(m) = s.try_next().await? {
        if let Some(a) = parse_addr(&m) {
            out.addrs.push(a);
        }
    }
    for v6 in [false, true] {
        let msg = if v6 { RouteMessageBuilder::<Ipv6Addr>::new().build() } else { RouteMessageBuilder::<Ipv4Addr>::new().build() };
        let mut s = h.route().get(msg).execute();
        while let Some(m) = s.try_next().await? {
            if let Some(r) = parse_route(&m) {
                out.routes.push(r);
            }
        }
    }
    Ok(out)
}

pub async fn set_up(h: &Handle, index: u32, up: bool) -> Result<(), rtnetlink::Error> {
    let b = LinkUnspec::new_with_index(index);
    h.link().set(if up { b.up() } else { b.down() }.build()).execute().await
}

pub async fn set_mac(h: &Handle, index: u32, mac: [u8; 6]) -> Result<(), rtnetlink::Error> {
    h.link().set(LinkUnspec::new_with_index(index).address(mac.to_vec()).build()).execute().await
}

pub async fn set_mtu(h: &Handle, index: u32, mtu: u32) -> Result<(), rtnetlink::Error> {
    h.link().set(LinkUnspec::new_with_index(index).mtu(mtu).build()).execute().await
}

pub async fn set_controller(h: &Handle, index: u32, controller: Option<u32>) -> Result<(), rtnetlink::Error> {
    let b = LinkUnspec::new_with_index(index);
    let b = match controller {
        Some(c) => b.controller(c),
        None => b.nocontroller(),
    };
    h.link().set(b.build()).execute().await
}

pub async fn delete(h: &Handle, index: u32) -> Result<(), rtnetlink::Error> {
    h.link().del(index).execute().await
}

pub async fn add_link(h: &Handle, msg: LinkMessage) -> Result<(), rtnetlink::Error> {
    h.link().add(msg).execute().await
}

pub async fn add_addr(h: &Handle, index: u32, ip: IpAddr, prefix: u8) -> Result<(), rtnetlink::Error> {
    h.address().add(index, ip, prefix).replace().execute().await
}

/// Remove every address of one family from an interface.
pub async fn flush_addrs(h: &Handle, index: u32, v6: Option<bool>) -> Result<(), rtnetlink::Error> {
    let mut s = h.address().get().set_link_index_filter(index).execute();
    let mut del = Vec::new();
    while let Some(m) = s.try_next().await? {
        let is6 = m.header.family == AddressFamily::Inet6;
        if v6.is_none_or(|w| w == is6) && !(is6 && m.header.scope == rtnetlink::packet_route::address::AddressScope::Link) {
            del.push(m);
        }
    }
    for m in del {
        let _ = h.address().del(m).execute().await;
    }
    Ok(())
}

pub fn route_msg(index: u32, dest: IpAddr, prefix: u8, gateway: Option<IpAddr>, metric: u32, table: u32) -> RouteMessage {
    let mut b = RouteMessageBuilder::<IpAddr>::new();
    b = b.destination_prefix(dest, prefix).unwrap_or_else(|_| RouteMessageBuilder::<IpAddr>::new());
    if let Some(gw) = gateway {
        b = b.gateway(gw).unwrap_or_else(|_| RouteMessageBuilder::<IpAddr>::new());
    }
    let mut b = b.output_interface(index).protocol(RouteProtocol::Other(PROTO)).table_id(table);
    if metric > 0 {
        b = b.priority(metric);
    }
    if gateway.is_none() {
        b = b.scope(RouteScope::Link);
    }
    b.build()
}

pub async fn add_route(h: &Handle, msg: RouteMessage) -> Result<(), rtnetlink::Error> {
    h.route().add(msg).replace().execute().await
}

/// Remove the routes we installed on an interface (all tables).
pub async fn flush_routes(h: &Handle, index: u32) -> Result<(), rtnetlink::Error> {
    for v6 in [false, true] {
        let msg = if v6 { RouteMessageBuilder::<Ipv6Addr>::new().build() } else { RouteMessageBuilder::<Ipv4Addr>::new().build() };
        let mut s = h.route().get(msg).execute();
        let mut del = Vec::new();
        while let Some(m) = s.try_next().await? {
            let ours = m.header.protocol == RouteProtocol::Other(PROTO) || m.header.protocol == RouteProtocol::Dhcp;
            if ours && m.attributes.iter().any(|a| matches!(a, RouteAttribute::Oif(i) if *i == index)) {
                del.push(m);
            }
        }
        for m in del {
            let _ = h.route().del(m).execute().await;
        }
    }
    Ok(())
}

pub fn sysctl(path: &str, val: &str) -> std::io::Result<()> {
    std::fs::write(format!("/proc/sys/{path}"), val)
}

pub fn read_sys(path: &str) -> String {
    std::fs::read_to_string(path).map(|s| s.trim().to_string()).unwrap_or_default()
}

pub fn driver(name: &str) -> String {
    std::fs::read_link(format!("/sys/class/net/{name}/device/driver"))
        .ok()
        .and_then(|p| p.file_name().map(|f| f.to_string_lossy().to_string()))
        .unwrap_or_default()
}

pub fn speed(name: &str) -> u32 {
    read_sys(&format!("/sys/class/net/{name}/speed")).parse::<i64>().ok().filter(|s| *s > 0).unwrap_or(0) as u32
}
