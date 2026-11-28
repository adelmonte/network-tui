//! WireGuard: configure a device over generic netlink, route a full tunnel
//! the way wg-quick does, and import wg-quick config files.

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};

use futures::StreamExt;
use netlink_packet_core::{NetlinkMessage, NetlinkPayload, NLM_F_ACK, NLM_F_REQUEST};
use netlink_packet_generic::GenlMessage;
use netlink_packet_wireguard::{
    WireguardAddressFamily, WireguardAllowedIp, WireguardAllowedIpAttr, WireguardAttribute, WireguardCmd, WireguardDeviceFlags,
    WireguardMessage, WireguardPeer, WireguardPeerAttribute,
};
use rtnetlink::packet_route::route::RouteProtocol;
use rtnetlink::packet_route::rule::{RuleAttribute, RuleFlags};
use rtnetlink::{Handle, IpVersion};

use crate::backend::form;
use crate::backend::val::{Dict, DictExt, Settings, Val};

use super::link::PROTO;

/// Table and firewall mark for full-tunnel routing (wg-quick's convention).
pub const TABLE: u32 = 51820;

#[derive(Clone, Debug, Default)]
pub struct Peer {
    pub public_key: [u8; 32],
    pub psk: Option<[u8; 32]>,
    pub endpoint: Option<SocketAddr>,
    pub keepalive: u16,
    pub allowed: Vec<(IpAddr, u8)>,
}

#[derive(Clone, Debug, Default)]
pub struct Config {
    pub private_key: [u8; 32],
    pub listen_port: u16,
    pub fwmark: u32,
    pub peers: Vec<Peer>,
}

impl Config {
    /// Does any peer take all traffic (0.0.0.0/0 or ::/0)?
    pub fn full_tunnel(&self, v6: bool) -> bool {
        self.peers.iter().flat_map(|p| &p.allowed).any(|(ip, pfx)| *pfx == 0 && ip.is_ipv6() == v6)
    }
}

pub fn b64_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut acc = 0u32;
    let mut bits = 0;
    for c in s.trim().bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => break,
            _ => return None,
        } as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

fn key(s: &str) -> Result<[u8; 32], String> {
    b64_decode(s).and_then(|v| v.try_into().ok()).ok_or_else(|| "a WireGuard key is malformed".to_string())
}

async fn resolve(ep: &str) -> Result<SocketAddr, String> {
    if let Ok(a) = ep.parse() {
        return Ok(a);
    }
    tokio::net::lookup_host(ep).await.map_err(|e| format!("can't resolve endpoint {ep}: {e}"))?.next().ok_or_else(|| format!("can't resolve endpoint {ep}"))
}

pub async fn from_settings(s: &Settings) -> Result<Config, String> {
    let w = s.get("wireguard").cloned().unwrap_or_default();
    let pk = w.s("private-key");
    if pk.is_empty() {
        return Err("no private key set".into());
    }
    let mut cfg = Config { private_key: key(&pk)?, listen_port: w.u("listen-port") as u16, fwmark: w.u("fwmark"), peers: Vec::new() };
    for p in w.get("peers").map(|v| v.dict_list().to_vec()).unwrap_or_default() {
        let mut peer = Peer { public_key: key(&p.s("public-key"))?, keepalive: p.u("persistent-keepalive") as u16, ..Default::default() };
        let psk = p.s("preshared-key");
        if !psk.is_empty() {
            peer.psk = Some(key(&psk)?);
        }
        let ep = p.s("endpoint");
        if !ep.is_empty() {
            peer.endpoint = Some(resolve(&ep).await?);
        }
        for a in p.get("allowed-ips").map(Val::str_list).unwrap_or_default() {
            let (ip, pfx) = form::parse_cidr(&a).ok_or_else(|| format!("bad allowed IP “{a}”"))?;
            peer.allowed.push((ip, pfx as u8));
        }
        cfg.peers.push(peer);
    }
    Ok(cfg)
}

pub async fn configure(ifname: &str, cfg: &Config) -> Result<(), String> {
    let mut attrs = vec![
        WireguardAttribute::IfName(ifname.to_string()),
        WireguardAttribute::Flags(WireguardDeviceFlags::ReplacePeers),
        WireguardAttribute::PrivateKey(cfg.private_key),
        WireguardAttribute::ListenPort(cfg.listen_port),
        WireguardAttribute::Fwmark(cfg.fwmark),
    ];
    let peers = cfg
        .peers
        .iter()
        .map(|p| {
            let mut a = vec![WireguardPeerAttribute::PublicKey(p.public_key)];
            if let Some(k) = p.psk {
                a.push(WireguardPeerAttribute::PresharedKey(k));
            }
            if let Some(e) = p.endpoint {
                a.push(WireguardPeerAttribute::Endpoint(e));
            }
            if p.keepalive > 0 {
                a.push(WireguardPeerAttribute::PersistentKeepalive(p.keepalive));
            }
            a.push(WireguardPeerAttribute::AllowedIps(
                p.allowed
                    .iter()
                    .map(|(ip, pfx)| {
                        let fam = if ip.is_ipv6() { WireguardAddressFamily::Ipv6 } else { WireguardAddressFamily::Ipv4 };
                        WireguardAllowedIp(vec![
                            WireguardAllowedIpAttr::Family(fam),
                            WireguardAllowedIpAttr::IpAddr(*ip),
                            WireguardAllowedIpAttr::Cidr(*pfx),
                        ])
                    })
                    .collect(),
            ));
            WireguardPeer(a)
        })
        .collect();
    attrs.push(WireguardAttribute::Peers(peers));

    let (conn, mut handle, _) = genetlink::new_connection().map_err(|e| e.to_string())?;
    let task = tokio::spawn(conn);
    let res = async {
        let mut msg = NetlinkMessage::from(GenlMessage::from_payload(WireguardMessage { cmd: WireguardCmd::SetDevice, attributes: attrs }));
        msg.header.flags = NLM_F_REQUEST | NLM_F_ACK;
        let mut replies = handle.request(msg).await.map_err(|e| format!("WireGuard netlink: {e}"))?;
        while let Some(r) = replies.next().await {
            if let NetlinkPayload::Error(e) = r.map_err(|e| e.to_string())?.payload
                && e.code.is_some() {
                    return Err(format!("WireGuard rejected the configuration: {}", e.to_io()));
                }
        }
        Ok(())
    }
    .await;
    task.abort();
    res
}

/// wg-quick's full-tunnel trick: everything not marked by WireGuard itself
/// goes to our table, while more specific routes in main still win.
pub async fn add_rules(h: &Handle, v6: bool) -> Result<(), String> {
    let mk = || {
        let r = h.rule().add();
        if v6 { RuleReq::V6(r.v6()) } else { RuleReq::V4(r.v4()) }
    };
    let mut a = mk();
    a.msg().header.flags = RuleFlags::Invert;
    a.msg().attributes.extend([RuleAttribute::FwMark(TABLE), RuleAttribute::Table(TABLE), RuleAttribute::Protocol(RouteProtocol::Other(PROTO))]);
    a.msg().header.action = rtnetlink::packet_route::rule::RuleAction::ToTable;
    a.exec().await?;
    let mut b = mk();
    b.msg().attributes.extend([RuleAttribute::Table(254), RuleAttribute::SuppressPrefixLen(0), RuleAttribute::Protocol(RouteProtocol::Other(PROTO))]);
    b.msg().header.action = rtnetlink::packet_route::rule::RuleAction::ToTable;
    b.exec().await
}

enum RuleReq {
    V4(rtnetlink::RuleAddRequest<std::net::Ipv4Addr>),
    V6(rtnetlink::RuleAddRequest<std::net::Ipv6Addr>),
}

impl RuleReq {
    fn msg(&mut self) -> &mut rtnetlink::packet_route::rule::RuleMessage {
        match self {
            RuleReq::V4(r) => r.message_mut(),
            RuleReq::V6(r) => r.message_mut(),
        }
    }
    async fn exec(self) -> Result<(), String> {
        match self {
            RuleReq::V4(r) => r.execute().await,
            RuleReq::V6(r) => r.execute().await,
        }
        .map_err(|e| format!("adding a routing rule: {e}"))
    }
}

/// Remove the rules [`add_rules`] installed.
pub async fn del_rules(h: &Handle) {
    for v in [IpVersion::V4, IpVersion::V6] {
        let mut s = h.rule().get(v).execute();
        let mut del = Vec::new();
        while let Some(Ok(m)) = s.next().await {
            if m.attributes.contains(&RuleAttribute::Protocol(RouteProtocol::Other(PROTO))) {
                del.push(m);
            }
        }
        for m in del {
            let _ = h.rule().del(m).execute().await;
        }
    }
}

/// Turn a wg-quick .conf file into a profile.
pub fn import_conf(text: &str, name: &str) -> Result<Settings, String> {
    let mut s = form::new_settings("wireguard", name);
    let mut iface: BTreeMap<String, String> = BTreeMap::new();
    let mut peers: Vec<BTreeMap<String, String>> = Vec::new();
    let mut section = String::new();
    for line in text.lines() {
        let l = line.split('#').next().unwrap_or("").trim();
        if l.is_empty() {
            continue;
        }
        if l.starts_with('[') {
            section = l.trim_matches(['[', ']']).to_lowercase();
            if section == "peer" {
                peers.push(BTreeMap::new());
            }
            continue;
        }
        let Some((k, v)) = l.split_once('=') else { continue };
        let (k, v) = (k.trim().to_lowercase(), v.trim().to_string());
        let map = match section.as_str() {
            "interface" => &mut iface,
            "peer" => peers.last_mut().ok_or("[Peer] keys before any [Peer]")?,
            _ => continue,
        };
        // Repeated keys (Address, AllowedIPs, DNS) accumulate.
        map.entry(k).and_modify(|e| *e = format!("{e}, {v}")).or_insert(v);
    }
    let pk = iface.get("privatekey").ok_or("no PrivateKey in [Interface]")?;
    key(pk)?;
    let w = s.get_mut("wireguard").expect("new_settings adds it");
    w.insert("private-key".into(), Val::Str(pk.clone()));
    if let Some(p) = iface.get("listenport").and_then(|p| p.parse::<u32>().ok()) {
        w.insert("listen-port".into(), Val::U32(p));
    }
    if let Some(m) = iface.get("fwmark").and_then(|p| p.parse::<u32>().ok()) {
        w.insert("fwmark".into(), Val::U32(m));
    }
    let mut plist = Vec::new();
    for p in &peers {
        let mut d = Dict::new();
        let pk = p.get("publickey").ok_or("a [Peer] has no PublicKey")?;
        key(pk)?;
        d.insert("public-key".into(), Val::Str(pk.clone()));
        if let Some(v) = p.get("endpoint") {
            d.insert("endpoint".into(), Val::Str(v.clone()));
        }
        if let Some(v) = p.get("presharedkey") {
            d.insert("preshared-key".into(), Val::Str(v.clone()));
        }
        if let Some(v) = p.get("persistentkeepalive").and_then(|v| v.parse::<u32>().ok()) {
            d.insert("persistent-keepalive".into(), Val::U32(v));
        }
        d.insert("allowed-ips".into(), Val::StrList(form::split_list(p.get("allowedips").map(String::as_str).unwrap_or(""))));
        plist.push(d);
    }
    w.insert("peers".into(), Val::DictList(plist));
    let (mut v4, mut v6) = (Vec::new(), Vec::new());
    for a in form::split_list(iface.get("address").map(String::as_str).unwrap_or("")) {
        let (ip, pfx) = form::parse_cidr(&a).ok_or_else(|| format!("bad Address “{a}”"))?;
        let mut d = Dict::new();
        d.insert("address".into(), Val::Str(ip.to_string()));
        d.insert("prefix".into(), Val::U32(pfx));
        if ip.is_ipv6() { v6.push(d) } else { v4.push(d) }
    }
    let ipv4 = s.entry("ipv4".into()).or_default();
    ipv4.insert("method".into(), Val::Str(if v4.is_empty() { "disabled" } else { "manual" }.into()));
    if !v4.is_empty() {
        ipv4.insert("address-data".into(), Val::DictList(v4));
    }
    let dns: Vec<u32> = form::split_list(iface.get("dns").map(String::as_str).unwrap_or(""))
        .iter()
        .filter_map(|d| d.parse::<std::net::Ipv4Addr>().ok())
        .map(|a| u32::from_le_bytes(a.octets()))
        .collect();
    if !dns.is_empty() {
        ipv4.insert("dns".into(), Val::U32List(dns));
    }
    let ipv6 = s.entry("ipv6".into()).or_default();
    ipv6.insert("method".into(), Val::Str(if v6.is_empty() { "disabled" } else { "manual" }.into()));
    if !v6.is_empty() {
        ipv6.insert("address-data".into(), Val::DictList(v6));
    }
    if let Some(m) = iface.get("mtu").and_then(|m| m.parse::<u32>().ok()) {
        s.get_mut("wireguard").expect("set").insert("mtu".into(), Val::U32(m));
    }
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_keys() {
        let k = "YAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=";
        assert_eq!(b64_decode(k).unwrap().len(), 32);
        assert!(key("short").is_err());
    }

    #[test]
    fn imports_wg_quick() {
        let conf = "[Interface]\nPrivateKey = YAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=\nAddress = 10.0.0.2/32, fd00::2/128\nDNS = 1.1.1.1\n\n[Peer]\nPublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\nEndpoint = vpn.example.com:51820\nAllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 25\n";
        let s = import_conf(conf, "work").unwrap();
        let w = &s["wireguard"];
        assert_eq!(w.get("peers").unwrap().dict_list()[0].s("endpoint"), "vpn.example.com:51820");
        assert_eq!(w.get("peers").unwrap().dict_list()[0].get("allowed-ips").unwrap().str_list().len(), 2);
        assert_eq!(s["ipv4"].s("method"), "manual");
        assert_eq!(s["ipv6"].s("method"), "manual");
    }
}
