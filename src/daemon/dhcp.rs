//! A small DHCPv4 client for wired-style interfaces (Wi-Fi addressing is
//! done by iwd). One task per interface: it gets a lease, reports it, and
//! keeps renewing until it's aborted.

use std::net::{Ipv4Addr, SocketAddrV4};
use std::os::fd::FromRawFd;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::sync::mpsc::UnboundedSender;
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout, Instant};

use super::Internal;

#[derive(Clone, Debug, PartialEq)]
pub struct Lease {
    pub addr: Ipv4Addr,
    pub prefix: u8,
    pub router: Option<Ipv4Addr>,
    pub dns: Vec<Ipv4Addr>,
    pub domain: Option<String>,
    pub mtu: Option<u16>,
    pub server: Ipv4Addr,
    pub lease_secs: u32,
    pub t1: u32,
    pub t2: u32,
    /// Classless static routes (option 121): destination, prefix, gateway.
    pub routes: Vec<(Ipv4Addr, u8, Ipv4Addr)>,
}

#[derive(Clone, Debug)]
pub enum DhcpEv {
    Bound(Lease),
    /// Couldn't get (or keep) a lease; the client keeps trying.
    Lost(String),
}

const DISCOVER: u8 = 1;
const OFFER: u8 = 2;
const REQUEST: u8 = 3;
const ACK: u8 = 5;
const NAK: u8 = 6;
const MAGIC: [u8; 4] = [99, 130, 83, 99];

pub fn spawn(iface: String, mac: [u8; 6], hostname: String, tx: UnboundedSender<Internal>) -> JoinHandle<()> {
    tokio::spawn(async move {
        let sock = match socket(&iface) {
            Ok(s) => s,
            Err(e) => {
                let _ = tx.send(Internal::Dhcp { iface, ev: DhcpEv::Lost(format!("DHCP couldn't start: {e}")) });
                return;
            }
        };
        let c = Client { sock, mac, hostname, xid: rand_u32() };
        c.run(&iface, &tx).await;
    })
}

fn rand_u32() -> u32 {
    let mut b = [0u8; 4];
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        use std::io::Read;
        let _ = f.read_exact(&mut b);
    }
    u32::from_le_bytes(b) ^ std::process::id()
}

fn socket(iface: &str) -> std::io::Result<UdpSocket> {
    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK, 0);
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let std_sock = std::net::UdpSocket::from_raw_fd(fd);
        let one: libc::c_int = 1;
        let p = &one as *const _ as *const libc::c_void;
        let n = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_REUSEADDR, p, n);
        libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_BROADCAST, p, n);
        let name = iface.as_bytes();
        if libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_BINDTODEVICE, name.as_ptr() as *const libc::c_void, name.len() as libc::socklen_t) < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let addr = libc::sockaddr_in {
            sin_family: libc::AF_INET as libc::sa_family_t,
            sin_port: 68u16.to_be(),
            sin_addr: libc::in_addr { s_addr: 0 },
            sin_zero: [0; 8],
        };
        if libc::bind(fd, &addr as *const _ as *const libc::sockaddr, std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t) < 0 {
            return Err(std::io::Error::last_os_error());
        }
        UdpSocket::from_std(std_sock)
    }
}

struct Client {
    sock: UdpSocket,
    mac: [u8; 6],
    hostname: String,
    xid: u32,
}

impl Client {
    async fn run(&self, iface: &str, tx: &UnboundedSender<Internal>) {
        let send = |ev| tx.send(Internal::Dhcp { iface: iface.to_string(), ev }).is_ok();
        let mut told = false;
        loop {
            let Some(lease) = self.acquire().await else {
                if !told && !send(DhcpEv::Lost("DHCP failed — no address from the router".into())) {
                    return;
                }
                told = true;
                sleep(Duration::from_secs(20)).await;
                continue;
            };
            told = false;
            if !send(DhcpEv::Bound(lease.clone())) {
                return;
            }
            let mut lease = lease;
            let mut start = Instant::now();
            loop {
                // Renew with the server at T1, with anyone at T2, give up at expiry.
                let t1 = start + Duration::from_secs(lease.t1 as u64);
                let t2 = start + Duration::from_secs(lease.t2 as u64);
                let end = start + Duration::from_secs(lease.lease_secs as u64);
                tokio::time::sleep_until(t1).await;
                let mut renewed = None;
                while renewed.is_none() && Instant::now() < end {
                    let rebinding = Instant::now() >= t2;
                    let dest = if rebinding { Ipv4Addr::BROADCAST } else { lease.server };
                    let pkt = self.packet(REQUEST, Some(lease.addr), None, None);
                    let _ = self.sock.send_to(&pkt, SocketAddrV4::new(dest, 67)).await;
                    match self.wait(&[ACK, NAK], Duration::from_secs(10)).await {
                        Some((ACK, l)) => renewed = Some(l),
                        Some(_) => break,
                        None => {
                            let left = end.saturating_duration_since(Instant::now());
                            sleep((left / 2).clamp(Duration::from_secs(5), Duration::from_secs(60))).await;
                        }
                    }
                }
                match renewed {
                    Some(l) => {
                        if l != lease && !send(DhcpEv::Bound(l.clone())) {
                            return;
                        }
                        lease = l;
                        start = Instant::now();
                    }
                    None => {
                        if !send(DhcpEv::Lost("the DHCP lease expired".into())) {
                            return;
                        }
                        break;
                    }
                }
            }
        }
    }

    async fn acquire(&self) -> Option<Lease> {
        for attempt in 0..4u32 {
            let pkt = self.packet(DISCOVER, None, None, None);
            let _ = self.sock.send_to(&pkt, SocketAddrV4::new(Ipv4Addr::BROADCAST, 67)).await;
            let wait = Duration::from_secs(4 << attempt.min(2));
            let Some((_, offer)) = self.wait(&[OFFER], wait).await else { continue };
            let pkt = self.packet(REQUEST, None, Some(offer.addr), Some(offer.server));
            let _ = self.sock.send_to(&pkt, SocketAddrV4::new(Ipv4Addr::BROADCAST, 67)).await;
            match self.wait(&[ACK, NAK], Duration::from_secs(6)).await {
                Some((ACK, l)) => return Some(l),
                _ => continue,
            }
        }
        None
    }

    async fn wait(&self, want: &[u8], dur: Duration) -> Option<(u8, Lease)> {
        let deadline = Instant::now() + dur;
        let mut buf = [0u8; 1500];
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            let (n, _) = timeout(left, self.sock.recv_from(&mut buf)).await.ok()?.ok()?;
            if let Some((t, l)) = parse(&buf[..n], self.xid, &self.mac)
                && want.contains(&t) {
                    return Some((t, l));
                }
        }
    }

    fn packet(&self, kind: u8, ciaddr: Option<Ipv4Addr>, requested: Option<Ipv4Addr>, server: Option<Ipv4Addr>) -> Vec<u8> {
        let mut p = vec![0u8; 236];
        p[0] = 1;
        p[1] = 1;
        p[2] = 6;
        p[4..8].copy_from_slice(&self.xid.to_be_bytes());
        if ciaddr.is_none() {
            p[10] = 0x80; // ask for broadcast replies: we have no address yet
        }
        if let Some(c) = ciaddr {
            p[12..16].copy_from_slice(&c.octets());
        }
        p[28..34].copy_from_slice(&self.mac);
        p.extend(MAGIC);
        p.extend([53, 1, kind]);
        p.extend([61, 7, 1]);
        p.extend(self.mac);
        if let Some(r) = requested {
            p.extend([50, 4]);
            p.extend(r.octets());
        }
        if let Some(s) = server {
            p.extend([54, 4]);
            p.extend(s.octets());
        }
        if !self.hostname.is_empty() && self.hostname.len() < 64 {
            p.extend([12, self.hostname.len() as u8]);
            p.extend(self.hostname.as_bytes());
        }
        p.extend([55, 10, 1, 3, 6, 15, 26, 51, 54, 58, 59, 121]);
        p.push(255);
        while p.len() < 300 {
            p.push(0);
        }
        p
    }
}

fn ip(b: &[u8]) -> Option<Ipv4Addr> {
    Some(Ipv4Addr::new(*b.first()?, *b.get(1)?, *b.get(2)?, *b.get(3)?))
}

fn be32(b: &[u8]) -> Option<u32> {
    Some(u32::from_be_bytes(b.get(..4)?.try_into().ok()?))
}

/// A reply for us: (message type, lease).
pub fn parse(b: &[u8], xid: u32, mac: &[u8; 6]) -> Option<(u8, Lease)> {
    if b.len() < 240 || b[0] != 2 || be32(&b[4..])? != xid || &b[28..34] != mac || b[236..240] != MAGIC {
        return None;
    }
    let mut l = Lease {
        addr: ip(&b[16..20])?,
        prefix: 24,
        router: None,
        dns: Vec::new(),
        domain: None,
        mtu: None,
        server: ip(&b[20..24])?,
        lease_secs: 3600,
        t1: 0,
        t2: 0,
        routes: Vec::new(),
    };
    let mut kind = 0;
    let mut o = &b[240..];
    while let Some(&code) = o.first() {
        match code {
            0 => {
                o = &o[1..];
                continue;
            }
            255 => break,
            _ => {}
        }
        let len = *o.get(1)? as usize;
        let v = o.get(2..2 + len)?;
        match code {
            1 => l.prefix = u32::from(ip(v)?).count_ones() as u8,
            3 => l.router = ip(v),
            6 => l.dns = v.chunks_exact(4).filter_map(ip).collect(),
            15 => l.domain = Some(String::from_utf8_lossy(v).trim_end_matches('\0').to_string()),
            26 => l.mtu = v.get(..2).map(|m| u16::from_be_bytes([m[0], m[1]])),
            51 => l.lease_secs = be32(v)?,
            53 => kind = *v.first()?,
            54 => l.server = ip(v)?,
            58 => l.t1 = be32(v)?,
            59 => l.t2 = be32(v)?,
            121 => l.routes = classless(v),
            _ => {}
        }
        o = &o[2 + len..];
    }
    if l.t1 == 0 || l.t1 >= l.lease_secs {
        l.t1 = l.lease_secs / 2;
    }
    if l.t2 == 0 || l.t2 >= l.lease_secs || l.t2 <= l.t1 {
        l.t2 = l.lease_secs / 8 * 7;
    }
    Some((kind, l))
}

fn classless(mut v: &[u8]) -> Vec<(Ipv4Addr, u8, Ipv4Addr)> {
    let mut out = Vec::new();
    while let Some(&w) = v.first() {
        let sig = (w as usize).div_ceil(8);
        if w > 32 || v.len() < 1 + sig + 4 {
            break;
        }
        let mut d = [0u8; 4];
        d[..sig].copy_from_slice(&v[1..1 + sig]);
        let gw = ip(&v[1 + sig..]).unwrap_or(Ipv4Addr::UNSPECIFIED);
        out.push((Ipv4Addr::from(d), w, gw));
        v = &v[1 + sig + 4..];
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_an_ack() {
        let mac = [2, 0, 0, 0, 0, 1];
        let mut b = vec![0u8; 240];
        b[0] = 2;
        b[4..8].copy_from_slice(&7u32.to_be_bytes());
        b[16..20].copy_from_slice(&[192, 168, 1, 50]);
        b[28..34].copy_from_slice(&mac);
        b[236..240].copy_from_slice(&MAGIC);
        b.extend([53, 1, ACK, 1, 4, 255, 255, 255, 0, 3, 4, 192, 168, 1, 1, 6, 8, 1, 1, 1, 1, 9, 9, 9, 9, 51, 4, 0, 0, 14, 16]);
        b.extend([54, 4, 192, 168, 1, 1, 121, 8, 24, 10, 0, 0, 192, 168, 1, 254, 255]);
        let (k, l) = parse(&b, 7, &mac).unwrap();
        assert_eq!(k, ACK);
        assert_eq!(l.addr, Ipv4Addr::new(192, 168, 1, 50));
        assert_eq!(l.prefix, 24);
        assert_eq!(l.router, Some(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(l.dns.len(), 2);
        assert_eq!(l.lease_secs, 3600);
        assert_eq!(l.t1, 1800);
        assert_eq!(l.routes, vec![(Ipv4Addr::new(10, 0, 0, 0), 24, Ipv4Addr::new(192, 168, 1, 254))]);
        assert!(parse(&b, 8, &mac).is_none());
    }
}
