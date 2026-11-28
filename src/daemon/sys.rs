//! System bits: radio kill switches, hostname, DNS servers in use, the
//! connectivity check, NAT for hotspots, and who may change things.

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::backend::model::Connectivity;

/// (soft-blocked, hard-blocked, present) for a radio type ("wlan", "wwan").
pub fn rfkill(kind: &str) -> (bool, bool, bool) {
    let (mut soft, mut hard, mut any) = (false, false, false);
    if let Ok(rd) = std::fs::read_dir("/sys/class/rfkill") {
        for e in rd.flatten() {
            let p = e.path();
            if super::link::read_sys(&p.join("type").to_string_lossy()) != kind {
                continue;
            }
            any = true;
            soft |= super::link::read_sys(&p.join("soft").to_string_lossy()) == "1";
            hard |= super::link::read_sys(&p.join("hard").to_string_lossy()) == "1";
        }
    }
    (soft, hard, any)
}

pub fn set_rfkill(kind: &str, blocked: bool) -> std::io::Result<()> {
    let mut res = Ok(());
    if let Ok(rd) = std::fs::read_dir("/sys/class/rfkill") {
        for e in rd.flatten() {
            let p = e.path();
            if super::link::read_sys(&p.join("type").to_string_lossy()) == kind
                && let Err(e) = std::fs::write(p.join("soft"), if blocked { "1" } else { "0" }) {
                    res = Err(e);
                }
        }
    }
    res
}

pub fn hostname() -> String {
    super::link::read_sys("/proc/sys/kernel/hostname")
}

pub fn set_hostname(h: &str) -> std::io::Result<()> {
    std::fs::write("/etc/hostname", format!("{h}\n"))?;
    std::fs::write("/proc/sys/kernel/hostname", h)
}

/// Name servers and search domains from /etc/resolv.conf.
pub fn resolv() -> (Vec<String>, Vec<String>) {
    let text = std::fs::read_to_string("/etc/resolv.conf").unwrap_or_default();
    let (mut ns, mut search) = (Vec::new(), Vec::new());
    for l in text.lines() {
        let mut w = l.split_whitespace();
        match w.next() {
            Some("nameserver") => ns.extend(w.next().map(str::to_string)),
            Some("search" | "domain") => search.extend(w.map(str::to_string)),
            _ => {}
        }
    }
    (ns, search)
}

const CHECK_HOST: &str = "ping.archlinux.org";
const CHECK_PATH: &str = "/nm-check.txt";
const CHECK_BODY: &str = "NetworkManager is online";

/// Fetch a known page over plain HTTP and see what comes back.
pub async fn check_connectivity() -> Connectivity {
    let run = async {
        let mut addrs = match tokio::net::lookup_host((CHECK_HOST, 80)).await {
            Ok(a) => a,
            Err(_) => return Connectivity::Limited,
        };
        let Some(addr) = addrs.next() else { return Connectivity::Limited };
        let Ok(mut s) = tokio::net::TcpStream::connect(addr).await else { return Connectivity::Limited };
        let req = format!("GET {CHECK_PATH} HTTP/1.1\r\nHost: {CHECK_HOST}\r\nConnection: close\r\nUser-Agent: network-tui\r\n\r\n");
        if s.write_all(req.as_bytes()).await.is_err() {
            return Connectivity::Limited;
        }
        let mut buf = Vec::new();
        let _ = s.take(16 * 1024).read_to_end(&mut buf).await;
        let text = String::from_utf8_lossy(&buf);
        if text.starts_with("HTTP/1.1 200") && text.contains(CHECK_BODY) {
            Connectivity::Full
        } else if buf.is_empty() {
            Connectivity::Limited
        } else {
            Connectivity::Portal
        }
    };
    tokio::time::timeout(Duration::from_secs(8), run).await.unwrap_or(Connectivity::Limited)
}

/// Root, or a member of the wheel or network group.
pub fn privileged(uid: u32, gid: u32) -> bool {
    if uid == 0 {
        return true;
    }
    let passwd = std::fs::read_to_string("/etc/passwd").unwrap_or_default();
    let user = passwd.lines().find_map(|l| {
        let f: Vec<&str> = l.split(':').collect();
        (f.len() > 3 && f[2].parse() == Ok(uid)).then(|| f[0].to_string())
    });
    let groups = std::fs::read_to_string("/etc/group").unwrap_or_default();
    groups.lines().any(|l| {
        let f: Vec<&str> = l.split(':').collect();
        if f.len() < 4 || !matches!(f[0], "wheel" | "network") {
            return false;
        }
        f[2].parse() == Ok(gid) || user.as_deref().is_some_and(|u| f[3].split(',').any(|m| m == u))
    })
}

const NFT_TABLE: &str = "network_tui";

/// Masquerade traffic from a shared subnet out of every other interface.
pub async fn nat_on(iface: &str, subnet: &str) -> Result<(), String> {
    let script = format!(
        "table ip {NFT_TABLE}\ndelete table ip {NFT_TABLE}\ntable ip {NFT_TABLE} {{\n  chain postrouting {{\n    type nat hook postrouting priority srcnat; policy accept;\n    ip saddr {subnet} oifname != \"{iface}\" masquerade\n  }}\n  chain forward {{\n    type filter hook forward priority filter; policy accept;\n    iifname \"{iface}\" accept\n    oifname \"{iface}\" ct state established,related accept\n  }}\n}}\n"
    );
    nft(&script).await
}

pub async fn nat_off() {
    let _ = nft(&format!("table ip {NFT_TABLE}\ndelete table ip {NFT_TABLE}\n")).await;
}

async fn nft(script: &str) -> Result<(), String> {
    let mut child = tokio::process::Command::new("nft")
        .args(["-f", "-"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("can't run nft (is nftables installed?): {e}"))?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(script.as_bytes()).await.map_err(|e| e.to_string())?;
    }
    let out = child.wait_with_output().await.map_err(|e| e.to_string())?;
    if out.status.success() { Ok(()) } else { Err(String::from_utf8_lossy(&out.stderr).trim().to_string()) }
}

#[cfg(test)]
mod tests {
    #[test]
    fn root_is_privileged() {
        assert!(super::privileged(0, 0));
    }
}
