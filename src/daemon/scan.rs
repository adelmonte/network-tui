//! Per-access-point details (band, signal, security) from the kernel's
//! nl80211 scan results, which iwd's D-Bus API doesn't expose.

use futures::TryStreamExt;
use wl_nl80211::{Nl80211Attr, Nl80211BssInfo};

use crate::backend::model::Security;

#[derive(Clone, Debug, PartialEq)]
pub struct Bss {
    pub bssid: String,
    pub ssid: Vec<u8>,
    pub freq: u32,
    pub dbm: i32,
    pub security: Security,
    pub max_rate_kbps: u32,
}

impl Bss {
    pub fn strength(&self) -> u8 {
        (2 * (self.dbm + 100)).clamp(0, 100) as u8
    }
}

pub async fn dump(if_index: u32) -> Result<Vec<Bss>, String> {
    let (conn, handle, _) = wl_nl80211::new_connection().map_err(|e| e.to_string())?;
    let task = tokio::spawn(conn);
    let mut out = Vec::new();
    let res: Result<(), String> = async {
        let mut s = handle.scan().dump(if_index).execute().await;
        while let Some(msg) = s.try_next().await.map_err(|e| e.to_string())? {
            for a in &msg.payload.attributes {
                if let Nl80211Attr::Bss(info) = a
                    && let Some(b) = parse(info) {
                        out.push(b);
                    }
            }
        }
        Ok(())
    }
    .await;
    task.abort();
    res.map(|_| out)
}

fn parse(info: &[Nl80211BssInfo]) -> Option<Bss> {
    let mut bssid = None;
    let mut freq = 0;
    let mut dbm = -100;
    let mut privacy = false;
    let mut ies: &[u8] = &[];
    for i in info {
        match i {
            Nl80211BssInfo::Bssid(b) => bssid = Some(b.iter().map(|x| format!("{x:02x}")).collect::<Vec<_>>().join(":")),
            Nl80211BssInfo::Frequency(f) => freq = *f,
            Nl80211BssInfo::SignalMbm(m) => dbm = *m / 100,
            Nl80211BssInfo::Capability(c) => privacy = c.contains(wl_nl80211::Ieee80211CapabilityInfo::Privacy),
            Nl80211BssInfo::RawInformationElements(b) => ies = b,
            Nl80211BssInfo::RawProbeResponseInformationElements(b) if ies.is_empty() => ies = b,
            _ => {}
        }
    }
    let p = parse_ies(ies);
    let security = p.security(privacy);
    Some(Bss { bssid: bssid?, ssid: p.ssid, freq, dbm, security, max_rate_kbps: p.max_rate_kbps })
}

#[derive(Default, Debug)]
struct Ies {
    ssid: Vec<u8>,
    rsn: Option<Vec<u32>>,
    wpa: Option<Vec<u32>>,
    max_rate_kbps: u32,
}

impl Ies {
    fn security(&self, privacy: bool) -> Security {
        // AKM suites, as OUI 00-0F-AC (or 00-50-F2 for WPA1) + type.
        let rsn = self.rsn.as_deref().unwrap_or_default();
        let has = |t: u32| rsn.contains(&t);
        if rsn.iter().any(|t| matches!(t, 1 | 3 | 5 | 11 | 12 | 13)) {
            Security::Enterprise
        } else if (has(8) || has(9)) && (has(2) || has(4) || has(6)) {
            Security::Wpa2Wpa3
        } else if has(8) || has(9) {
            Security::Wpa3
        } else if has(2) || has(4) || has(6) {
            Security::Wpa2
        } else if has(18) {
            Security::Owe
        } else if let Some(w) = &self.wpa {
            if w.contains(&1) { Security::Enterprise } else { Security::Wpa }
        } else if self.rsn.is_some() && rsn.is_empty() {
            Security::Wpa2
        } else if privacy {
            Security::Wep
        } else {
            Security::Open
        }
    }
}

/// AKM suite types from an RSN (or WPA vendor) element body.
fn akms(body: &[u8], oui: [u8; 3]) -> Vec<u32> {
    // version(2) group cipher(4) pairwise count(2) + 4n, akm count(2) + 4n
    let mut i = 2 + 4;
    let count = |b: &[u8], i: usize| -> Option<usize> { Some(u16::from_le_bytes([*b.get(i)?, *b.get(i + 1)?]) as usize) };
    let Some(pc) = count(body, i) else { return Vec::new() };
    i += 2 + 4 * pc;
    let Some(ac) = count(body, i) else { return Vec::new() };
    i += 2;
    (0..ac)
        .filter_map(|k| {
            let s = body.get(i + 4 * k..i + 4 * k + 4)?;
            (s[..3] == oui).then_some(s[3] as u32)
        })
        .collect()
}

fn parse_ies(mut b: &[u8]) -> Ies {
    let mut out = Ies::default();
    while b.len() >= 2 {
        let (id, len) = (b[0], b[1] as usize);
        let Some(body) = b.get(2..2 + len) else { break };
        match id {
            0 => out.ssid = body.to_vec(),
            1 | 50 => {
                for r in body {
                    out.max_rate_kbps = out.max_rate_kbps.max((*r & 0x7f) as u32 * 500);
                }
            }
            48 => out.rsn = Some(akms(body, [0x00, 0x0f, 0xac])),
            221 if body.len() >= 4 && body[..4] == [0x00, 0x50, 0xf2, 0x01] => out.wpa = Some(akms(&body[4..], [0x00, 0x50, 0xf2])),
            _ => {}
        }
        b = &b[2 + len..];
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rsn(akm: &[u8]) -> Vec<u8> {
        let mut body = vec![1, 0, 0x00, 0x0f, 0xac, 4, 1, 0, 0x00, 0x0f, 0xac, 4, akm.len() as u8, 0];
        for a in akm {
            body.extend([0x00, 0x0f, 0xac, *a]);
        }
        let mut ie = vec![48, body.len() as u8];
        ie.extend(body);
        ie
    }

    #[test]
    fn security_from_ies() {
        let mut ies = vec![0, 4, b'C', b'a', b'f', b'e'];
        ies.extend(rsn(&[2]));
        let p = parse_ies(&ies);
        assert_eq!(p.ssid, b"Cafe");
        assert_eq!(p.security(true), Security::Wpa2);
        assert_eq!(parse_ies(&rsn(&[2, 8])).security(true), Security::Wpa2Wpa3);
        assert_eq!(parse_ies(&rsn(&[8])).security(true), Security::Wpa3);
        assert_eq!(parse_ies(&rsn(&[1])).security(true), Security::Enterprise);
        assert_eq!(parse_ies(&rsn(&[18])).security(false), Security::Owe);
        assert_eq!(parse_ies(&[]).security(true), Security::Wep);
        assert_eq!(parse_ies(&[]).security(false), Security::Open);
    }
}
