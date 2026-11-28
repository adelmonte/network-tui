//! iwd's network files in /var/lib/iwd: Wi-Fi profiles are mirrored into
//! them so iwd can connect (and auto-connect) on its own.

use std::net::Ipv4Addr;

use crate::backend::form;
use crate::backend::val::{ssid_to_string, DictExt, Settings, Val};

use super::store::{get_s, ssid_of};

pub const DIR: &str = "/var/lib/iwd";

/// A minimal INI document that keeps unknown sections and keys (iwd adds
/// its own, like the SAE points it derives).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Ini {
    sections: Vec<(String, Vec<(String, String)>)>,
}

impl Ini {
    pub fn parse(text: &str) -> Self {
        let mut ini = Ini::default();
        for line in text.lines() {
            let l = line.trim();
            if l.is_empty() || l.starts_with('#') {
                continue;
            }
            if let Some(name) = l.strip_prefix('[').and_then(|r| r.strip_suffix(']')) {
                ini.sections.push((name.to_string(), Vec::new()));
            } else if let Some((k, v)) = l.split_once('=') {
                if ini.sections.is_empty() {
                    ini.sections.push((String::new(), Vec::new()));
                }
                ini.sections.last_mut().expect("pushed").1.push((k.trim().to_string(), v.trim().to_string()));
            }
        }
        ini
    }

    pub fn render(&self) -> String {
        let mut out = String::new();
        for (name, kvs) in &self.sections {
            if kvs.is_empty() {
                continue;
            }
            if !out.is_empty() {
                out.push('\n');
            }
            out.push_str(&format!("[{name}]\n"));
            for (k, v) in kvs {
                out.push_str(&format!("{k}={v}\n"));
            }
        }
        out
    }

    pub fn get(&self, sec: &str, key: &str) -> Option<&str> {
        self.sections.iter().find(|s| s.0 == sec)?.1.iter().find(|kv| kv.0 == key).map(|kv| kv.1.as_str())
    }

    pub fn set(&mut self, sec: &str, key: &str, val: impl Into<String>) {
        let val = val.into();
        let s = match self.sections.iter().position(|s| s.0 == sec) {
            Some(i) => &mut self.sections[i].1,
            None => {
                self.sections.push((sec.to_string(), Vec::new()));
                &mut self.sections.last_mut().expect("pushed").1
            }
        };
        match s.iter_mut().find(|kv| kv.0 == key) {
            Some(kv) => kv.1 = val,
            None => s.push((key.to_string(), val)),
        }
    }

    pub fn remove(&mut self, sec: &str, key: &str) {
        if let Some(s) = self.sections.iter_mut().find(|s| s.0 == sec) {
            s.1.retain(|kv| kv.0 != key);
        }
    }

    pub fn remove_where(&mut self, sec: &str, f: impl Fn(&str) -> bool) {
        if let Some(s) = self.sections.iter_mut().find(|s| s.0 == sec) {
            s.1.retain(|kv| !f(&kv.0));
        }
    }

    fn set_opt(&mut self, sec: &str, key: &str, val: Option<String>) {
        match val {
            Some(v) if !v.is_empty() => self.set(sec, key, v),
            _ => self.remove(sec, key),
        }
    }
}

/// iwd's file name for an SSID: as-is when it's plain, else `=` + hex.
pub fn file_name(ssid: &[u8], ext: &str) -> String {
    let plain = !ssid.is_empty() && ssid.iter().all(|c| c.is_ascii_alphanumeric() || b"-_ ".contains(c));
    if plain {
        format!("{}.{ext}", String::from_utf8_lossy(ssid))
    } else {
        format!("={}.{ext}", ssid.iter().map(|b| format!("{b:02x}")).collect::<String>())
    }
}

/// Inverse of [`file_name`]: (ssid, extension).
pub fn parse_name(name: &str) -> Option<(Vec<u8>, String)> {
    let (stem, ext) = name.rsplit_once('.')?;
    if !matches!(ext, "psk" | "open" | "8021x") {
        return None;
    }
    let ssid = match stem.strip_prefix('=') {
        Some(hex) => {
            if hex.len() % 2 != 0 {
                return None;
            }
            (0..hex.len()).step_by(2).map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok()).collect::<Option<Vec<u8>>>()?
        }
        None => stem.as_bytes().to_vec(),
    };
    Some((ssid, ext.to_string()))
}

/// Which iwd file type a Wi-Fi profile maps to.
pub fn ext_for(s: &Settings) -> Result<&'static str, String> {
    match get_s(s, "802-11-wireless-security", "key-mgmt").as_str() {
        "" | "owe" => Ok("open"),
        "wpa-psk" | "sae" => Ok("psk"),
        "wpa-eap" | "wpa-eap-suite-b-192" => Ok("8021x"),
        "none" | "ieee8021x" => Err("WEP isn't supported (iwd dropped it as insecure)".into()),
        k => Err(format!("unsupported Wi-Fi security “{k}”")),
    }
}

pub fn path_for(s: &Settings) -> Result<String, String> {
    let ssid = ssid_of(s).filter(|b| !b.is_empty()).ok_or("the profile has no SSID")?;
    Ok(format!("{DIR}/{}", file_name(&ssid, ext_for(s)?)))
}

fn cert_path(s: &Settings, key: &str) -> Option<String> {
    match s.get("802-1x").and_then(|d| d.get(key)) {
        Some(Val::Bytes(b)) => {
            let t = String::from_utf8_lossy(b).trim_end_matches('\0').to_string();
            Some(t.strip_prefix("file://").map(str::to_string).unwrap_or(t)).filter(|p| !p.is_empty())
        }
        Some(Val::Str(p)) if !p.is_empty() => Some(p.clone()),
        _ => None,
    }
}

fn prefix_mask(p: u32) -> Ipv4Addr {
    Ipv4Addr::from(if p == 0 { 0 } else { u32::MAX << (32 - p.min(32)) })
}

fn mask_prefix(m: &str) -> u32 {
    m.parse::<Ipv4Addr>().map(|a| u32::from(a).count_ones()).unwrap_or(24)
}

/// A per-network MAC that stays the same across reconnects (NM's "stable").
pub fn stable_mac(ssid: &[u8]) -> String {
    let seed = std::fs::read("/etc/machine-id").unwrap_or_default();
    let mut h: u64 = 0xcbf29ce484222325;
    for b in seed.iter().chain(b"/").chain(ssid) {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    let mut b = h.to_be_bytes();
    b[0] = (b[0] & 0xfe) | 0x02; // unicast, locally administered
    format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", b[0], b[1], b[2], b[3], b[4], b[5])
}

/// Write `s` into `ini` (an existing file's contents, or empty).
pub fn apply(ini: &mut Ini, s: &Settings) {
    let c = s.get("connection").cloned().unwrap_or_default();
    let w = s.get("802-11-wireless").cloned().unwrap_or_default();
    let sec = s.get("802-11-wireless-security").cloned().unwrap_or_default();

    ini.set("Settings", "AutoConnect", if c.opt_b("autoconnect").unwrap_or(true) { "true" } else { "false" });
    ini.set_opt("Settings", "Hidden", w.b("hidden").then(|| "true".into()));
    let mac = w.s("assigned-mac-address");
    ini.remove("Settings", "AlwaysRandomizeAddress");
    ini.remove("Settings", "AddressOverride");
    match mac.as_str() {
        "random" => ini.set("Settings", "AlwaysRandomizeAddress", "true"),
        "stable" => ini.set("Settings", "AddressOverride", stable_mac(&ssid_of(s).unwrap_or_default())),
        m if form::parse_mac(m).is_some() => ini.set("Settings", "AddressOverride", m.to_lowercase()),
        _ => {}
    }

    if matches!(sec.s("key-mgmt").as_str(), "wpa-psk" | "sae") {
        let psk = sec.s("psk");
        let is_hex = psk.len() == 64 && psk.chars().all(|c| c.is_ascii_hexdigit());
        if is_hex {
            if ini.get("Security", "PreSharedKey") != Some(psk.as_str()) {
                ini.remove_where("Security", |k| k.starts_with("SAE-PT-") || k == "Passphrase");
                ini.set("Security", "PreSharedKey", psk);
            }
        } else if !psk.is_empty() && ini.get("Security", "Passphrase") != Some(psk.as_str()) {
            // A new passphrase invalidates everything iwd derived from the old one.
            ini.remove_where("Security", |k| k.starts_with("SAE-PT-") || k == "PreSharedKey");
            ini.set("Security", "Passphrase", psk);
        }
    }

    if sec.s("key-mgmt").starts_with("wpa-eap") {
        apply_eap(ini, s);
    }

    let v4 = s.get("ipv4").cloned().unwrap_or_default();
    for k in ["Address", "Netmask", "Gateway", "DNS"] {
        ini.remove("IPv4", k);
    }
    if v4.s("method") == "manual" {
        if let Some(a) = v4.get("address-data").and_then(|v| v.dict_list().first().cloned()) {
            ini.set("IPv4", "Address", a.s("address"));
            ini.set("IPv4", "Netmask", prefix_mask(a.u("prefix")).to_string());
        }
        ini.set_opt("IPv4", "Gateway", Some(v4.s("gateway")));
        if let Some(Val::U32List(dns)) = v4.get("dns") {
            let list: Vec<String> = dns.iter().map(|n| Ipv4Addr::from(n.to_le_bytes()).to_string()).collect();
            ini.set_opt("IPv4", "DNS", Some(list.join(" ")));
        }
    }
    let v6 = s.get("ipv6").map(|d| d.s("method")).unwrap_or_default();
    ini.set("IPv6", "Enabled", if matches!(v6.as_str(), "disabled" | "ignore") { "false" } else { "true" });
}

fn apply_eap(ini: &mut Ini, s: &Settings) {
    let x = s.get("802-1x").cloned().unwrap_or_default();
    ini.remove_where("Security", |k| k.starts_with("EAP-"));
    let eap = x.get("eap").map(Val::str_list).unwrap_or_default();
    let method = eap.first().map(String::as_str).unwrap_or("peap");
    let identity = x.s("identity");
    let anon = x.s("anonymous-identity");
    let outer_id = if anon.is_empty() { identity.clone() } else { anon };
    let p2 = x.s("phase2-auth");
    let (name, prefix) = match method {
        "ttls" => ("TTLS", "EAP-TTLS"),
        "tls" => ("TLS", "EAP-TLS"),
        "pwd" => ("PWD", "EAP-PWD"),
        _ => ("PEAP", "EAP-PEAP"),
    };
    ini.set("Security", "EAP-Method", name);
    match method {
        "tls" => {
            ini.set("Security", "EAP-Identity", identity);
            ini.set_opt("Security", "EAP-TLS-ClientCert", cert_path(s, "client-cert"));
            ini.set_opt("Security", "EAP-TLS-ClientKey", cert_path(s, "private-key"));
            ini.set_opt("Security", "EAP-TLS-ClientKeyPassphrase", Some(x.s("private-key-password")));
        }
        "pwd" => {
            ini.set("Security", "EAP-Identity", identity);
            ini.set_opt("Security", "EAP-PWD-Password", Some(x.s("password")));
        }
        _ => {
            ini.set("Security", "EAP-Identity", outer_id);
            let p2m = match (method, p2.as_str()) {
                ("ttls", "pap") => "Tunneled-PAP",
                ("ttls", "chap") => "Tunneled-CHAP",
                ("ttls", "mschap") => "Tunneled-MSCHAP",
                ("ttls", _) => "Tunneled-MSCHAPv2",
                (_, "gtc") => "GTC",
                (_, "md5") => "MD5",
                _ => "MSCHAPV2",
            };
            ini.set("Security", &format!("{prefix}-Phase2-Method"), p2m);
            ini.set("Security", &format!("{prefix}-Phase2-Identity"), identity);
            ini.set_opt("Security", &format!("{prefix}-Phase2-Password"), Some(x.s("password")));
        }
    }
    ini.set_opt("Security", &format!("{prefix}-CACert"), cert_path(s, "ca-cert"));
    let dom = x.s("domain-suffix-match");
    ini.set_opt("Security", &format!("{prefix}-ServerDomainMask"), (!dom.is_empty()).then(|| format!("*.{dom}")));
}

/// A profile for an iwd network file nobody created through us.
pub fn import(ssid: &[u8], ext: &str, ini: &Ini) -> Settings {
    let name = ssid_to_string(ssid);
    let km = match ext {
        "psk" => Some("wpa-psk"),
        "8021x" => Some("wpa-eap"),
        _ => None,
    };
    let psk = ini.get("Security", "Passphrase").or(ini.get("Security", "PreSharedKey")).unwrap_or_default();
    let hidden = ini.get("Settings", "Hidden") == Some("true");
    let mut s = form::wifi_join_settings(&name, km, psk, hidden);
    if let Some(w) = s.get_mut("802-11-wireless") {
        w.insert("ssid".into(), Val::Bytes(ssid.to_vec()));
        if ini.get("Settings", "AlwaysRandomizeAddress") == Some("true") {
            w.insert("assigned-mac-address".into(), Val::Str("random".into()));
        } else if let Some(m) = ini.get("Settings", "AddressOverride") {
            w.insert("assigned-mac-address".into(), Val::Str(m.to_string()));
        }
    }
    if ini.get("Settings", "AutoConnect") == Some("false") {
        s.get_mut("connection").expect("set").insert("autoconnect".into(), Val::Bool(false));
    }
    if let Some(addr) = ini.get("IPv4", "Address") {
        let mut a = crate::backend::val::Dict::new();
        a.insert("address".into(), Val::Str(addr.to_string()));
        a.insert("prefix".into(), Val::U32(mask_prefix(ini.get("IPv4", "Netmask").unwrap_or("255.255.255.0"))));
        let v4 = s.entry("ipv4".into()).or_default();
        v4.insert("method".into(), Val::Str("manual".into()));
        v4.insert("address-data".into(), Val::DictList(vec![a]));
        if let Some(gw) = ini.get("IPv4", "Gateway") {
            v4.insert("gateway".into(), Val::Str(gw.to_string()));
        }
    }
    if ini.get("IPv6", "Enabled") == Some("false") {
        s.entry("ipv6".into()).or_default().insert("method".into(), Val::Str("disabled".into()));
    }
    if ext == "8021x" {
        let x = s.entry("802-1x".into()).or_default();
        let m = ini.get("Security", "EAP-Method").unwrap_or("PEAP").to_lowercase();
        let prefix = format!("EAP-{}", m.to_uppercase());
        x.insert("eap".into(), Val::StrList(vec![m.clone()]));
        let id = ini.get("Security", &format!("{prefix}-Phase2-Identity")).or(ini.get("Security", "EAP-Identity")).unwrap_or_default();
        x.insert("identity".into(), Val::Str(id.to_string()));
        if let Some(pw) = ini.get("Security", &format!("{prefix}-Phase2-Password")).or(ini.get("Security", "EAP-PWD-Password")) {
            x.insert("password".into(), Val::Str(pw.to_string()));
        }
        if let Some(p2) = ini.get("Security", &format!("{prefix}-Phase2-Method")) {
            let p2 = p2.trim_start_matches("Tunneled-").to_lowercase();
            x.insert("phase2-auth".into(), Val::Str(p2));
        }
    }
    s
}

/// Profiles for each iwd network file in the directory.
pub fn scan_dir() -> Vec<(String, Vec<u8>, String, Ini)> {
    let mut out = Vec::new();
    let Ok(rd) = std::fs::read_dir(DIR) else { return out };
    for e in rd.flatten() {
        let name = e.file_name().to_string_lossy().to_string();
        let Some((ssid, ext)) = parse_name(&name) else { continue };
        let Ok(text) = std::fs::read_to_string(e.path()) else { continue };
        out.push((format!("{DIR}/{name}"), ssid, ext, Ini::parse(&text)));
    }
    out
}

/// Create or update the iwd file for a client Wi-Fi profile. `old` is the
/// file the previous version of the profile mapped to, removed if it moved.
pub fn write(s: &Settings, old: Option<&str>) -> Result<String, String> {
    let path = path_for(s)?;
    let mut ini = std::fs::read_to_string(&path).map(|t| Ini::parse(&t)).unwrap_or_default();
    apply(&mut ini, s);
    super::store::write_private(std::path::Path::new(&path), ini.render().as_bytes()).map_err(|e| format!("writing {path}: {e}"))?;
    if let Some(o) = old
        && o != path {
            let _ = std::fs::remove_file(o);
        }
    Ok(path)
}

/// iwd access point profile for a hotspot.
pub fn write_ap(s: &Settings, address: Ipv4Addr) -> Result<String, String> {
    let ssid = ssid_of(s).filter(|b| !b.is_empty()).ok_or("the hotspot has no name")?;
    let ssid = std::str::from_utf8(&ssid).map_err(|_| "hotspot names must be valid UTF-8")?.to_string();
    let dir = format!("{DIR}/ap");
    let _ = std::fs::create_dir_all(&dir);
    let path = format!("{dir}/{ssid}.ap");
    let mut ini = Ini::default();
    let psk = get_s(s, "802-11-wireless-security", "psk");
    if !psk.is_empty() {
        ini.set("Security", "Passphrase", psk);
    }
    let w = s.get("802-11-wireless").cloned().unwrap_or_default();
    let ch = w.u("channel");
    let ch = if ch > 0 {
        ch
    } else {
        match w.s("band").as_str() {
            "a" => 36,
            _ => 6,
        }
    };
    ini.set("General", "Channel", ch.to_string());
    ini.set("IPv4", "Address", address.to_string());
    ini.set("IPv4", "Netmask", "255.255.255.0");
    ini.set("IPv4", "Gateway", address.to_string());
    super::store::write_private(std::path::Path::new(&path), ini.render().as_bytes()).map_err(|e| format!("writing {path}: {e}"))?;
    Ok(ssid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_round_trip() {
        assert_eq!(file_name(b"Fios-6YwHc", "psk"), "Fios-6YwHc.psk");
        let emoji = "local_network 🙄".as_bytes();
        assert_eq!(file_name(emoji, "psk"), "=6c6f63616c5f6e6574776f726b20f09f9984.psk");
        assert_eq!(parse_name("=6c6f63616c5f6e6574776f726b20f09f9984.psk"), Some((emoji.to_vec(), "psk".into())));
        assert_eq!(parse_name("My Net.open"), Some((b"My Net".to_vec(), "open".into())));
        assert_eq!(parse_name(".known_network.freq"), None);
    }

    #[test]
    fn apply_keeps_iwd_keys_until_the_password_changes() {
        let mut ini = Ini::parse("[IPv6]\nEnabled=true\n\n[Security]\nPassphrase=hunter22\nSAE-PT-Group19=abc\n");
        let mut s = form::wifi_join_settings("Cafe", Some("wpa-psk"), "hunter22", false);
        apply(&mut ini, &s);
        assert_eq!(ini.get("Security", "SAE-PT-Group19"), Some("abc"));
        assert_eq!(ini.get("Settings", "AutoConnect"), Some("true"));
        s.get_mut("802-11-wireless-security").unwrap().insert("psk".into(), Val::Str("newpass99".into()));
        apply(&mut ini, &s);
        assert_eq!(ini.get("Security", "SAE-PT-Group19"), None);
        assert_eq!(ini.get("Security", "Passphrase"), Some("newpass99"));
        let back = import(b"Cafe", "psk", &Ini::parse(&ini.render()));
        assert_eq!(back["802-11-wireless-security"].s("psk"), "newpass99");
    }

    #[test]
    fn wep_is_refused() {
        let s = form::wifi_join_settings("Old", Some("none"), "abcde", false);
        assert!(ext_for(&s).is_err());
    }
}
