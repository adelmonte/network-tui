//! Saved profiles (one JSON file per profile, in NetworkManager's settings
//! layout) and the daemon's own small state file.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::backend::val::{Dict, DictExt, Settings, Val};

pub const DIR: &str = "/var/lib/network-tui";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct State {
    pub networking: bool,
    /// Interfaces the user told us to leave alone.
    pub unmanaged: BTreeSet<String>,
    /// Interfaces with auto-connect switched off.
    pub no_autoconnect: BTreeSet<String>,
    pub wired_counter: u32,
}

impl Default for State {
    fn default() -> Self {
        Self { networking: true, unmanaged: BTreeSet::new(), no_autoconnect: BTreeSet::new(), wired_counter: 0 }
    }
}

pub struct Store {
    dir: PathBuf,
    pub profiles: BTreeMap<String, Settings>,
    pub state: State,
}

impl Store {
    pub fn load() -> Self {
        Self::load_from(Path::new(DIR))
    }

    pub fn load_from(dir: &Path) -> Self {
        let _ = std::fs::create_dir_all(dir.join("profiles"));
        let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
        let mut profiles = BTreeMap::new();
        if let Ok(rd) = std::fs::read_dir(dir.join("profiles")) {
            for e in rd.flatten() {
                let p = e.path();
                if p.extension().is_none_or(|x| x != "json") {
                    continue;
                }
                match std::fs::read(&p).map_err(|e| e.to_string()).and_then(|b| serde_json::from_slice::<Settings>(&b).map_err(|e| e.to_string())) {
                    Ok(s) => {
                        let u = uuid(&s);
                        if !u.is_empty() {
                            profiles.insert(u, s);
                        }
                    }
                    Err(e) => tracing::warn!("skipping {}: {e}", p.display()),
                }
            }
        }
        let state = std::fs::read(dir.join("state.json")).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default();
        Self { dir: dir.to_path_buf(), profiles, state }
    }

    pub fn file_of(&self, uuid: &str) -> PathBuf {
        self.dir.join("profiles").join(format!("{uuid}.json"))
    }

    pub fn vpn_dir(&self) -> PathBuf {
        self.dir.join("vpn")
    }

    pub fn put(&mut self, s: Settings) -> std::io::Result<String> {
        let u = uuid(&s);
        write_private(&self.file_of(&u), &serde_json::to_vec_pretty(&s).expect("settings serialize"))?;
        self.profiles.insert(u.clone(), s);
        Ok(u)
    }

    pub fn remove(&mut self, uuid: &str) -> Option<Settings> {
        let _ = std::fs::remove_file(self.file_of(uuid));
        self.profiles.remove(uuid)
    }

    pub fn save_state(&self) {
        if let Err(e) = write_private(&self.dir.join("state.json"), &serde_json::to_vec_pretty(&self.state).expect("state serialize")) {
            tracing::warn!("saving state: {e}");
        }
    }

    pub fn by_ssid(&self, ssid: &[u8]) -> Vec<&Settings> {
        let mut v: Vec<&Settings> = self.profiles.values().filter(|s| is_wifi_client(s) && ssid_of(s).as_deref() == Some(ssid)).collect();
        v.sort_by_key(|s| {
            let c = conn(s);
            (std::cmp::Reverse(c.i("autoconnect-priority")), std::cmp::Reverse(c.i("timestamp")))
        });
        v
    }

    pub fn touch(&mut self, uuid: &str) {
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
        if let Some(mut s) = self.profiles.get(uuid).cloned() {
            s.entry("connection".into()).or_default().insert("timestamp".into(), Val::U64(now));
            let _ = self.put(s);
        }
    }
}

/// Write a file only root can read, atomically.
pub fn write_private(path: &Path, data: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    {
        let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)
}

pub fn conn(s: &Settings) -> Dict {
    s.get("connection").cloned().unwrap_or_default()
}

pub fn uuid(s: &Settings) -> String {
    s.get("connection").map(|c| c.s("uuid")).unwrap_or_default()
}

pub fn kind(s: &Settings) -> String {
    s.get("connection").map(|c| c.s("type")).unwrap_or_default()
}

pub fn id(s: &Settings) -> String {
    s.get("connection").map(|c| c.s("id")).unwrap_or_default()
}

pub fn iface(s: &Settings) -> String {
    s.get("connection").map(|c| c.s("interface-name")).unwrap_or_default()
}

pub fn autoconnect(s: &Settings) -> bool {
    s.get("connection").and_then(|c| c.opt_b("autoconnect")).unwrap_or(true)
}

pub fn get_s(s: &Settings, setting: &str, key: &str) -> String {
    s.get(setting).map(|d| d.s(key)).unwrap_or_default()
}

pub fn ssid_of(s: &Settings) -> Option<Vec<u8>> {
    s.get("802-11-wireless").and_then(|w| w.get("ssid")).and_then(Val::bytes).map(<[u8]>::to_vec)
}

pub fn is_wifi_client(s: &Settings) -> bool {
    kind(s) == "802-11-wireless" && get_s(s, "802-11-wireless", "mode") != "ap"
}

pub fn is_hotspot(s: &Settings) -> bool {
    kind(s) == "802-11-wireless" && get_s(s, "802-11-wireless", "mode") == "ap"
}

pub fn kind_is_hotspot(st: &Store, uuid: &str) -> bool {
    st.profiles.get(uuid).is_some_and(is_hotspot)
}

const SECRET_KEYS: &[(&str, &str)] = &[
    ("802-11-wireless-security", "psk"),
    ("802-11-wireless-security", "wep-key0"),
    ("802-11-wireless-security", "wep-key1"),
    ("802-11-wireless-security", "wep-key2"),
    ("802-11-wireless-security", "wep-key3"),
    ("802-11-wireless-security", "leap-password"),
    ("802-1x", "password"),
    ("802-1x", "private-key-password"),
    ("802-1x", "phase2-private-key-password"),
    ("wireguard", "private-key"),
    ("vpn", "secrets"),
];

/// A copy with every secret removed (what clients get in snapshots).
pub fn strip_secrets(s: &Settings) -> Settings {
    let mut s = s.clone();
    for (setting, key) in SECRET_KEYS {
        if let Some(d) = s.get_mut(*setting) {
            d.remove(*key);
        }
    }
    if let Some(Val::DictList(peers)) = s.get_mut("wireguard").and_then(|w| w.get_mut("peers")) {
        for p in peers {
            p.remove("preshared-key");
        }
    }
    s
}

/// Fill secrets the client left out (it never had them) from the stored copy.
pub fn merge_secrets(new: &mut Settings, old: &Settings) {
    for (setting, key) in SECRET_KEYS {
        if let (Some(d), Some(v)) = (new.get_mut(*setting), old.get(*setting).and_then(|o| o.get(*key)))
            && !d.contains_key(*key) {
                d.insert(key.to_string(), v.clone());
            }
    }
    let old_peers: Vec<Dict> = old.get("wireguard").and_then(|w| w.get("peers")).map(|p| p.dict_list().to_vec()).unwrap_or_default();
    if let Some(Val::DictList(peers)) = new.get_mut("wireguard").and_then(|w| w.get_mut("peers")) {
        for p in peers {
            if p.contains_key("preshared-key") {
                continue;
            }
            let pk = p.s("public-key");
            if let Some(v) = old_peers.iter().find(|o| o.s("public-key") == pk).and_then(|o| o.get("preshared-key")) {
                p.insert("preshared-key".into(), v.clone());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::form;

    #[test]
    fn secrets_are_stripped_and_merged_back() {
        let s = form::wifi_join_settings("Cafe", Some("wpa-psk"), "hunter22", false);
        let stripped = strip_secrets(&s);
        assert!(stripped["802-11-wireless-security"].get("psk").is_none());
        let mut edited = stripped.clone();
        edited.get_mut("connection").unwrap().insert("id".into(), Val::Str("Cafe 2".into()));
        merge_secrets(&mut edited, &s);
        assert_eq!(edited["802-11-wireless-security"].s("psk"), "hunter22");
        assert_eq!(id(&edited), "Cafe 2");
    }

    #[test]
    fn store_round_trip() {
        let dir = std::env::temp_dir().join(format!("ntui-store-{}", std::process::id()));
        let mut st = Store::load_from(&dir);
        let s = form::wifi_join_settings("Cafe", Some("wpa-psk"), "hunter22", false);
        let u = st.put(s.clone()).unwrap();
        let st2 = Store::load_from(&dir);
        assert_eq!(st2.profiles.get(&u), Some(&s));
        assert_eq!(st2.by_ssid(b"Cafe").len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
