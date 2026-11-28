//! OpenVPN connections: run `openvpn` as a child and watch its log.

use std::collections::BTreeMap;
use std::path::Path;
use std::process::Stdio;

use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::mpsc::UnboundedSender;
use tokio::task::JoinHandle;

use crate::backend::form;
use crate::backend::val::{Settings, Val};

use super::Internal;

pub const SERVICE: &str = "org.freedesktop.NetworkManager.openvpn";
const RUN_DIR: &str = "/run/network-tui";

#[derive(Clone, Debug)]
pub enum VpnEv {
    Started(u32),
    Device(String),
    Up,
    Down(String),
}

/// Does the config want a username and password?
pub fn wants_auth(config: &Path) -> bool {
    std::fs::read_to_string(config).map(|t| t.lines().any(|l| l.trim() == "auth-user-pass")).unwrap_or(false)
}

pub fn spawn(uuid: String, config: String, auth: Option<(String, String)>, tx: UnboundedSender<Internal>) -> JoinHandle<()> {
    tokio::spawn(async move {
        let send = |ev| {
            let _ = tx.send(Internal::Vpn { uuid: uuid.clone(), ev });
        };
        let mut cmd = tokio::process::Command::new("openvpn");
        cmd.args(["--config", &config, "--auth-nocache", "--verb", "3"]);
        let config_dir = Path::new(&config).parent().map(Path::to_path_buf);
        if let Some(d) = &config_dir {
            cmd.current_dir(d);
        }
        let auth_file = format!("{RUN_DIR}/{uuid}.auth");
        if let Some((u, p)) = &auth {
            let _ = std::fs::create_dir_all(RUN_DIR);
            if let Err(e) = super::store::write_private(Path::new(&auth_file), format!("{u}\n{p}\n").as_bytes()) {
                return send(VpnEv::Down(format!("can't write credentials: {e}")));
            }
            cmd.args(["--auth-user-pass", &auth_file]);
        }
        cmd.stdout(Stdio::piped()).stderr(Stdio::null()).stdin(Stdio::null()).kill_on_drop(true);
        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => return send(VpnEv::Down(format!("can't run openvpn (is it installed?): {e}"))),
        };
        if let Some(pid) = child.id() {
            send(VpnEv::Started(pid));
        }
        let mut lines = BufReader::new(child.stdout.take().expect("piped")).lines();
        let mut reason = String::from("OpenVPN exited");
        while let Ok(Some(l)) = lines.next_line().await {
            tracing::debug!("openvpn: {l}");
            if l.contains("Initialization Sequence Completed") {
                let _ = std::fs::remove_file(&auth_file);
                send(VpnEv::Up);
            } else if let Some(rest) = l.split("TUN/TAP device ").nth(1)
                && let Some(dev) = rest.strip_suffix(" opened") {
                    send(VpnEv::Device(dev.to_string()));
                } else if l.contains("AUTH_FAILED") {
                reason = "authentication failed (wrong username or password?)".into();
            } else if l.contains("Exiting due to fatal error") || l.contains("Options error") {
                reason = l.split_once(' ').map(|x| x.1).unwrap_or(&l).to_string();
            }
        }
        let _ = child.wait().await;
        let _ = std::fs::remove_file(&auth_file);
        send(VpnEv::Down(reason));
    })
}

/// Copy an .ovpn file into our store and make a profile for it.
pub fn import(file: &Path, vpn_dir: &Path) -> Result<Settings, String> {
    let text = std::fs::read_to_string(file).map_err(|e| format!("can't read {}: {e}", file.display()))?;
    if !text.lines().any(|l| l.trim_start().starts_with("remote ")) {
        return Err("that doesn't look like an OpenVPN config (no “remote” line)".into());
    }
    let name = file.file_stem().map(|s| s.to_string_lossy().to_string()).unwrap_or_else(|| "VPN".into());
    let mut s = form::new_settings("vpn", &name);
    let uuid = super::store::uuid(&s);
    std::fs::create_dir_all(vpn_dir).map_err(|e| e.to_string())?;
    let dest = vpn_dir.join(format!("{uuid}.ovpn"));
    super::store::write_private(&dest, text.as_bytes()).map_err(|e| format!("can't save the config: {e}"))?;
    s.get_mut("connection").expect("set").insert("autoconnect".into(), Val::Bool(false));
    let mut data = BTreeMap::new();
    data.insert("config".to_string(), dest.to_string_lossy().to_string());
    data.insert("connection-type".to_string(), if wants_auth(&dest) { "password" } else { "tls" }.to_string());
    let mut vpn = crate::backend::val::Dict::new();
    vpn.insert("service-type".into(), Val::Str(SERVICE.into()));
    vpn.insert("data".into(), Val::StrMap(data));
    s.insert("vpn".into(), vpn);
    Ok(s)
}

pub fn data(s: &Settings, key: &str) -> String {
    match s.get("vpn").and_then(|v| v.get("data")) {
        Some(Val::StrMap(m)) => m.get(key).cloned().unwrap_or_default(),
        _ => String::new(),
    }
}

pub fn secret(s: &Settings, key: &str) -> String {
    match s.get("vpn").and_then(|v| v.get("secrets")) {
        Some(Val::StrMap(m)) => m.get(key).cloned().unwrap_or_default(),
        _ => String::new(),
    }
}

pub fn set_secret(s: &mut Settings, key: &str, val: &str) {
    let v = s.entry("vpn".into()).or_default();
    let mut m = match v.remove("secrets") {
        Some(Val::StrMap(m)) => m,
        _ => BTreeMap::new(),
    };
    m.insert(key.to_string(), val.to_string());
    v.insert("secrets".into(), Val::StrMap(m));
}

pub fn set_data(s: &mut Settings, key: &str, val: &str) {
    let v = s.entry("vpn".into()).or_default();
    let mut m = match v.remove("data") {
        Some(Val::StrMap(m)) => m,
        _ => BTreeMap::new(),
    };
    m.insert(key.to_string(), val.to_string());
    v.insert("data".into(), Val::StrMap(m));
}
