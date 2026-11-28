//! Run hook scripts when connections come and go, NetworkManager-dispatcher
//! style: each executable in [`DIR`] gets `<interface> <action>` as
//! arguments and CONNECTION_ID, CONNECTION_UUID, DEVICE_IFACE and
//! NM_DISPATCHER_ACTION in its environment. Scripts run one at a time, in
//! name order, in the order events happen.

use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::time::Duration;

use tokio::sync::mpsc::{unbounded_channel, UnboundedSender};

pub const DIR: &str = "/etc/network-tui/dispatcher.d";
const TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Debug)]
pub struct Event {
    pub iface: String,
    /// "up", "down", "dhcp4-change", "vpn-up", "vpn-down"
    pub action: &'static str,
    pub id: String,
    pub uuid: String,
}

pub fn spawn() -> UnboundedSender<Event> {
    let (tx, mut rx) = unbounded_channel::<Event>();
    tokio::spawn(async move {
        while let Some(ev) = rx.recv().await {
            for script in scripts() {
                run(&script, &ev).await;
            }
        }
    });
    tx
}

/// Root-owned executables nobody else can write to, like NM requires.
fn scripts() -> Vec<std::path::PathBuf> {
    let Ok(rd) = std::fs::read_dir(DIR) else { return Vec::new() };
    let mut v: Vec<_> = rd
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            std::fs::metadata(p).is_ok_and(|m| {
                let mode = m.permissions().mode();
                m.is_file() && m.uid() == 0 && mode & 0o111 != 0 && mode & 0o022 == 0
            })
        })
        .collect();
    v.sort();
    v
}

async fn run(script: &std::path::Path, ev: &Event) {
    let mut cmd = tokio::process::Command::new(script);
    cmd.arg(&ev.iface)
        .arg(ev.action)
        .env_clear()
        .env("PATH", "/usr/local/sbin:/usr/local/bin:/usr/bin")
        .env("CONNECTION_ID", &ev.id)
        .env("CONNECTION_UUID", &ev.uuid)
        .env("DEVICE_IFACE", &ev.iface)
        .env("NM_DISPATCHER_ACTION", ev.action)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true);
    match cmd.spawn() {
        Ok(mut child) => match tokio::time::timeout(TIMEOUT, child.wait()).await {
            Ok(Ok(st)) if !st.success() => tracing::info!("dispatcher {}: {} {} exited with {st}", script.display(), ev.iface, ev.action),
            Err(_) => tracing::warn!("dispatcher {}: timed out after {}s", script.display(), TIMEOUT.as_secs()),
            _ => {}
        },
        Err(e) => tracing::warn!("dispatcher {}: {e}", script.display()),
    }
}
