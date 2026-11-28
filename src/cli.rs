//! Small scriptable commands that talk to the daemon: `status`, `up`, `down`.

use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

use crate::backend::model::Snapshot;
use crate::backend::{Cmd, Ev, SOCKET};

type Lines = tokio::io::Lines<BufReader<tokio::net::unix::OwnedReadHalf>>;

async fn connect() -> color_eyre::Result<(Lines, tokio::net::unix::OwnedWriteHalf, Snapshot)> {
    let s = UnixStream::connect(SOCKET).await.map_err(|e| color_eyre::eyre::eyre!("can't reach the daemon at {SOCKET}: {e}"))?;
    let (r, w) = s.into_split();
    let mut lines = BufReader::new(r).lines();
    loop {
        let l = lines.next_line().await?.ok_or_else(|| color_eyre::eyre::eyre!("the daemon hung up"))?;
        if let Ok(Ev::Snapshot(s)) = serde_json::from_str::<Ev>(&l) {
            return Ok((lines, w, *s));
        }
    }
}

/// Active connections, one per line: name, type, device (tab-separated).
/// With `wifi`, just the name of the active Wi-Fi connection.
pub async fn status(wifi: bool) -> color_eyre::Result<()> {
    let (_, _, snap) = connect().await?;
    for a in &snap.active {
        let dev = a.devices.first().map(|d| d.trim_start_matches("/device/")).unwrap_or("");
        if wifi {
            let is_client = snap.profiles.iter().any(|p| p.path == a.conn_path && p.is_wifi() && p.wifi_mode() != "ap");
            if is_client && a.state == 2 {
                println!("{}", a.id);
                return Ok(());
            }
            continue;
        }
        let state = if a.state == 2 { "" } else { " (activating)" };
        println!("{}\t{}\t{dev}{state}", a.id, crate::backend::model::kind_label(&a.kind));
    }
    Ok(())
}

pub async fn up_down(name: &str, up: bool) -> color_eyre::Result<()> {
    let (mut lines, mut w, snap) = connect().await?;
    let Some(p) = snap.profiles.iter().find(|p| p.id == name || p.uuid == name) else {
        color_eyre::eyre::bail!("no saved connection named “{name}”");
    };
    let cmd = if up {
        Cmd::Activate { profile: p.path.clone(), device: None, label: p.id.clone() }
    } else {
        let Some(a) = snap.active.iter().find(|a| a.conn_path == p.path) else {
            color_eyre::eyre::bail!("“{name}” isn't active");
        };
        Cmd::Deactivate { active: a.path.clone(), label: p.id.clone() }
    };
    let mut l = serde_json::to_string(&cmd)?;
    l.push('\n');
    w.write_all(l.as_bytes()).await?;
    let path = p.path.clone();
    let wait = async {
        while let Some(l) = lines.next_line().await? {
            match serde_json::from_str::<Ev>(&l) {
                Ok(Ev::Ok(m)) => {
                    println!("{m}");
                    return Ok(());
                }
                Ok(Ev::Error(m)) => color_eyre::eyre::bail!("{m}"),
                Ok(Ev::SecretRequest { .. }) => color_eyre::eyre::bail!("“{name}” needs a password; connect from the TUI"),
                // Wi-Fi failures show up as a device state with a reason.
                Ok(Ev::Snapshot(s)) if up => {
                    let failed = s.devices.iter().find(|d| d.active.is_none() && d.state_reason != 0 && d.state_reason != 39 && !d.state.busy());
                    let active = s.profiles.iter().any(|p| p.path == path && p.active_state == Some(2));
                    if active {
                        println!("Connected {name}");
                        return Ok(());
                    }
                    if let Some(d) = failed
                        && s.active.iter().all(|a| a.conn_path != path) {
                            let why = crate::backend::model::reason_text(d.state_reason).unwrap_or("failed");
                            color_eyre::eyre::bail!("{}: couldn't connect — {why}", d.iface);
                        }
                }
                _ => {}
            }
        }
        color_eyre::eyre::bail!("the daemon hung up")
    };
    tokio::time::timeout(Duration::from_secs(60), wait).await.map_err(|_| color_eyre::eyre::eyre!("timed out"))?
}
