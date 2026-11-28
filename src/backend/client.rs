//! Talks to the network-tui daemon over its Unix socket: one JSON [`Cmd`]
//! per line out, one JSON [`Ev`] per line in. Reconnects on its own, so the
//! app survives the daemon restarting.

use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};

use super::{Cmd, Ev, Handle, SOCKET};

pub fn spawn() -> Handle {
    let (tx, cmd_rx) = unbounded_channel();
    let (ev_tx, rx) = unbounded_channel();
    tokio::spawn(run(cmd_rx, ev_tx));
    Handle { tx, rx }
}

async fn run(mut cmds: UnboundedReceiver<Cmd>, ev: UnboundedSender<Ev>) {
    let mut told = false;
    loop {
        match UnixStream::connect(SOCKET).await {
            Ok(stream) => {
                told = false;
                if !session(stream, &mut cmds, &ev).await {
                    return;
                }
                let _ = ev.send(Ev::Unavailable("Lost the connection to the network-tui daemon — reconnecting…".into()));
            }
            Err(e) => {
                if !told {
                    told = true;
                    let hint = match e.kind() {
                        std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused => {
                            "The daemon isn't running. Start it with: sudo svctrl start network-tui"
                        }
                        std::io::ErrorKind::PermissionDenied => "Permission denied on the daemon's socket.",
                        _ => "Can't reach the daemon.",
                    };
                    let _ = ev.send(Ev::Unavailable(format!("{hint} ({SOCKET}: {e})")));
                }
            }
        }
        // Drop commands typed while disconnected rather than replaying them later.
        while cmds.try_recv().is_ok() {}
        tokio::time::sleep(Duration::from_secs(1)).await;
        if ev.is_closed() {
            return;
        }
    }
}

/// One connection. Returns false when the app is shutting down.
async fn session(stream: UnixStream, cmds: &mut UnboundedReceiver<Cmd>, ev: &UnboundedSender<Ev>) -> bool {
    let (r, mut w) = stream.into_split();
    let mut lines = BufReader::new(r).lines();
    loop {
        tokio::select! {
            line = lines.next_line() => match line {
                Ok(Some(l)) => match serde_json::from_str::<Ev>(&l) {
                    Ok(e) => {
                        if ev.send(e).is_err() {
                            return false;
                        }
                    }
                    Err(e) => tracing::warn!("bad message from daemon: {e}"),
                },
                _ => return true,
            },
            cmd = cmds.recv() => match cmd {
                Some(c) => {
                    let mut l = serde_json::to_string(&c).expect("commands serialize");
                    l.push('\n');
                    if w.write_all(l.as_bytes()).await.is_err() {
                        return true;
                    }
                }
                None => return false,
            },
        }
    }
}
