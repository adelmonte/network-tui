//! Backend interface: the UI sends [`Cmd`]s and receives [`Ev`]s.
//! [`client`] talks to the network-tui daemon over its Unix socket (JSON
//! lines of these same types); [`demo`] fakes it.

pub mod client;
pub mod demo;
pub mod form;
pub mod model;
pub mod val;

use serde::{Deserialize, Serialize};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

use model::Snapshot;
use val::{Dict, Settings};

/// Where the daemon listens.
pub const SOCKET: &str = "/run/network-tui.sock";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Cmd {
    Scan(String),
    /// Join a network: reuse `profile` if given, else create one from `settings`.
    ConnectWifi { device: String, ap: String, profile: Option<String>, settings: Option<Settings>, label: String },
    Activate { profile: String, device: Option<String>, label: String },
    Deactivate { active: String, label: String },
    DisconnectDevice { device: String, label: String },
    AddProfile { settings: Settings, activate_on: Option<String> },
    UpdateProfile { path: String, settings: Settings },
    DeleteProfile { path: String, label: String },
    /// Fetch secrets (for editing or sharing a network).
    GetSecrets { path: String, setting: String },
    SetWifiEnabled(bool),
    SetWwanEnabled(bool),
    SetNetworkingEnabled(bool),
    SetHostname(String),
    CheckConnectivity,
    SetManaged { device: String, on: bool },
    SetDeviceAutoconnect { device: String, on: bool },
    /// Import a VPN config; the client reads the file and sends its contents.
    Import { kind: String, file: String, contents: String },
    SecretReply { id: u64, secrets: Option<Dict> },
}

/// What the secret agent is asking the user for.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SecretRequest {
    pub conn_id: String,
    pub setting: String,
    /// The key to fill in within `setting`, e.g. "psk", "password".
    pub key: String,
    /// The previous secret was rejected.
    pub retry: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Ev {
    Unavailable(String),
    Snapshot(Box<Snapshot>),
    Busy { key: String, label: String, on: bool },
    Ok(String),
    Info(String),
    Error(String),
    Secrets { path: String, setting: String, values: Dict },
    SecretRequest { id: u64, req: SecretRequest },
    SecretCancelled(u64),
}

pub struct Handle {
    pub tx: UnboundedSender<Cmd>,
    pub rx: UnboundedReceiver<Ev>,
}
