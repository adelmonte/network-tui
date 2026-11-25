//! Backend interface: the UI sends [`Cmd`]s and receives [`Ev`]s.
//! [`nm`] talks to NetworkManager over D-Bus; [`demo`] fakes it.
//!
//! NetworkManager is the only real backend. On the target machine NM uses iwd
//! for Wi-Fi underneath (`wifi.backend=iwd`), which is transparent here.

pub mod demo;
pub mod form;
pub mod model;
pub mod nm;
pub mod val;

use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

use model::Snapshot;
use val::{Dict, Settings};

#[derive(Clone, Debug)]
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
    Import { kind: String, file: String },
    SecretReply { id: u64, secrets: Option<Dict> },
}

/// What the secret agent is asking the user for.
#[derive(Clone, Debug, PartialEq)]
pub struct SecretRequest {
    pub conn_id: String,
    pub setting: String,
    /// The key to fill in within `setting`, e.g. "psk", "password".
    pub key: String,
    /// NM says the previous secret was wrong.
    pub retry: bool,
}

#[derive(Clone, Debug)]
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
