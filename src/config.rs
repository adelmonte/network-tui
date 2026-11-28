//! network-tui configuration (`~/.config/network-tui/config.toml`).

use std::collections::HashMap;

use serde::Deserialize;

use crate::ui::theme::ThemeConfig;

pub const APP: &str = "network-tui";

pub const DEFAULT_TOML: &str = r##"# network-tui configuration
# Every option is listed here with its default value.
# Delete a line to go back to the default. Restart the app to apply.

[general]
# Icon set: "nerd" (Nerd Font glyphs; kitty ships them), "unicode", or "ascii"
icons = "nerd"
# Enable mouse: click, double-click to connect, right-click for a menu, wheel to scroll
mouse = true
# Show the details panel when the terminal is wide enough
details = true
# Ask before forgetting networks or deleting connections
confirm_delete = true
# Show signal as "bars", "percent", or "both"
signal = "both"

[wifi]
# Hide networks weaker than this (0-100). 0 shows everything.
min_signal = 0
# Ask for a scan when the app opens (iwd also scans on its own)
scan_on_start = true
# Defaults for a new hotspot. Empty name = "<hostname>-hotspot".
hotspot_name = ""
# "" (automatic), "bg" (2.4 GHz, best range/compatibility), or "a" (5 GHz, faster)
hotspot_band = "bg"
# New Wi-Fi profiles: MAC address to show networks. "" (the card's own address),
# "stable" (random but fixed per network), "random" (new every time), "permanent"
new_profile_mac = "stable"

[theme]
# preset = "dark"        # "dark" or "mono". The NO_COLOR env var also forces mono.
# accent = "#a6e3a1"
# fg = "reset"
# dim = "#6c7086"
# border = "#45475a"
# selection = "#313244"
# ok = "#a6e3a1"
# warn = "#f9e2af"
# error = "#f38ba8"
# info = "#89dceb"

[keys]
# Rebind any action: action_name = ["key", "another-key"]. [] unbinds.
# Key syntax: "j", "J", "ctrl-p", "alt-x", "shift-tab", "enter", "space",
# "esc", "up", "pgdn", "home", "delete", "f1".
# Press `?` in the app to see every action name and its current keys.
# connect = ["enter", "space"]
"##;

#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
#[derive(Default)]
pub struct Config {
    pub general: General,
    pub wifi: Wifi,
    pub theme: ThemeConfig,
    pub keys: HashMap<String, Vec<String>>,
}


#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum IconSet {
    Nerd,
    Unicode,
    Ascii,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SignalStyle {
    Bars,
    Percent,
    Both,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct General {
    #[serde(default = "d_icons")]
    pub icons: IconSet,
    #[serde(default = "d_true")]
    pub mouse: bool,
    #[serde(default = "d_true")]
    pub details: bool,
    #[serde(default = "d_true")]
    pub confirm_delete: bool,
    #[serde(default = "d_signal")]
    pub signal: SignalStyle,
}

impl Default for General {
    fn default() -> Self {
        toml::from_str("").expect("general defaults")
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Wifi {
    #[serde(default)]
    pub min_signal: u8,
    #[serde(default = "d_true")]
    pub scan_on_start: bool,
    #[serde(default)]
    pub hotspot_name: String,
    #[serde(default = "d_band")]
    pub hotspot_band: String,
    #[serde(default = "d_mac")]
    pub new_profile_mac: String,
}

impl Default for Wifi {
    fn default() -> Self {
        toml::from_str("").expect("wifi defaults")
    }
}

fn d_true() -> bool {
    true
}
fn d_icons() -> IconSet {
    IconSet::Nerd
}
fn d_signal() -> SignalStyle {
    SignalStyle::Both
}
fn d_band() -> String {
    "bg".into()
}
fn d_mac() -> String {
    "stable".into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_file_matches_struct_defaults() {
        let c: Config = toml::from_str(DEFAULT_TOML).unwrap();
        let d = Config::default();
        assert_eq!(c.general.signal, d.general.signal);
        assert_eq!(c.wifi.hotspot_band, d.wifi.hotspot_band);
        assert_eq!(c.wifi.new_profile_mac, d.wifi.new_profile_mac);
        assert_eq!(c.wifi.scan_on_start, d.wifi.scan_on_start);
    }

    #[test]
    fn unknown_keys_rejected() {
        assert!(toml::from_str::<Config>("[wifi]\nnope = 1").is_err());
    }
}
