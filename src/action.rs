//! Every user-triggerable action. Names are `[keys]` config names; the
//! descriptions feed help, footer and the command palette.

use crate::define_actions;

define_actions! {
    pub enum Action {
        // global
        Quit => "quit", "Quit", ["q", "ctrl-c"],
        Help => "help", "Show keys & help", ["?", "f1"],
        Palette => "palette", "Command palette", [":", "ctrl-p"],
        NextTab => "next_tab", "Next tab", ["tab", "L"],
        PrevTab => "prev_tab", "Previous tab", ["shift-tab", "H"],
        TabWifi => "tab_wifi", "Go to Wi-Fi", ["1"],
        TabConnections => "tab_connections", "Go to Connections", ["2"],
        TabDevices => "tab_devices", "Go to Devices", ["3"],
        TabGeneral => "tab_general", "Go to General", ["4"],
        Up => "up", "Move up", ["k", "up"],
        Down => "down", "Move down", ["j", "down"],
        Top => "top", "Jump to top", ["g", "home"],
        Bottom => "bottom", "Jump to bottom", ["G", "end"],
        PageUp => "page_up", "Page up", ["pgup", "ctrl-u"],
        PageDown => "page_down", "Page down", ["pgdn", "ctrl-d"],
        Filter => "filter", "Filter list", ["/"],
        Menu => "menu", "Actions for selection", ["m", "."],
        Details => "details", "Show/hide details panel", ["i"],
        WifiRadio => "wifi_radio", "Wi-Fi radio on/off", ["w"],
        // wifi
        Connect => "connect", "Connect / disconnect", ["enter", "space"],
        Scan => "scan", "Scan for networks", ["s", "f5"],
        Forget => "forget", "Forget saved network", ["x", "delete"],
        Edit => "edit", "Edit settings", ["e"],
        Autoconnect => "autoconnect", "Auto-connect on/off", ["a"],
        Hidden => "hidden", "Join a hidden network", ["n"],
        Hotspot => "hotspot", "Start/stop hotspot", ["h"],
        Share => "share", "Share network (QR code)", ["y"],
        // connections
        Activate => "activate", "Activate / deactivate", ["enter", "space"],
        NewProfile => "new_profile", "New connection", ["n"],
        DeleteProfile => "delete_profile", "Delete connection", ["x", "delete"],
        EditProfile => "edit_profile", "Edit connection", ["e"],
        ProfileAutoconnect => "profile_autoconnect", "Auto-connect on/off", ["a"],
        Import => "import", "Import VPN config file", ["I"],
        // devices
        DeviceToggle => "device_toggle", "Connect / disconnect device", ["enter", "space"],
        Managed => "managed", "Let NetworkManager manage it", ["M"],
        DeviceAutoconnect => "device_autoconnect", "Device auto-connect on/off", ["a"],
        // general
        GeneralActivate => "general_activate", "Change selected setting", ["enter", "space"],
        Hostname => "hostname", "Set hostname", ["e"],
        Networking => "networking", "Networking on/off", ["N"],
        Airplane => "airplane", "Airplane mode", ["A"],
        CheckConnectivity => "check", "Check internet connectivity", ["c"],
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ctx {
    Wifi,
    Connections,
    Devices,
    General,
}

impl Action {
    pub fn ctx(self) -> Option<Ctx> {
        use Action::*;
        Some(match self {
            Connect | Scan | Forget | Edit | Autoconnect | Hidden | Hotspot | Share => Ctx::Wifi,
            Activate | NewProfile | DeleteProfile | EditProfile | ProfileAutoconnect | Import => Ctx::Connections,
            DeviceToggle | Managed | DeviceAutoconnect => Ctx::Devices,
            GeneralActivate | Hostname | Networking | Airplane | CheckConnectivity => Ctx::General,
            _ => return None,
        })
    }

    pub fn available(self, ctx: Ctx) -> bool {
        self.ctx().is_none_or(|c| c == ctx)
    }

    pub fn is_toggle(self) -> bool {
        use Action::*;
        matches!(self, Connect | Activate | DeviceToggle | WifiRadio | Autoconnect | ProfileAutoconnect | DeviceAutoconnect | Managed | Networking | Airplane | Hotspot | GeneralActivate)
    }

    pub fn footer(ctx: Ctx) -> &'static [Action] {
        use Action::*;
        match ctx {
            Ctx::Wifi => &[Connect, Scan, Edit, Forget, Hidden, Hotspot, Share, Filter, Help],
            Ctx::Connections => &[Activate, EditProfile, NewProfile, DeleteProfile, Import, Filter, Help],
            Ctx::Devices => &[DeviceToggle, Managed, DeviceAutoconnect, Help],
            Ctx::General => &[GeneralActivate, Hostname, Airplane, CheckConnectivity, Help],
        }
    }

    pub fn section(self) -> &'static str {
        match self.ctx() {
            None => "General keys",
            Some(Ctx::Wifi) => "Wi-Fi tab",
            Some(Ctx::Connections) => "Connections tab",
            Some(Ctx::Devices) => "Devices tab",
            Some(Ctx::General) => "General tab",
        }
    }
}
