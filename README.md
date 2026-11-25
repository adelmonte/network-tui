# network-tui

![screenshot](demo.png)

A terminal NetworkManager client, written in Rust with [ratatui](https://ratatui.rs). It covers what nmtui does, with a keyboard and mouse interface.

- Wi-Fi: scan, connect, forget, hidden networks, hotspot, QR code sharing
- Ethernet, Wi-Fi, WireGuard, VPN, VLAN, bridge and bond connections; import `.ovpn` and WireGuard files
- Full connection editor: MAC privacy, enterprise Wi-Fi, static IP, DNS, routes, with validation before saving
- Interface state, addresses, gateway, DNS and link speed
- Hostname, airplane mode, radios and connectivity check
- Built-in password agent and readable error messages
- Works with the iwd Wi-Fi backend
- Mouse and keyboard throughout

## Install

### Arch Linux

A PKGBUILD is in [`packaging/`](packaging/PKGBUILD):

```sh
git clone https://github.com/adelmonte/network-tui
cd network-tui/packaging
makepkg -si
```

### From source

Needs Rust 1.85+.

```sh
cargo build --release
install -Dm755 target/release/network-tui ~/.local/bin/network-tui
```

At runtime it needs NetworkManager. Changing connections goes through polkit, like `nmcli`.

## Usage

```
network-tui [--demo] [-c|--config PATH] [--print-default-config]
```

| Option | |
|---|---|
| `--demo` | Run with fake networks |
| `-c`, `--config PATH` | Use a config file other than `~/.config/network-tui/config.toml` |
| `--print-default-config` | Print the default config and exit |

### Keys

| Key | Action |
|---|---|
| `1`–`4`, `Tab` | Wi-Fi / Connections / Devices / General |
| `j` / `k`, `↓` / `↑` | Move |
| `Enter` | Connect / disconnect |
| `s` | Scan |
| `e` | Edit |
| `n` | Hidden network / new connection |
| `x` | Forget / delete |
| `h` | Hotspot |
| `y` | Share as QR code |
| `/` | Filter |
| `:`, `Ctrl-P` | Command palette |
| `?` | All keys |

## Configuration

`~/.config/network-tui/config.toml` is created on first run with every option commented: icons, colors, key bindings, signal display, hotspot defaults and MAC privacy for new networks.

## License

GPL-3.0-or-later
