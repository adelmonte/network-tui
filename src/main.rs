//! network-tui — a terminal UI for managing network connections, and the
//! daemon (`network-tui daemon`) that does the work.

mod action;
mod app;
mod backend;
mod cli;
mod config;
mod core;
mod daemon;
mod editor;
mod ui;
mod view;

use std::path::PathBuf;
use std::time::Duration;

use clap::{Parser, Subcommand};
use crossterm::event::EventStream;
use futures::StreamExt;

use crate::app::App;
use crate::config::{Config, APP, DEFAULT_TOML};

#[derive(Parser, Debug)]
#[command(name = "network-tui", version, about = "Manage network connections from the terminal")]
struct Cli {
    #[command(subcommand)]
    cmd: Option<Command>,
    /// Use a fake backend with sample networks (no daemon needed)
    #[arg(long)]
    demo: bool,
    /// Config file (default: ~/.config/network-tui/config.toml)
    #[arg(short, long)]
    config: Option<PathBuf>,
    /// Print the default config and exit
    #[arg(long)]
    print_default_config: bool,
    /// Verbose logging to the log file
    #[arg(short, long, global = true)]
    verbose: bool,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Run the network daemon (as root, from your service manager)
    Daemon {
        /// Write a newline to this file descriptor once the socket is up
        #[arg(long, value_name = "FD")]
        ready_fd: Option<i32>,
    },
    /// List active connections (name, type, device)
    Status {
        /// Print only the active Wi-Fi connection's name
        #[arg(long)]
        wifi: bool,
    },
    /// Bring up a saved connection by name
    Up { name: String },
    /// Take down an active connection by name
    Down { name: String },
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> color_eyre::Result<()> {
    color_eyre::install()?;
    let cli = Cli::parse();
    match &cli.cmd {
        Some(Command::Status { wifi }) => return cli::status(*wifi).await,
        Some(Command::Up { name }) => return cli::up_down(name, true).await,
        Some(Command::Down { name }) => return cli::up_down(name, false).await,
        _ => {}
    }
    if let Some(Command::Daemon { ready_fd }) = cli.cmd {
        tracing_subscriber::fmt()
            .with_max_level(if cli.verbose { tracing::Level::DEBUG } else { tracing::Level::INFO })
            .with_target(false)
            .with_writer(std::io::stderr)
            .init();
        return daemon::run(ready_fd).await;
    }
    if cli.print_default_config {
        print!("{DEFAULT_TOML}");
        return Ok(());
    }
    let _log = core::logging::init(APP, cli.verbose);
    let loaded = core::config::load::<Config>(APP, cli.config.as_deref(), DEFAULT_TOML);
    for w in &loaded.warnings {
        tracing::warn!("{w}");
    }
    let mut backend = if cli.demo { backend::demo::spawn() } else { backend::client::spawn() };
    let mut app = App::new(loaded.value, loaded.path, backend.tx.clone(), cli.demo, loaded.warnings);

    let mut term = core::term::init(app.cfg.general.mouse)?;
    let mut events = EventStream::new();
    let mut tick = tokio::time::interval(Duration::from_millis(100));
    let result: color_eyre::Result<()> = async {
        let mut dirty = true;
        let mut animated = false;
        let mut idle_ticks = 0u32;
        loop {
            if dirty {
                term.draw(|f| view::render(&mut app, f))?;
                animated = ui::widgets::take_animated();
                dirty = false;
                idle_ticks = 0;
            }
            tokio::select! {
                e = events.next() => match e {
                    Some(Ok(e)) => {
                        dirty |= ui::widgets::event_redraws(&e);
                        app.on_event(e);
                    }
                    Some(Err(e)) => return Err(e.into()),
                    None => break,
                },
                Some(ev) = backend.rx.recv() => {
                    dirty = true;
                    app.on_backend(ev);
                    while let Ok(ev) = backend.rx.try_recv() {
                        app.on_backend(ev);
                    }
                }
                _ = tick.tick() => {
                    idle_ticks += 1;
                    // Redraw for spinners, expired toasts, and once a second for relative times.
                    dirty |= app.on_tick() | animated | (idle_ticks >= 10);
                }
            }
            if app.quit {
                break;
            }
        }
        Ok(())
    }
    .await;
    core::term::restore();
    result
}
