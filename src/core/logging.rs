//! File logging. A TUI owns the terminal, so logs go to
//! `$XDG_STATE_HOME/<app>/<app>.log` (or `~/.local/state/...`).

use std::path::PathBuf;

use tracing_appender::non_blocking::WorkerGuard;

pub fn log_dir(app: &str) -> PathBuf {
    dirs::state_dir()
        .or_else(dirs::cache_dir)
        .unwrap_or_else(std::env::temp_dir)
        .join(app)
}

/// Start logging. Keep the returned guard alive for the program's lifetime.
pub fn init(app: &str, verbose: bool) -> Option<WorkerGuard> {
    let dir = log_dir(app);
    std::fs::create_dir_all(&dir).ok()?;
    let appender = tracing_appender::rolling::never(&dir, format!("{app}.log"));
    let (writer, guard) = tracing_appender::non_blocking(appender);
    let level = if verbose { tracing::Level::DEBUG } else { tracing::Level::INFO };
    tracing_subscriber::fmt()
        .with_writer(writer)
        .with_ansi(false)
        .with_max_level(level)
        .try_init()
        .ok()?;
    Some(guard)
}
