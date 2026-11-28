//! Terminal lifecycle: raw mode, alternate screen, mouse capture,
//! and a panic hook that restores the terminal before printing.

use std::io::{stdout, Stdout};

use crossterm::{
    event::{DisableBracketedPaste, DisableMouseCapture, EnableBracketedPaste},
    style::Print,
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, Clear, ClearType, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Terminal};

pub type Term = Terminal<CrosstermBackend<Stdout>>;

pub fn init(mouse: bool) -> std::io::Result<Term> {
    install_panic_hook();
    enable_raw_mode()?;
    let mut out = stdout();
    // Clear with a plain escape instead of `Terminal::clear()`: that one asks
    // the terminal for the cursor position and fails outright when no reply
    // arrives in time (slow SSH, some multiplexers) — impala issues #171/#174.
    execute!(out, EnterAlternateScreen, EnableBracketedPaste, Clear(ClearType::All))?;
    if mouse {
        // Clicks, drags and wheel in SGR encoding, but not crossterm's
        // any-motion mode (1003): that reports every cell the pointer crosses.
        execute!(out, Print("\x1b[?1000h\x1b[?1002h\x1b[?1006h"))?;
    }
    Terminal::new(CrosstermBackend::new(out))
}

pub fn restore() {
    let _ = disable_raw_mode();
    let _ = execute!(stdout(), DisableMouseCapture, DisableBracketedPaste, LeaveAlternateScreen);
    let _ = execute!(stdout(), crossterm::cursor::Show);
}

fn install_panic_hook() {
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        restore();
        prev(info);
    }));
}
