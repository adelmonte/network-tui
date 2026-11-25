//! Common widgets shared by all three apps.

use std::time::{Duration, Instant};

use ratatui::{
    layout::{Alignment, Constraint, Flex, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Clear, Paragraph, Wrap},
    Frame,
};
use unicode_width::UnicodeWidthStr;

use super::mouse::MouseMap;
use super::theme::Theme;

pub const SPINNER: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

pub fn spinner(tick: u64) -> &'static str {
    SPINNER[(tick as usize) % SPINNER.len()]
}

/// A rect of at most `w` x `h`, centred in `area`.
pub fn centered(area: Rect, w: u16, h: u16) -> Rect {
    let [v] = Layout::vertical([Constraint::Length(h.min(area.height))]).flex(Flex::Center).areas(area);
    let [r] = Layout::horizontal([Constraint::Length(w.min(area.width))]).flex(Flex::Center).areas(v);
    r
}

pub fn panel<'a>(theme: &Theme, title: &'a str, focused: bool) -> Block<'a> {
    Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(theme.border(focused))
        .title(Span::styled(
            format!(" {title} "),
            if focused { theme.accent().add_modifier(Modifier::BOLD) } else { theme.dim() },
        ))
}

/// Clear `area`, draw a modal frame and return the inner rect.
pub fn popup(f: &mut Frame, area: Rect, theme: &Theme, title: &str) -> Rect {
    f.render_widget(Clear, area);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(theme.accent())
        .title(Span::styled(format!(" {title} "), theme.accent().add_modifier(Modifier::BOLD)));
    let inner = block.inner(area);
    f.render_widget(block, area);
    inner
}

/// Tab bar: ` 1 Devices │ 2 Adapters `. Each tab is clickable. When the
/// titles don't fit, other tabs collapse to their number.
pub fn tabs<T: Clone>(
    f: &mut Frame,
    area: Rect,
    titles: &[&str],
    selected: usize,
    theme: &Theme,
    mouse: &mut MouseMap<T>,
    target: impl Fn(usize) -> T,
) {
    let full: usize = titles.iter().enumerate().map(|(i, t)| format!(" {} {} ", i + 1, t).width()).sum::<usize>() + titles.len().saturating_sub(1);
    let compact = full > area.width as usize;
    let mut x = area.x;
    let mut spans = Vec::new();
    for (i, t) in titles.iter().enumerate() {
        let label = if compact && i != selected { format!(" {} ", i + 1) } else { format!(" {} {} ", i + 1, t) };
        let w = label.width() as u16;
        let style = if i == selected {
            if theme.mono {
                Style::default().add_modifier(Modifier::REVERSED | Modifier::BOLD)
            } else {
                Style::default().fg(theme.accent).add_modifier(Modifier::BOLD | Modifier::UNDERLINED)
            }
        } else {
            theme.dim()
        };
        if x + w <= area.right() {
            mouse.add(Rect::new(x, area.y, w, 1), target(i));
        }
        spans.push(Span::styled(label, style));
        x += w;
        if i + 1 < titles.len() {
            spans.push(Span::styled("│", theme.border(false)));
            x += 1;
        }
    }
    f.render_widget(Line::from(spans), area);
}

/// Footer of key hints: `Enter connect · s scan · ? help`. Each hint is
/// clickable (registers `target`). Truncates cleanly at the right edge.
pub fn hints<T: Clone>(f: &mut Frame, area: Rect, items: &[(String, String, T)], theme: &Theme, mouse: &mut MouseMap<T>) {
    let mut spans = Vec::new();
    let mut x = area.x;
    for (i, (k, d, t)) in items.iter().enumerate() {
        let sep = if i > 0 { 3 } else { 0 };
        let w = (k.width() + 1 + d.width()) as u16;
        if x + sep + w > area.right() {
            break;
        }
        if i > 0 {
            spans.push(Span::styled(" · ", theme.dim()));
        }
        mouse.add(Rect::new(x + sep, area.y, w, 1), t.clone());
        spans.push(Span::styled(k.clone(), theme.key()));
        spans.push(Span::raw(" "));
        spans.push(Span::styled(d.clone(), theme.dim()));
        x += sep + w;
    }
    f.render_widget(Line::from(spans), area);
}

/// `● on` / `○ off` toggle label.
pub fn toggle(on: bool, theme: &Theme) -> Span<'static> {
    if on {
        Span::styled("● on ", theme.ok())
    } else {
        Span::styled("○ off", theme.dim())
    }
}

/// `[x]` / `[ ]` checkbox.
pub fn checkbox(on: bool, theme: &Theme) -> Span<'static> {
    if on {
        Span::styled("[x]", theme.accent())
    } else {
        Span::styled("[ ]", theme.dim())
    }
}

/// Four-step signal bars from a 0–100 strength.
pub fn signal_bars(strength: u8, theme: &Theme) -> Span<'static> {
    let level = match strength {
        0..=20 => 1,
        21..=45 => 2,
        46..=70 => 3,
        _ => 4,
    };
    let bars = ["▂", "▄", "▆", "█"];
    let s: String = bars.iter().enumerate().map(|(i, b)| if i < level { *b } else { " " }).collect();
    let style = match level {
        1 => theme.error(),
        2 => theme.warn(),
        _ => theme.ok(),
    };
    Span::styled(s, style)
}

/// Compact horizontal bar, e.g. battery or level: `▰▰▰▱▱`.
pub fn mini_bar(pct: u8, cells: usize) -> String {
    let filled = ((pct as usize * cells) + 50) / 100;
    (0..cells).map(|i| if i < filled { '▰' } else { '▱' }).collect()
}

// ---------------------------------------------------------------- toasts

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Level {
    Info,
    Ok,
    Warn,
    Error,
}

#[derive(Clone, Debug)]
pub struct Toast {
    pub level: Level,
    pub text: String,
    pub at: Instant,
}

#[derive(Debug, Default)]
pub struct Toasts {
    items: Vec<Toast>,
    /// Errors stay longer than info.
    pub ttl: Option<Duration>,
}

impl Toasts {
    pub fn push(&mut self, level: Level, text: impl Into<String>) {
        let text = text.into();
        // Collapse exact repeats so a flapping device doesn't flood the screen.
        self.items.retain(|t| t.text != text);
        self.items.push(Toast { level, text, at: Instant::now() });
        if self.items.len() > 4 {
            self.items.remove(0);
        }
    }

    pub fn prune(&mut self) -> bool {
        let base = self.ttl.unwrap_or(Duration::from_secs(4));
        let before = self.items.len();
        self.items.retain(|t| {
            let ttl = if t.level == Level::Error { base * 2 } else { base };
            t.at.elapsed() < ttl
        });
        before != self.items.len()
    }

    pub fn dismiss_all(&mut self) {
        self.items.clear();
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Draw stacked in the bottom-right corner of `area`.
    pub fn render(&self, f: &mut Frame, area: Rect, theme: &Theme) {
        let mut y = area.bottom();
        for t in self.items.iter().rev() {
            let (icon, style) = match t.level {
                Level::Info => ("ℹ", theme.info()),
                Level::Ok => ("✓", theme.ok()),
                Level::Warn => ("!", theme.warn()),
                Level::Error => ("✗", theme.error()),
            };
            let max_w = (area.width as usize).saturating_sub(4).min(70);
            let text: String = truncate(&t.text, max_w.saturating_sub(4));
            let w = (text.width() + 6) as u16;
            if y < area.y + 3 {
                break;
            }
            y -= 3;
            let r = Rect::new(area.right().saturating_sub(w + 1), y, w.min(area.width), 3);
            f.render_widget(Clear, r);
            let block = Block::default().borders(Borders::ALL).border_type(BorderType::Rounded).border_style(style);
            let p = Paragraph::new(Line::from(vec![Span::styled(format!("{icon} "), style), Span::raw(text)])).block(block);
            f.render_widget(p, r);
        }
    }
}

pub fn truncate(s: &str, max: usize) -> String {
    if s.width() <= max {
        return s.to_string();
    }
    let mut out = String::new();
    let mut w = 0;
    for c in s.chars() {
        let cw = c.to_string().width();
        if w + cw + 1 > max {
            break;
        }
        out.push(c);
        w += cw;
    }
    out.push('…');
    out
}

// ---------------------------------------------------------------- confirm

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfirmHit {
    Yes,
    No,
}

/// Yes/No dialog. Returns nothing; clicks are reported through `mouse`.
#[allow(clippy::too_many_arguments)]
pub fn confirm<T: Clone>(
    f: &mut Frame,
    area: Rect,
    theme: &Theme,
    title: &str,
    message: &str,
    yes_label: &str,
    yes_selected: bool,
    mouse: &mut MouseMap<T>,
    target: impl Fn(ConfirmHit) -> T,
) {
    let w = (message.width() as u16 + 6).clamp(36, 70);
    let lines = (message.width() as u16 / (w - 4)) + 1;
    let r = centered(area, w, lines + 5);
    mouse.modal_barrier();
    let inner = popup(f, r, theme, title);
    let [msg, _, buttons] =
        Layout::vertical([Constraint::Min(1), Constraint::Length(1), Constraint::Length(1)]).areas(inner.inner(ratatui::layout::Margin::new(1, 0)));
    f.render_widget(Paragraph::new(message.to_string()).wrap(Wrap { trim: true }).style(theme.text()), msg);
    let yes = format!("  {yes_label}  ");
    let no = "  Cancel  ".to_string();
    let total = yes.width() + no.width() + 2;
    let start = buttons.x + (buttons.width.saturating_sub(total as u16)) / 2;
    let ys = Rect::new(start, buttons.y, yes.width() as u16, 1);
    let ns = Rect::new(start + yes.width() as u16 + 2, buttons.y, no.width() as u16, 1);
    let btn = |sel: bool| {
        if sel {
            if theme.mono {
                Style::default().add_modifier(Modifier::REVERSED)
            } else {
                Style::default().bg(theme.accent).fg(ratatui::style::Color::Black).add_modifier(Modifier::BOLD)
            }
        } else {
            theme.dim().add_modifier(Modifier::REVERSED)
        }
    };
    f.render_widget(Span::styled(yes, btn(yes_selected)), ys);
    f.render_widget(Span::styled(no, btn(!yes_selected)), ns);
    mouse.add(ys, target(ConfirmHit::Yes));
    mouse.add(ns, target(ConfirmHit::No));
}

// ---------------------------------------------------------------- help

/// One row of the help popup.
pub enum HelpRow {
    Section(String),
    /// keys, description, config name (may be empty)
    Key(String, String, String),
    Text(String),
}

/// Scrollable help popup. Returns the max scroll so the caller can clamp.
pub fn help(f: &mut Frame, area: Rect, theme: &Theme, title: &str, rows: &[HelpRow], scroll: u16) -> u16 {
    let r = centered(area, 72, area.height.saturating_sub(4).max(10));
    let inner = popup(f, r, theme, title);
    let key_w = rows
        .iter()
        .filter_map(|r| if let HelpRow::Key(k, _, _) = r { Some(k.width()) } else { None })
        .max()
        .unwrap_or(8)
        .min(28);
    let mut lines: Vec<Line> = Vec::new();
    for r in rows {
        match r {
            HelpRow::Section(s) => {
                if !lines.is_empty() {
                    lines.push(Line::raw(""));
                }
                lines.push(Line::from(Span::styled(s.clone(), theme.accent().add_modifier(Modifier::BOLD))));
            }
            HelpRow::Key(k, d, n) => lines.push(Line::from(vec![
                Span::styled(format!("  {:<key_w$}  ", k), theme.key()),
                Span::styled(d.clone(), theme.text()),
                Span::styled(if n.is_empty() { String::new() } else { format!("  {n}") }, theme.dim()),
            ])),
            HelpRow::Text(t) => lines.push(Line::from(Span::styled(format!("  {t}"), theme.dim()))),
        }
    }
    let max_scroll = (lines.len() as u16).saturating_sub(inner.height);
    let scroll = scroll.min(max_scroll);
    f.render_widget(Paragraph::new(lines).scroll((scroll, 0)), inner);
    let foot = " j/k scroll · Esc close ";
    let fr = Rect::new(r.right().saturating_sub(foot.width() as u16 + 2), r.bottom() - 1, foot.width() as u16, 1);
    f.render_widget(Span::styled(foot, theme.dim()), fr);
    max_scroll
}

/// Full-area placeholder for "nothing to show" states (no adapter, daemon down...).
pub fn empty_state(f: &mut Frame, area: Rect, theme: &Theme, title: &str, body: &[&str]) {
    let mut lines = vec![Line::from(Span::styled(title.to_string(), theme.warn().add_modifier(Modifier::BOLD))), Line::raw("")];
    lines.extend(body.iter().map(|b| Line::from(Span::styled(b.to_string(), theme.dim()))));
    let h = lines.len() as u16;
    let r = centered(area, area.width.saturating_sub(4), h);
    f.render_widget(Paragraph::new(lines).alignment(Alignment::Center).wrap(Wrap { trim: true }), r);
}
