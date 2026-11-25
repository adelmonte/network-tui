//! Command palette (`:` / C-p): fuzzy-filter every action available in the
//! current context and run it with Enter or a click.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::{
    layout::{Constraint, Layout, Rect},
    text::{Line, Span},
    Frame,
};
use unicode_width::UnicodeWidthStr;

use super::input::{InputOutcome, TextInput};
use super::mouse::MouseMap;
use super::theme::Theme;
use super::widgets::{centered, popup, truncate};

#[derive(Clone, Debug)]
pub struct Entry<T> {
    pub label: String,
    pub keys: String,
    pub value: T,
}

#[derive(Debug)]
pub struct Palette<T> {
    entries: Vec<Entry<T>>,
    filtered: Vec<usize>,
    pub input: TextInput,
    selected: usize,
}

pub enum PaletteOutcome<T> {
    Run(T),
    Close,
    None,
}

/// Subsequence match score: lower is better; None if no match.
pub fn fuzzy_score(needle: &str, hay: &str) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    let hay_l = hay.to_lowercase();
    if let Some(pos) = hay_l.find(&needle.to_lowercase()) {
        return Some(pos); // contiguous matches rank first
    }
    let mut score = 1000;
    let mut last = 0usize;
    let mut hs = hay_l.char_indices();
    for n in needle.to_lowercase().chars() {
        loop {
            let (i, h) = hs.next()?;
            if h == n {
                score += i.saturating_sub(last);
                last = i;
                break;
            }
        }
    }
    Some(score)
}

impl<T: Clone> Palette<T> {
    pub fn new(entries: Vec<Entry<T>>) -> Self {
        let mut p = Self { filtered: Vec::new(), entries, input: TextInput::default().with_placeholder("type to filter…"), selected: 0 };
        p.refilter();
        p
    }

    fn refilter(&mut self) {
        let q = self.input.value();
        let mut scored: Vec<(usize, usize)> =
            self.entries.iter().enumerate().filter_map(|(i, e)| fuzzy_score(&q, &e.label).map(|s| (s, i))).collect();
        scored.sort();
        self.filtered = scored.into_iter().map(|(_, i)| i).collect();
        self.selected = 0;
    }

    pub fn handle_key(&mut self, key: &KeyEvent) -> PaletteOutcome<T> {
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        match key.code {
            KeyCode::Down | KeyCode::Tab => self.step(1),
            KeyCode::Char('n') if ctrl => self.step(1),
            KeyCode::Up | KeyCode::BackTab => self.step(-1),
            KeyCode::Char('p') if ctrl => self.step(-1),
            _ => match self.input.handle_key(key) {
                InputOutcome::Submit => {
                    return match self.filtered.get(self.selected) {
                        Some(&i) => PaletteOutcome::Run(self.entries[i].value.clone()),
                        None => PaletteOutcome::Close,
                    }
                }
                InputOutcome::Cancel => return PaletteOutcome::Close,
                InputOutcome::Changed => self.refilter(),
                _ => {}
            },
        }
        PaletteOutcome::None
    }

    fn step(&mut self, d: isize) {
        let n = self.filtered.len();
        if n > 0 {
            self.selected = (self.selected as isize + d).rem_euclid(n as isize) as usize;
        }
    }

    pub fn value_at(&self, row: usize) -> Option<T> {
        self.filtered.get(row).map(|&i| self.entries[i].value.clone())
    }

    /// `target(row)` builds the mouse target for a visible row index.
    pub fn render<M: Clone>(
        &self,
        f: &mut Frame,
        area: Rect,
        theme: &Theme,
        mouse: &mut MouseMap<M>,
        target: impl Fn(usize) -> M,
    ) {
        let h = (self.filtered.len() as u16 + 4).clamp(6, 18);
        let mut r = centered(area, 64, h);
        r.y = area.y + area.height / 6;
        mouse.modal_barrier();
        let inner = popup(f, r, theme, "Command palette");
        let [inp, sep, list] = Layout::vertical([Constraint::Length(1), Constraint::Length(1), Constraint::Min(1)]).areas(inner);
        f.render_widget(Span::styled("❯ ", theme.accent()), Rect { width: 2, ..inp });
        self.input.render(f, Rect { x: inp.x + 2, width: inp.width.saturating_sub(2), ..inp }, theme, true);
        f.render_widget(Span::styled("─".repeat(sep.width as usize), theme.border(false)), sep);
        let visible = list.height as usize;
        let start = self.selected.saturating_sub(visible.saturating_sub(1));
        for (row, &i) in self.filtered.iter().enumerate().skip(start).take(visible) {
            let e = &self.entries[i];
            let y = list.y + (row - start) as u16;
            let line_r = Rect::new(list.x, y, list.width, 1);
            let kw = e.keys.width();
            let label = truncate(&e.label, (list.width as usize).saturating_sub(kw + 3));
            let pad = (list.width as usize).saturating_sub(label.width() + kw + 2);
            let style = if row == self.selected { theme.selected(true) } else { theme.text() };
            let line = Line::from(vec![
                Span::styled(format!(" {label}"), style),
                Span::styled(" ".repeat(pad), style),
                Span::styled(format!("{} ", e.keys), style.patch(theme.dim())),
            ]);
            f.render_widget(line, line_r);
            mouse.add(line_r, target(row));
        }
        if self.filtered.is_empty() {
            f.render_widget(Span::styled(" no matching commands", theme.dim()), list);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fuzzy_ranks_contiguous_first() {
        assert!(fuzzy_score("scan", "Start scan").unwrap() < fuzzy_score("scan", "Set config alias name").unwrap());
        assert!(fuzzy_score("xyz", "Start scan").is_none());
        assert_eq!(fuzzy_score("", "anything"), Some(0));
    }
}
