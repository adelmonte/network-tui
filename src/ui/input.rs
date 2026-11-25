//! Minimal single-line text input with readline-ish editing:
//! ←/→, Home/End (C-a/C-e), Backspace/Del, C-w (delete word), C-u (clear to start).

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::{
    layout::{Position, Rect},
    text::{Line, Span},
    Frame,
};
use unicode_width::UnicodeWidthStr;

use super::theme::Theme;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InputOutcome {
    Changed,
    Moved,
    Submit,
    Cancel,
    Ignored,
}

#[derive(Clone, Debug, Default)]
pub struct TextInput {
    chars: Vec<char>,
    cursor: usize,
    pub masked: bool,
    pub placeholder: String,
}

impl TextInput {
    pub fn new(initial: &str) -> Self {
        let chars: Vec<char> = initial.chars().collect();
        let cursor = chars.len();
        Self { chars, cursor, ..Default::default() }
    }

    pub fn masked(mut self) -> Self {
        self.masked = true;
        self
    }

    pub fn with_placeholder(mut self, p: &str) -> Self {
        self.placeholder = p.to_string();
        self
    }

    pub fn value(&self) -> String {
        self.chars.iter().collect()
    }

    pub fn is_empty(&self) -> bool {
        self.chars.is_empty()
    }

    pub fn set(&mut self, v: &str) {
        self.chars = v.chars().collect();
        self.cursor = self.chars.len();
    }

    pub fn insert_str(&mut self, s: &str) {
        for c in s.chars().filter(|c| !c.is_control()) {
            self.chars.insert(self.cursor, c);
            self.cursor += 1;
        }
    }

    pub fn handle_key(&mut self, key: &KeyEvent) -> InputOutcome {
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        match key.code {
            KeyCode::Enter => InputOutcome::Submit,
            KeyCode::Esc => InputOutcome::Cancel,
            KeyCode::Char('c') if ctrl => InputOutcome::Cancel,
            KeyCode::Char('a') if ctrl => self.move_to(0),
            KeyCode::Char('e') if ctrl => self.move_to(self.chars.len()),
            KeyCode::Char('u') if ctrl => {
                self.chars.drain(..self.cursor);
                self.cursor = 0;
                InputOutcome::Changed
            }
            KeyCode::Char('w') if ctrl => {
                let mut start = self.cursor;
                while start > 0 && self.chars[start - 1] == ' ' {
                    start -= 1;
                }
                while start > 0 && self.chars[start - 1] != ' ' {
                    start -= 1;
                }
                self.chars.drain(start..self.cursor);
                self.cursor = start;
                InputOutcome::Changed
            }
            KeyCode::Char(c) if !ctrl => {
                self.chars.insert(self.cursor, c);
                self.cursor += 1;
                InputOutcome::Changed
            }
            KeyCode::Backspace if self.cursor > 0 => {
                self.cursor -= 1;
                self.chars.remove(self.cursor);
                InputOutcome::Changed
            }
            KeyCode::Delete if self.cursor < self.chars.len() => {
                self.chars.remove(self.cursor);
                InputOutcome::Changed
            }
            KeyCode::Left if self.cursor > 0 => self.move_to(self.cursor - 1),
            KeyCode::Right if self.cursor < self.chars.len() => self.move_to(self.cursor + 1),
            KeyCode::Home => self.move_to(0),
            KeyCode::End => self.move_to(self.chars.len()),
            _ => InputOutcome::Ignored,
        }
    }

    fn move_to(&mut self, pos: usize) -> InputOutcome {
        self.cursor = pos.min(self.chars.len());
        InputOutcome::Moved
    }

    /// Move the cursor to a clicked column (relative to the field's left edge).
    pub fn click(&mut self, rel_col: u16) {
        let mut w = 0u16;
        for (i, c) in self.chars.iter().enumerate() {
            let cw = if self.masked { 1 } else { UnicodeWidthStr::width(c.to_string().as_str()) as u16 };
            if w + cw / 2 >= rel_col {
                self.cursor = i;
                return;
            }
            w += cw;
        }
        self.cursor = self.chars.len();
    }

    /// Render into a one-line area and, when focused, place the terminal cursor.
    pub fn render(&self, f: &mut Frame, area: Rect, theme: &Theme, focused: bool) {
        let shown: String = if self.masked { "•".repeat(self.chars.len()) } else { self.value() };
        let before: String = if self.masked {
            "•".repeat(self.cursor)
        } else {
            self.chars[..self.cursor].iter().collect()
        };
        let cursor_x = UnicodeWidthStr::width(before.as_str()) as u16;
        // Horizontal scroll so the cursor stays visible.
        let width = area.width.max(1);
        let offset = cursor_x.saturating_sub(width - 1);
        let line = if shown.is_empty() && !self.placeholder.is_empty() {
            Line::from(Span::styled(self.placeholder.clone(), theme.dim()))
        } else {
            let skip: String = skip_width(&shown, offset);
            Line::from(Span::styled(skip, theme.text()))
        };
        f.render_widget(line, area);
        if focused {
            f.set_cursor_position(Position::new(area.x + cursor_x - offset, area.y));
        }
    }
}

fn skip_width(s: &str, cols: u16) -> String {
    let mut w = 0u16;
    let mut out = String::new();
    for c in s.chars() {
        if w >= cols {
            out.push(c);
        } else {
            w += UnicodeWidthStr::width(c.to_string().as_str()) as u16;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn k(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }
    fn ctrl(c: char) -> KeyEvent {
        KeyEvent::new(KeyCode::Char(c), KeyModifiers::CONTROL)
    }

    #[test]
    fn editing() {
        let mut i = TextInput::new("hello world");
        i.handle_key(&ctrl('w'));
        assert_eq!(i.value(), "hello ");
        i.handle_key(&k(KeyCode::Home));
        i.handle_key(&k(KeyCode::Char('>')));
        assert_eq!(i.value(), ">hello ");
        i.handle_key(&k(KeyCode::End));
        i.handle_key(&k(KeyCode::Backspace));
        assert_eq!(i.value(), ">hello");
        i.handle_key(&k(KeyCode::Left));
        i.handle_key(&ctrl('u'));
        assert_eq!(i.value(), "o");
        assert_eq!(i.handle_key(&k(KeyCode::Enter)), InputOutcome::Submit);
    }
}
