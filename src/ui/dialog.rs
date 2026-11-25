//! Small form dialog shared by the apps: a few labelled text/secret/choice
//! fields, an error line, OK/Cancel buttons. Keyboard: Tab/↑↓ move, ←/→ or
//! Space change a choice, Enter submits (or moves to the next empty field),
//! Esc cancels, Ctrl-R shows/hides secrets. Mouse: click fields and buttons.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::{
    layout::{Margin, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Paragraph, Wrap},
    Frame,
};
use unicode_width::UnicodeWidthStr;

use super::input::TextInput;
use super::mouse::MouseMap;
use super::theme::Theme;
use super::widgets::{centered, popup};

pub const LABEL_W: u16 = 16;

#[derive(Clone, Debug)]
pub struct Field {
    pub label: String,
    pub input: TextInput,
    /// (value, label) choices; when set, the field is a selector.
    pub choices: Option<(Vec<(String, String)>, usize)>,
    pub secret: bool,
}

impl Field {
    pub fn text(label: &str, v: &str) -> Self {
        Self { label: label.into(), input: TextInput::new(v), choices: None, secret: false }
    }
    pub fn placeholder(mut self, p: &str) -> Self {
        self.input.placeholder = p.into();
        self
    }
    pub fn secret(label: &str, v: &str) -> Self {
        Self { label: label.into(), input: TextInput::new(v).masked(), choices: None, secret: true }
    }
    pub fn choice(label: &str, opts: Vec<(String, String)>, selected_value: &str) -> Self {
        let sel = opts.iter().position(|o| o.0 == selected_value).unwrap_or(0);
        Self { label: label.into(), input: TextInput::default(), choices: Some((opts, sel)), secret: false }
    }
    pub fn value(&self) -> String {
        match &self.choices {
            Some((o, i)) => o.get(*i).map(|x| x.0.clone()).unwrap_or_default(),
            None => self.input.value(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Dialog<P> {
    pub title: String,
    pub intro: String,
    pub fields: Vec<Field>,
    pub focus: usize,
    pub ok_label: String,
    pub purpose: P,
    pub error: Option<String>,
}

pub enum DialogKey {
    Submit,
    Cancel,
    None,
}

impl<P> Dialog<P> {
    pub fn new(title: &str, intro: &str, fields: Vec<Field>, ok_label: &str, purpose: P) -> Self {
        Self { title: title.into(), intro: intro.into(), fields, focus: 0, ok_label: ok_label.into(), purpose, error: None }
    }

    pub fn value(&self, i: usize) -> String {
        self.fields.get(i).map(Field::value).unwrap_or_default()
    }

    pub fn fail(&mut self, field: usize, msg: impl Into<String>) {
        self.error = Some(msg.into());
        self.focus = field.min(self.fields.len().saturating_sub(1));
    }

    pub fn handle_key(&mut self, k: &KeyEvent) -> DialogKey {
        let n = self.fields.len().max(1);
        let ctrl = k.modifiers.contains(KeyModifiers::CONTROL);
        match k.code {
            KeyCode::Esc => return DialogKey::Cancel,
            KeyCode::Tab | KeyCode::Down => self.focus = (self.focus + 1) % n,
            KeyCode::BackTab | KeyCode::Up => self.focus = (self.focus + n - 1) % n,
            KeyCode::Char('r') if ctrl => {
                for f in self.fields.iter_mut().filter(|f| f.secret) {
                    f.input.masked = !f.input.masked;
                }
            }
            KeyCode::Enter => {
                let next_empty = self.fields.iter().enumerate().skip(self.focus + 1).find(|(_, f)| f.choices.is_none() && f.input.is_empty() && f.input.placeholder.is_empty());
                match next_empty {
                    Some((i, _)) if self.fields[self.focus].choices.is_none() => self.focus = i,
                    _ => return DialogKey::Submit,
                }
            }
            _ => {
                let Some(f) = self.fields.get_mut(self.focus) else { return DialogKey::None };
                if let Some((o, sel)) = &mut f.choices {
                    let len = o.len().max(1);
                    match k.code {
                        KeyCode::Left | KeyCode::Char('h') => *sel = (*sel + len - 1) % len,
                        KeyCode::Right | KeyCode::Char('l') | KeyCode::Char(' ') => *sel = (*sel + 1) % len,
                        _ => {}
                    }
                } else {
                    f.input.handle_key(k);
                    self.error = None;
                }
            }
        }
        DialogKey::None
    }

    /// Mouse click on field `i` (rel_x relative to the field row).
    pub fn click_field(&mut self, i: usize, rel_x: u16) {
        if i >= self.fields.len() {
            return;
        }
        if self.focus == i {
            let f = &mut self.fields[i];
            if let Some((o, sel)) = &mut f.choices {
                *sel = (*sel + 1) % o.len().max(1);
            } else {
                f.input.click(rel_x.saturating_sub(LABEL_W));
            }
        }
        self.focus = i;
    }

    pub fn paste(&mut self, s: &str) {
        if let Some(f) = self.fields.get_mut(self.focus)
            && f.choices.is_none() {
                f.input.insert_str(s);
            }
    }

    pub fn render<T: Clone>(&self, f: &mut Frame, area: Rect, theme: &Theme, mouse: &mut MouseMap<T>, field_t: impl Fn(usize) -> T, button_t: impl Fn(bool) -> T) {
        mouse.modal_barrier();
        let w = 70u16.min(area.width);
        let intro_lines = if self.intro.is_empty() { 0 } else { (self.intro.width() as u16 / (w.saturating_sub(4)).max(1)) + 1 };
        let h = intro_lines + u16::from(intro_lines > 0) + self.fields.len() as u16 + 4 + 2;
        let r = centered(area, w, h);
        let inner = popup(f, r, theme, &self.title).inner(Margin::new(1, 0));
        let mut y = inner.y;
        if intro_lines > 0 {
            f.render_widget(Paragraph::new(self.intro.clone()).wrap(Wrap { trim: true }).style(theme.dim()), Rect { y, height: intro_lines, ..inner });
            y += intro_lines + 1;
        }
        for (i, fl) in self.fields.iter().enumerate() {
            let rr = Rect { y, height: 1, ..inner };
            let focused = i == self.focus;
            f.render_widget(Span::styled(format!("{:<w$}", fl.label, w = LABEL_W as usize), if focused { theme.accent() } else { theme.text() }), rr);
            let vr = Rect { x: rr.x + LABEL_W, width: rr.width.saturating_sub(LABEL_W), ..rr };
            f.render_widget(Span::styled(" ".repeat(vr.width as usize), if focused { theme.selected(false) } else { Style::default() }), vr);
            match &fl.choices {
                Some((o, sel)) => {
                    let label = o.get(*sel).map(|x| x.1.as_str()).unwrap_or("");
                    f.render_widget(Line::from(vec![Span::styled("‹ ", theme.dim()), Span::styled(label.to_string(), theme.bold()), Span::styled(" ›", theme.dim())]), vr);
                }
                None => fl.input.render(f, vr, theme, focused),
            }
            mouse.add(rr, field_t(i));
            y += 1;
        }
        y += 1;
        let hint = if self.fields.iter().any(|f| f.secret) { "Ctrl-R show/hide · Tab next field" } else { "Tab next field · ←/→ change choice" };
        match &self.error {
            Some(e) => f.render_widget(Span::styled(format!("✗ {e}"), theme.error()), Rect { y, height: 1, ..inner }),
            None => f.render_widget(Span::styled(hint, theme.dim()), Rect { y, height: 1, ..inner }),
        }
        y += 2;
        let ok = format!(" {} ", self.ok_label);
        let cancel = " Cancel ";
        let okr = Rect::new(inner.x, y.min(inner.bottom().saturating_sub(1)), ok.width() as u16, 1);
        let cr = Rect::new(okr.right() + 1, okr.y, cancel.width() as u16, 1);
        f.render_widget(Span::styled(ok, theme.accent().add_modifier(Modifier::REVERSED | Modifier::BOLD)), okr);
        f.render_widget(Span::styled(cancel, theme.dim().add_modifier(Modifier::REVERSED)), cr);
        mouse.add(okr, button_t(true));
        mouse.add(cr, button_t(false));
    }
}
