//! Full connection editor (nmtui-style, but mouse-friendly): a scrollable
//! form whose fields appear/disappear with the choices made (e.g. addresses
//! only for "manual"). Validation errors are shown next to the field.

use std::collections::HashMap;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::{
    layout::{Constraint, Layout, Margin, Rect},
    style::Modifier,
    text::{Line, Span},
    Frame,
};
use unicode_width::UnicodeWidthStr;

use crate::app::Target;
use crate::backend::form::{Form, Key, Value};
use crate::backend::val::Settings;
use crate::ui::input::{InputOutcome, TextInput};
use crate::ui::mouse::MouseMap;
use crate::ui::theme::Theme;
use crate::ui::widgets::{centered, popup, truncate};

const LABEL_W: usize = 28;

pub enum EditorOutcome {
    None,
    Cancel,
    Save(Settings),
}

pub struct Editor {
    pub form: Form,
    /// Existing profile path; None = new profile.
    pub path: Option<String>,
    pub title: String,
    /// For new profiles: activate on this device right after saving.
    pub activate_on: Option<String>,
    sel: Key,
    editing: Option<TextInput>,
    pub errors: HashMap<Key, String>,
    scroll: usize,
    view_height: usize,
    dirty: bool,
    confirm_discard: bool,
    reveal: bool,
}

impl Editor {
    pub fn new(form: Form, path: Option<String>, title: String, activate_on: Option<String>) -> Self {
        let sel = form.fields.first().map(|f| f.key).unwrap_or(Key::Id);
        // A brand-new profile counts as unsaved from the start.
        let dirty = form.is_new;
        Self { form, path, title, activate_on, sel, editing: None, errors: HashMap::new(), scroll: 0, view_height: 10, dirty, confirm_discard: false, reveal: false }
    }

    fn visible(&self) -> Vec<usize> {
        self.form.visible_fields()
    }

    fn sel_pos(&self) -> usize {
        let v = self.visible();
        v.iter().position(|&i| self.form.fields[i].key == self.sel).unwrap_or(0)
    }

    fn field_mut(&mut self, k: Key) -> Option<&mut Value> {
        self.form.fields.iter_mut().find(|f| f.key == k).map(|f| &mut f.value)
    }

    fn move_sel(&mut self, d: isize) {
        let v = self.visible();
        if v.is_empty() {
            return;
        }
        let p = (self.sel_pos() as isize + d).clamp(0, v.len() as isize - 1) as usize;
        self.sel = self.form.fields[v[p]].key;
    }

    pub fn scroll_by(&mut self, d: isize) {
        self.move_sel(d);
    }

    fn activate(&mut self, forward: bool) {
        let k = self.sel;
        let reveal = self.reveal;
        let Some(v) = self.field_mut(k) else { return };
        let masked = matches!(v, Value::Secret(_)) && !reveal;
        match v {
            Value::Bool(b) => *b = !*b,
            Value::Choice(o, i) => *i = if forward { (*i + 1) % o.len() } else { (*i + o.len() - 1) % o.len() },
            Value::Text(t) | Value::Secret(t) => {
                let mut input = TextInput::new(t);
                input.masked = masked;
                self.editing = Some(input);
                return;
            }
        }
        self.touched(k);
    }

    fn touched(&mut self, k: Key) {
        self.dirty = true;
        self.confirm_discard = false;
        self.errors.remove(&k);
    }

    fn commit_edit(&mut self) {
        if let Some(input) = self.editing.take() {
            let k = self.sel;
            if let Some(Value::Text(t) | Value::Secret(t)) = self.field_mut(k)
                && *t != input.value() {
                    *t = input.value();
                    self.touched(k);
                }
        }
    }

    pub fn paste(&mut self, s: &str) {
        if let Some(i) = &mut self.editing {
            i.insert_str(s);
        }
    }

    /// Validate; on success return settings, else record errors and jump to the first.
    pub fn try_save(&mut self) -> Option<Settings> {
        self.commit_edit();
        match self.form.to_settings() {
            Ok(s) => Some(s),
            Err(errs) => {
                self.errors = errs.iter().cloned().collect();
                let vis: Vec<Key> = self.visible().iter().map(|&i| self.form.fields[i].key).collect();
                if let Some(first) = vis.iter().find(|k| self.errors.contains_key(k)) {
                    self.sel = *first;
                }
                None
            }
        }
    }

    pub fn handle_key(&mut self, k: &KeyEvent) -> EditorOutcome {
        let ctrl = k.modifiers.contains(KeyModifiers::CONTROL);
        if ctrl && k.code == KeyCode::Char('s') {
            return match self.try_save() {
                Some(s) => EditorOutcome::Save(s),
                None => EditorOutcome::None,
            };
        }
        if ctrl && k.code == KeyCode::Char('r') {
            self.reveal = !self.reveal;
            if let Some(i) = &mut self.editing
                && matches!(self.form.get(self.sel), Some(Value::Secret(_))) {
                    i.masked = !self.reveal;
                }
            return EditorOutcome::None;
        }
        if let Some(input) = &mut self.editing {
            match k.code {
                KeyCode::Tab | KeyCode::Down => {
                    self.commit_edit();
                    self.move_sel(1);
                }
                KeyCode::BackTab | KeyCode::Up => {
                    self.commit_edit();
                    self.move_sel(-1);
                }
                _ => match input.handle_key(k) {
                    InputOutcome::Submit => {
                        self.commit_edit();
                        self.move_sel(1);
                    }
                    InputOutcome::Cancel => self.editing = None,
                    _ => {}
                },
            }
            return EditorOutcome::None;
        }
        match k.code {
            KeyCode::Esc | KeyCode::Char('q') => {
                if self.dirty && !self.confirm_discard {
                    self.confirm_discard = true;
                } else {
                    return EditorOutcome::Cancel;
                }
            }
            KeyCode::Down | KeyCode::Char('j') | KeyCode::Tab => self.move_sel(1),
            KeyCode::Up | KeyCode::Char('k') | KeyCode::BackTab => self.move_sel(-1),
            KeyCode::PageDown => self.move_sel(self.view_height as isize - 1),
            KeyCode::PageUp => self.move_sel(-(self.view_height as isize - 1)),
            KeyCode::Home | KeyCode::Char('g') => self.move_sel(-10_000),
            KeyCode::End | KeyCode::Char('G') => self.move_sel(10_000),
            KeyCode::Enter | KeyCode::Char(' ') | KeyCode::Char('e') => self.activate(true),
            KeyCode::Right | KeyCode::Char('l') => {
                if matches!(self.form.get(self.sel), Some(Value::Choice(..))) {
                    self.activate(true);
                }
            }
            KeyCode::Left | KeyCode::Char('h') => {
                if matches!(self.form.get(self.sel), Some(Value::Choice(..))) {
                    self.activate(false);
                }
            }
            _ => {}
        }
        EditorOutcome::None
    }

    /// `i` is a visible-field index.
    pub fn click_row(&mut self, i: usize, double: bool, rel_x: u16) {
        let v = self.visible();
        let Some(&fi) = v.get(i) else { return };
        let k = self.form.fields[fi].key;
        let on_value = rel_x as usize >= LABEL_W + 2;
        if self.sel == k || double || on_value {
            if self.editing.is_some() && self.sel == k {
                if let Some(inp) = &mut self.editing {
                    inp.click(rel_x.saturating_sub(LABEL_W as u16 + 2));
                }
                return;
            }
            self.commit_edit();
            self.sel = k;
            self.activate(true);
        } else {
            self.commit_edit();
            self.sel = k;
        }
    }

    pub fn render(&mut self, f: &mut Frame, area: Rect, theme: &Theme, mouse: &mut MouseMap<Target>) {
        let w = area.width.saturating_sub(6).clamp(40, 100);
        let h = area.height.saturating_sub(2).max(12);
        let r = centered(area, w, h);
        mouse.modal_barrier();
        let inner = popup(f, r, theme, &self.title).inner(Margin::new(1, 0));
        let [body, _, help, foot] = Layout::vertical([Constraint::Min(3), Constraint::Length(1), Constraint::Length(1), Constraint::Length(1)]).areas(inner);

        // Build display rows: (section header) or (visible index, field index).
        enum Row {
            Header(&'static str),
            Field(usize, usize),
        }
        let vis = self.visible();
        let mut rows = Vec::new();
        let mut last = "";
        for (vi, &fi) in vis.iter().enumerate() {
            let sec = self.form.fields[fi].section;
            if sec != last {
                if !rows.is_empty() {
                    rows.push(Row::Header(""));
                }
                rows.push(Row::Header(sec));
                last = sec;
            }
            rows.push(Row::Field(vi, fi));
        }
        let sel_row = rows.iter().position(|r| matches!(r, Row::Field(_, fi) if self.form.fields[*fi].key == self.sel)).unwrap_or(0);
        let height = body.height as usize;
        self.view_height = height.max(1);
        if sel_row < self.scroll {
            self.scroll = sel_row.saturating_sub(1);
        } else if sel_row >= self.scroll + height {
            self.scroll = sel_row + 1 - height;
        }
        self.scroll = self.scroll.min(rows.len().saturating_sub(height));

        for (n, row) in rows.iter().enumerate().skip(self.scroll).take(height) {
            let rr = Rect { y: body.y + (n - self.scroll) as u16, height: 1, ..body };
            match row {
                Row::Header(s) => {
                    if !s.is_empty() {
                        f.render_widget(Span::styled(s.to_string(), theme.accent().add_modifier(Modifier::BOLD)), rr);
                    }
                }
                Row::Field(vi, fi) => {
                    let field = &self.form.fields[*fi];
                    let selected = field.key == self.sel;
                    let base = if selected { theme.selected(true) } else { theme.text() };
                    f.render_widget(Span::styled(" ".repeat(rr.width as usize), base), rr);
                    let label = format!(" {:<w$} ", truncate(field.label, LABEL_W - 1), w = LABEL_W - 1);
                    f.render_widget(Span::styled(label, if selected { base } else { theme.dim() }), Rect { width: LABEL_W as u16 + 1, ..rr });
                    let vr = Rect { x: rr.x + LABEL_W as u16 + 2, width: rr.width.saturating_sub(LABEL_W as u16 + 2), ..rr };
                    if let (true, Some(input)) = (selected, self.editing.as_ref()) {
                        f.render_widget(Span::styled(" ".repeat(vr.width as usize), theme.selected(false)), vr);
                        input.render(f, vr, theme, true);
                    } else {
                        let err = self.errors.get(&field.key);
                        let mut spans = match &field.value {
                            Value::Text(t) if t.is_empty() => vec![Span::styled("—", theme.dim())],
                            Value::Text(t) => vec![Span::styled(truncate(t, vr.width as usize), base)],
                            Value::Secret(t) if t.is_empty() => vec![Span::styled("(not set)", theme.dim())],
                            Value::Secret(t) => {
                                let shown = if self.reveal { t.clone() } else { "•".repeat(t.chars().count().min(16)) };
                                vec![Span::styled(shown, base)]
                            }
                            Value::Bool(b) => vec![
                                Span::styled(if *b { "[x] " } else { "[ ] " }, if *b { theme.accent() } else { theme.dim() }),
                                Span::styled(if *b { "yes" } else { "no" }, base),
                            ],
                            Value::Choice(o, i) => vec![
                                Span::styled("‹ ", theme.dim()),
                                Span::styled(o.get(*i).map(|x| x.1).unwrap_or(""), base.add_modifier(Modifier::BOLD)),
                                Span::styled(" ›", theme.dim()),
                            ],
                        };
                        if let Some(e) = err {
                            spans.push(Span::styled(format!("  ✗ {e}"), theme.error()));
                        }
                        f.render_widget(Line::from(spans), vr);
                    }
                    mouse.add(rr, Target::EditorRow(*vi));
                }
            }
        }
        if rows.len() > height {
            let more = format!(" {}/{} ", sel_row + 1, rows.len());
            let x = r.right().saturating_sub(more.width() as u16 + 2);
            f.render_widget(Span::styled(more, theme.dim()), Rect::new(x, r.y, 12, 1));
        }

        // Help / error line for the selected field.
        let help_line = if self.confirm_discard {
            Line::from(Span::styled("Unsaved changes — press Esc again to discard, or Ctrl-S to save", theme.warn()))
        } else if let Some(e) = self.errors.get(&self.sel) {
            Line::from(Span::styled(format!("✗ {e}"), theme.error()))
        } else {
            let h = self.form.fields.iter().find(|x| x.key == self.sel).map(|x| x.help).unwrap_or("");
            Line::from(Span::styled(h, theme.info()))
        };
        f.render_widget(help_line, help);

        // Buttons + key hints.
        let save = " Save ^S ";
        let cancel = " Cancel Esc ";
        let sr = Rect::new(foot.x, foot.y, save.width() as u16, 1);
        let cr = Rect::new(sr.right() + 1, foot.y, cancel.width() as u16, 1);
        f.render_widget(Span::styled(save, theme.accent().add_modifier(Modifier::REVERSED | Modifier::BOLD)), sr);
        f.render_widget(Span::styled(cancel, theme.dim().add_modifier(Modifier::REVERSED)), cr);
        mouse.add(sr, Target::EditorButton(true));
        mouse.add(cr, Target::EditorButton(false));
        let keys = if self.editing.is_some() { "Enter done · Esc undo · ^R show password" } else { "Enter/Space change · ←/→ choose · ^R show passwords" };
        let kx = cr.right() + 2;
        if kx < foot.right() {
            f.render_widget(Span::styled(truncate(keys, (foot.right() - kx) as usize), theme.dim()), Rect { x: kx, width: foot.right() - kx, ..foot });
        }
    }
}
