//! Key combos: parsing from config strings ("ctrl-p", "shift-tab", "j", "<f1>")
//! and pretty display for help/footer ("C-p", "⇧Tab", "j").

use std::fmt;
use std::str::FromStr;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct KeyCombo {
    pub code: KeyCode,
    pub mods: KeyModifiers,
}

impl KeyCombo {
    pub const fn new(code: KeyCode, mods: KeyModifiers) -> Self {
        Self { code, mods }
    }

    pub const fn plain(code: KeyCode) -> Self {
        Self::new(code, KeyModifiers::NONE)
    }

    /// Normalise a crossterm key event so it can be compared to parsed combos.
    /// Shift is folded into the character for printable keys ('J' not shift-j),
    /// and BackTab is always reported as shift+BackTab.
    pub fn from_event(ev: &KeyEvent) -> Self {
        let mut mods = ev.modifiers & (KeyModifiers::CONTROL | KeyModifiers::ALT | KeyModifiers::SHIFT);
        let code = match ev.code {
            KeyCode::Char(c) => {
                mods.remove(KeyModifiers::SHIFT);
                KeyCode::Char(c)
            }
            KeyCode::BackTab => {
                mods.remove(KeyModifiers::SHIFT);
                KeyCode::BackTab
            }
            other => other,
        };
        Self { code, mods }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct ParseKeyError(pub String);

impl fmt::Display for ParseKeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unrecognised key '{}'", self.0)
    }
}

impl std::error::Error for ParseKeyError {}

impl FromStr for KeyCombo {
    type Err = ParseKeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let raw = s.trim();
        let err = || ParseKeyError(raw.to_string());
        if raw.is_empty() {
            return Err(err());
        }
        // A bare single character (including "-" and "+") is always that character.
        let mut chars = raw.chars();
        if let (Some(c), None) = (chars.next(), chars.next()) {
            return Ok(Self::plain(KeyCode::Char(c)));
        }
        let body = raw.trim_start_matches('<').trim_end_matches('>');
        let mut mods = KeyModifiers::NONE;
        let mut rest = body;
        loop {
            let lower = rest.to_ascii_lowercase();
            let stripped = ["ctrl-", "c-", "control-", "ctrl+", "alt-", "a-", "m-", "alt+", "shift-", "s-", "shift+"]
                .iter()
                .find(|p| lower.starts_with(*p) && rest.len() > p.len());
            match stripped {
                Some(p) => {
                    match p.chars().next() {
                        Some('c') => mods |= KeyModifiers::CONTROL,
                        Some('a') | Some('m') => mods |= KeyModifiers::ALT,
                        _ => mods |= KeyModifiers::SHIFT,
                    }
                    rest = &rest[p.len()..];
                }
                None => break,
            }
        }
        let name = rest.to_ascii_lowercase();
        let code = match name.as_str() {
            "enter" | "return" | "cr" => KeyCode::Enter,
            "esc" | "escape" => KeyCode::Esc,
            "space" | "spc" => KeyCode::Char(' '),
            "tab" => {
                if mods.contains(KeyModifiers::SHIFT) {
                    mods.remove(KeyModifiers::SHIFT);
                    KeyCode::BackTab
                } else {
                    KeyCode::Tab
                }
            }
            "backtab" => KeyCode::BackTab,
            "backspace" | "bs" => KeyCode::Backspace,
            "delete" | "del" => KeyCode::Delete,
            "insert" | "ins" => KeyCode::Insert,
            "up" => KeyCode::Up,
            "down" => KeyCode::Down,
            "left" => KeyCode::Left,
            "right" => KeyCode::Right,
            "home" => KeyCode::Home,
            "end" => KeyCode::End,
            "pageup" | "pgup" => KeyCode::PageUp,
            "pagedown" | "pgdn" | "pgdown" => KeyCode::PageDown,
            "minus" => KeyCode::Char('-'),
            "plus" => KeyCode::Char('+'),
            n if n.starts_with('f') && n.len() > 1 => {
                let num: u8 = n[1..].parse().map_err(|_| err())?;
                if !(1..=24).contains(&num) {
                    return Err(err());
                }
                KeyCode::F(num)
            }
            _ => {
                let mut cs = rest.chars();
                match (cs.next(), cs.next()) {
                    (Some(c), None) => {
                        if mods.contains(KeyModifiers::SHIFT) && c.is_ascii_alphabetic() {
                            mods.remove(KeyModifiers::SHIFT);
                            KeyCode::Char(c.to_ascii_uppercase())
                        } else {
                            KeyCode::Char(c)
                        }
                    }
                    _ => return Err(err()),
                }
            }
        };
        Ok(Self { code, mods })
    }
}

impl fmt::Display for KeyCombo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.mods.contains(KeyModifiers::CONTROL) {
            write!(f, "C-")?;
        }
        if self.mods.contains(KeyModifiers::ALT) {
            write!(f, "M-")?;
        }
        if self.mods.contains(KeyModifiers::SHIFT) {
            write!(f, "S-")?;
        }
        match self.code {
            KeyCode::Char(' ') => write!(f, "Space"),
            KeyCode::Char(c) => write!(f, "{c}"),
            KeyCode::Enter => write!(f, "Enter"),
            KeyCode::Esc => write!(f, "Esc"),
            KeyCode::Tab => write!(f, "Tab"),
            KeyCode::BackTab => write!(f, "S-Tab"),
            KeyCode::Backspace => write!(f, "Bksp"),
            KeyCode::Delete => write!(f, "Del"),
            KeyCode::Insert => write!(f, "Ins"),
            KeyCode::Up => write!(f, "↑"),
            KeyCode::Down => write!(f, "↓"),
            KeyCode::Left => write!(f, "←"),
            KeyCode::Right => write!(f, "→"),
            KeyCode::Home => write!(f, "Home"),
            KeyCode::End => write!(f, "End"),
            KeyCode::PageUp => write!(f, "PgUp"),
            KeyCode::PageDown => write!(f, "PgDn"),
            KeyCode::F(n) => write!(f, "F{n}"),
            other => write!(f, "{other:?}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::KeyEventKind;

    fn p(s: &str) -> KeyCombo {
        s.parse().unwrap()
    }

    #[test]
    fn parses_common_forms() {
        assert_eq!(p("j"), KeyCombo::plain(KeyCode::Char('j')));
        assert_eq!(p("J"), KeyCombo::plain(KeyCode::Char('J')));
        assert_eq!(p("shift-j"), KeyCombo::plain(KeyCode::Char('J')));
        assert_eq!(p("-"), KeyCombo::plain(KeyCode::Char('-')));
        assert_eq!(p("ctrl-p"), KeyCombo::new(KeyCode::Char('p'), KeyModifiers::CONTROL));
        assert_eq!(p("<C-p>"), KeyCombo::new(KeyCode::Char('p'), KeyModifiers::CONTROL));
        assert_eq!(p("shift-tab"), KeyCombo::plain(KeyCode::BackTab));
        assert_eq!(p("space"), KeyCombo::plain(KeyCode::Char(' ')));
        assert_eq!(p("pgdn"), KeyCombo::plain(KeyCode::PageDown));
        assert_eq!(p("f5"), KeyCombo::plain(KeyCode::F(5)));
        assert!("nonsense".parse::<KeyCombo>().is_err());
        assert!("f99".parse::<KeyCombo>().is_err());
    }

    #[test]
    fn event_normalisation_matches_parse() {
        let ev = KeyEvent::new_with_kind(KeyCode::Char('J'), KeyModifiers::SHIFT, KeyEventKind::Press);
        assert_eq!(KeyCombo::from_event(&ev), p("J"));
        let ev = KeyEvent::new_with_kind(KeyCode::BackTab, KeyModifiers::SHIFT, KeyEventKind::Press);
        assert_eq!(KeyCombo::from_event(&ev), p("shift-tab"));
    }

    #[test]
    fn display_round_trip() {
        for s in ["j", "C-p", "Enter", "S-Tab", "F2", "Space"] {
            let k = p(s);
            assert_eq!(k.to_string().parse::<KeyCombo>().unwrap(), k, "{s}");
        }
    }
}
