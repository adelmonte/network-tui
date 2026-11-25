//! Family theme. Every app shares the palette; only the accent differs by default.
//! Colours accept names ("blue"), indexes ("12") or hex ("#7aa2f7").
//! `NO_COLOR` (https://no-color.org) switches to a monochrome theme that uses
//! bold/reverse/dim instead of colour.

use ratatui::style::{Color, Modifier, Style};
use serde::Deserialize;

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ThemeConfig {
    /// "dark" (default) or "mono".
    pub preset: Option<String>,
    pub accent: Option<String>,
    pub fg: Option<String>,
    pub dim: Option<String>,
    pub border: Option<String>,
    pub selection: Option<String>,
    pub ok: Option<String>,
    pub warn: Option<String>,
    pub error: Option<String>,
    pub info: Option<String>,
}

#[derive(Clone, Debug)]
pub struct Theme {
    pub mono: bool,
    pub accent: Color,
    pub fg: Color,
    pub dim: Color,
    pub border: Color,
    pub selection: Color,
    pub ok: Color,
    pub warn: Color,
    pub error: Color,
    pub info: Color,
}

impl Theme {
    pub fn dark(accent: Color) -> Self {
        Self {
            mono: false,
            accent,
            fg: Color::Reset,
            dim: Color::Rgb(0x6c, 0x70, 0x86),
            border: Color::Rgb(0x45, 0x47, 0x5a),
            selection: Color::Rgb(0x31, 0x32, 0x44),
            ok: Color::Rgb(0xa6, 0xe3, 0xa1),
            warn: Color::Rgb(0xf9, 0xe2, 0xaf),
            error: Color::Rgb(0xf3, 0x8b, 0xa8),
            info: Color::Rgb(0x89, 0xdc, 0xeb),
        }
    }

    pub fn mono() -> Self {
        Self {
            mono: true,
            accent: Color::Reset,
            fg: Color::Reset,
            dim: Color::Reset,
            border: Color::Reset,
            selection: Color::Reset,
            ok: Color::Reset,
            warn: Color::Reset,
            error: Color::Reset,
            info: Color::Reset,
        }
    }

    /// Build from config. `app_accent` is the app's default accent colour.
    pub fn from_config(cfg: &ThemeConfig, app_accent: Color, warnings: &mut Vec<String>) -> Self {
        let no_color = std::env::var_os("NO_COLOR").is_some_and(|v| !v.is_empty());
        if no_color || cfg.preset.as_deref() == Some("mono") {
            return Self::mono();
        }
        if let Some(p) = cfg.preset.as_deref()
            && p != "dark" {
                warnings.push(format!("[theme] unknown preset '{p}', using 'dark'"));
            }
        let mut t = Self::dark(app_accent);
        let mut set = |slot: &mut Color, v: &Option<String>, name: &str| {
            if let Some(v) = v {
                match v.parse::<Color>() {
                    Ok(c) => *slot = c,
                    Err(_) => warnings.push(format!("[theme] {name}: can't parse colour '{v}'")),
                }
            }
        };
        set(&mut t.accent, &cfg.accent, "accent");
        set(&mut t.fg, &cfg.fg, "fg");
        set(&mut t.dim, &cfg.dim, "dim");
        set(&mut t.border, &cfg.border, "border");
        set(&mut t.selection, &cfg.selection, "selection");
        set(&mut t.ok, &cfg.ok, "ok");
        set(&mut t.warn, &cfg.warn, "warn");
        set(&mut t.error, &cfg.error, "error");
        set(&mut t.info, &cfg.info, "info");
        t
    }

    fn c(&self, color: Color) -> Style {
        if self.mono {
            Style::default()
        } else {
            Style::default().fg(color)
        }
    }

    pub fn text(&self) -> Style {
        self.c(self.fg)
    }
    pub fn dim(&self) -> Style {
        if self.mono {
            Style::default().add_modifier(Modifier::DIM)
        } else {
            self.c(self.dim)
        }
    }
    pub fn accent(&self) -> Style {
        self.c(self.accent).add_modifier(if self.mono { Modifier::BOLD } else { Modifier::empty() })
    }
    pub fn bold(&self) -> Style {
        self.text().add_modifier(Modifier::BOLD)
    }
    pub fn ok(&self) -> Style {
        self.c(self.ok)
    }
    pub fn warn(&self) -> Style {
        self.c(self.warn).add_modifier(if self.mono { Modifier::BOLD } else { Modifier::empty() })
    }
    pub fn error(&self) -> Style {
        self.c(self.error).add_modifier(if self.mono { Modifier::BOLD } else { Modifier::empty() })
    }
    pub fn info(&self) -> Style {
        self.c(self.info)
    }
    pub fn border(&self, focused: bool) -> Style {
        if focused {
            self.accent()
        } else if self.mono {
            Style::default().add_modifier(Modifier::DIM)
        } else {
            self.c(self.border)
        }
    }
    /// Highlight for the selected row. `focused` = the list has keyboard focus.
    pub fn selected(&self, focused: bool) -> Style {
        if self.mono {
            return if focused {
                Style::default().add_modifier(Modifier::REVERSED)
            } else {
                Style::default().add_modifier(Modifier::UNDERLINED)
            };
        }
        let s = Style::default().bg(self.selection);
        if focused {
            s.add_modifier(Modifier::BOLD)
        } else {
            s
        }
    }
    /// Key labels in footers/help.
    pub fn key(&self) -> Style {
        self.accent().add_modifier(Modifier::BOLD)
    }
}
