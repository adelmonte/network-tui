//! Shared UI kit: theme, mouse hit-testing, text input, and common widgets
//! (tabs, footer hints, help, command palette, confirm, toasts).
//! Copied verbatim between the three apps — keep it app-agnostic.

#![allow(dead_code)] // shared kit: not every app uses every helper

pub mod input;
pub mod mouse;
pub mod palette;
pub mod theme;
pub mod widgets;
