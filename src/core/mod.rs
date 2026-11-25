//! Shared core: keys, keymap, terminal, config helpers, logging.
//! This module is copied verbatim between bluetooth-tui, network-tui and audio-tui.
//! Keep it free of app-specific types.

#![allow(dead_code)] // shared kit: not every app uses every helper

pub mod config;
pub mod keys;
pub mod keymap;
pub mod logging;
pub mod term;
