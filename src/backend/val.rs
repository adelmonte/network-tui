//! A small, owned value tree in the shape of NetworkManager's `a{sv}` data.
//! Profiles use it (in NM's settings layout), so the editor and the daemon
//! share one format, and it serializes as-is over the daemon's socket.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

pub type Dict = BTreeMap<String, Val>;
/// setting name -> key -> value, i.e. NM's `a{sa{sv}}` connection settings.
pub type Settings = BTreeMap<String, Dict>;
/// object path -> interface -> property -> value (the demo's fake D-Bus objects).
pub type Objects = BTreeMap<String, BTreeMap<String, Dict>>;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum Val {
    Bool(bool),
    U8(u8),
    I32(i32),
    U32(u32),
    I64(i64),
    U64(u64),
    F64(f64),
    Str(String),
    Path(String),
    Bytes(Vec<u8>),
    BytesList(Vec<Vec<u8>>),
    StrList(Vec<String>),
    PathList(Vec<String>),
    U32List(Vec<u32>),
    U32ListList(Vec<Vec<u32>>),
    Dict(Dict),
    /// `a{ss}` (e.g. bond options).
    StrMap(BTreeMap<String, String>),
    DictList(Vec<Dict>),
    /// Anything we don't model; kept so round-trips are lossless where possible.
    Other(String),
}

impl Val {
    pub fn str(&self) -> Option<&str> {
        match self {
            Val::Str(s) | Val::Path(s) => Some(s),
            _ => None,
        }
    }
    pub fn u32(&self) -> Option<u32> {
        match *self {
            Val::U32(v) => Some(v),
            Val::U8(v) => Some(v as u32),
            Val::I32(v) if v >= 0 => Some(v as u32),
            Val::U64(v) => u32::try_from(v).ok(),
            _ => None,
        }
    }
    pub fn i64(&self) -> Option<i64> {
        match *self {
            Val::I32(v) => Some(v as i64),
            Val::U32(v) => Some(v as i64),
            Val::I64(v) => Some(v),
            Val::U64(v) => i64::try_from(v).ok(),
            Val::U8(v) => Some(v as i64),
            _ => None,
        }
    }
    pub fn bool(&self) -> Option<bool> {
        match *self {
            Val::Bool(b) => Some(b),
            _ => None,
        }
    }
    pub fn bytes(&self) -> Option<&[u8]> {
        match self {
            Val::Bytes(b) => Some(b),
            _ => None,
        }
    }
    pub fn str_list(&self) -> Vec<String> {
        match self {
            Val::StrList(v) | Val::PathList(v) => v.clone(),
            Val::Str(s) if !s.is_empty() => vec![s.clone()],
            _ => Vec::new(),
        }
    }
    pub fn dict_list(&self) -> &[Dict] {
        match self {
            Val::DictList(v) => v,
            _ => &[],
        }
    }
}

/// Convenience accessors on a property dict.
pub trait DictExt {
    fn s(&self, k: &str) -> String;
    fn u(&self, k: &str) -> u32;
    fn i(&self, k: &str) -> i64;
    fn b(&self, k: &str) -> bool;
    fn opt_b(&self, k: &str) -> Option<bool>;
    fn path(&self, k: &str) -> Option<String>;
    fn paths(&self, k: &str) -> Vec<String>;
}

impl DictExt for Dict {
    fn s(&self, k: &str) -> String {
        self.get(k).and_then(Val::str).unwrap_or_default().to_string()
    }
    fn u(&self, k: &str) -> u32 {
        self.get(k).and_then(Val::u32).unwrap_or(0)
    }
    fn i(&self, k: &str) -> i64 {
        self.get(k).and_then(Val::i64).unwrap_or(0)
    }
    fn b(&self, k: &str) -> bool {
        self.get(k).and_then(Val::bool).unwrap_or(false)
    }
    fn opt_b(&self, k: &str) -> Option<bool> {
        self.get(k).and_then(Val::bool)
    }
    /// Object path, with NM's "/" meaning "none".
    fn path(&self, k: &str) -> Option<String> {
        self.get(k).and_then(Val::str).filter(|p| *p != "/" && !p.is_empty()).map(str::to_string)
    }
    fn paths(&self, k: &str) -> Vec<String> {
        self.get(k).map(Val::str_list).unwrap_or_default()
    }
}

/// SSIDs are raw bytes; show them as UTF-8 when possible, else escaped.
pub fn ssid_to_string(b: &[u8]) -> String {
    match std::str::from_utf8(b) {
        Ok(s) => s.to_string(),
        Err(_) => b.iter().map(|c| if c.is_ascii_graphic() || *c == b' ' { (*c as char).to_string() } else { format!("\\x{c:02x}") }).collect(),
    }
}
