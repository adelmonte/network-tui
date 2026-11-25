//! Config file helpers shared by all apps.
//!
//! Each app has `~/.config/<app>/config.toml`. On first run we write the
//! app's commented default so every option is discoverable in the file itself.
//! A broken file is reported as a warning and the built-in defaults are used.

use std::path::{Path, PathBuf};

use serde::de::DeserializeOwned;

pub fn config_dir(app: &str) -> PathBuf {
    dirs::config_dir().unwrap_or_else(|| PathBuf::from(".config")).join(app)
}

pub fn default_path(app: &str) -> PathBuf {
    config_dir(app).join("config.toml")
}

pub struct Loaded<T> {
    pub value: T,
    pub path: PathBuf,
    pub warnings: Vec<String>,
}

/// Load `path` (or the default path), creating it from `default_text` if missing.
/// `default_text` must deserialize into `T` on its own.
pub fn load<T: DeserializeOwned>(app: &str, path: Option<&Path>, default_text: &str) -> Loaded<T> {
    let path = path.map(Path::to_path_buf).unwrap_or_else(|| default_path(app));
    let mut warnings = Vec::new();
    if !path.exists() {
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        if let Err(e) = std::fs::write(&path, default_text) {
            warnings.push(format!("could not write default config {}: {e}", path.display()));
        }
    }
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        warnings.push(format!("could not read {}: {e}", path.display()));
        default_text.to_string()
    });
    let value = match toml::from_str::<T>(&text) {
        Ok(v) => v,
        Err(e) => {
            warnings.push(format!("{}: {} — using defaults", path.display(), e.message()));
            toml::from_str(default_text).expect("built-in default config must parse")
        }
    };
    Loaded { value, path, warnings }
}

/// Write a whole file atomically (write temp + rename) so a crash never
/// leaves a half-written config behind.
pub fn write_atomic(path: &Path, contents: &str) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("tmp~");
    std::fs::write(&tmp, contents)?;
    std::fs::rename(&tmp, path)
}

/// Update a single key inside a TOML file while keeping comments and layout.
/// `table` is a dotted path like "bluetooth" or "" for top level.
pub fn set_value(path: &Path, table: &str, key: &str, value: toml_edit::Item) -> Result<(), String> {
    let text = std::fs::read_to_string(path).unwrap_or_default();
    let mut doc: toml_edit::DocumentMut = text.parse().map_err(|e: toml_edit::TomlError| e.to_string())?;
    let mut cur: &mut toml_edit::Item = doc.as_item_mut();
    if !table.is_empty() {
        for part in table.split('.') {
            let t = cur.as_table_like_mut().ok_or_else(|| format!("{part} is not a table"))?;
            if t.get(part).is_none() {
                t.insert(part, toml_edit::Item::Table(toml_edit::Table::new()));
            }
            cur = t.get_mut(part).expect("just inserted");
        }
    }
    let t = cur.as_table_like_mut().ok_or_else(|| format!("{table} is not a table"))?;
    t.insert(key, value);
    write_atomic(path, &doc.to_string()).map_err(|e| e.to_string())
}
