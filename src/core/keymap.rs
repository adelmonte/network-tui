//! Generic keymap: many keys -> many actions, overridable from config.
//!
//! Apps declare their action enum with [`define_actions!`], which generates
//! names (used as config keys), descriptions (used by help/footer/palette)
//! and default bindings in one place so help text can never drift.

use std::collections::HashMap;
use std::hash::Hash;

use super::keys::KeyCombo;

/// Implemented by the enum generated with [`define_actions!`].
pub trait ActionSet: Copy + Eq + Hash + 'static {
    fn all() -> &'static [Self];
    fn name(self) -> &'static str;
    fn description(self) -> &'static str;
    fn default_keys(self) -> &'static [&'static str];
    fn from_name(name: &str) -> Option<Self> {
        Self::all().iter().copied().find(|a| a.name() == name)
    }
}

/// Declare an action enum.
///
/// ```ignore
/// define_actions! {
///     pub enum Action {
///         Quit => "quit", "Quit", ["q", "ctrl-c"],
///     }
/// }
/// ```
#[macro_export]
macro_rules! define_actions {
    (
        $vis:vis enum $name:ident {
            $( $variant:ident => $key:literal, $desc:literal, [ $( $k:literal ),* $(,)? ] ),* $(,)?
        }
    ) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
        $vis enum $name { $( $variant ),* }

        impl $crate::core::keymap::ActionSet for $name {
            fn all() -> &'static [Self] {
                &[ $( $name::$variant ),* ]
            }
            fn name(self) -> &'static str {
                match self { $( $name::$variant => $key ),* }
            }
            fn description(self) -> &'static str {
                match self { $( $name::$variant => $desc ),* }
            }
            fn default_keys(self) -> &'static [&'static str] {
                match self { $( $name::$variant => &[ $( $k ),* ] ),* }
            }
        }
    };
}

#[derive(Clone, Debug)]
pub struct Keymap<A: ActionSet> {
    by_key: HashMap<KeyCombo, Vec<A>>,
    by_action: HashMap<A, Vec<KeyCombo>>,
}

impl<A: ActionSet> Keymap<A> {
    /// Build from defaults, then apply overrides (`action name -> keys`).
    /// An override replaces all default keys of that action; an empty list unbinds it.
    /// Returns the keymap plus human-readable warnings for bad entries.
    pub fn build(overrides: &HashMap<String, Vec<String>>) -> (Self, Vec<String>) {
        let mut warnings = Vec::new();
        let mut by_action: HashMap<A, Vec<KeyCombo>> = HashMap::new();
        for &a in A::all() {
            let keys = a
                .default_keys()
                .iter()
                .map(|k| k.parse().unwrap_or_else(|e| panic!("bad default key for {}: {e}", a.name())))
                .collect();
            by_action.insert(a, keys);
        }
        let mut names: Vec<_> = overrides.keys().collect();
        names.sort();
        for name in names {
            let Some(action) = A::from_name(name) else {
                warnings.push(format!("[keys] unknown action '{name}'"));
                continue;
            };
            let mut keys = Vec::new();
            for k in &overrides[name] {
                match k.parse::<KeyCombo>() {
                    Ok(c) => keys.push(c),
                    Err(e) => warnings.push(format!("[keys] {name}: {e}")),
                }
            }
            by_action.insert(action, keys);
        }
        let mut by_key: HashMap<KeyCombo, Vec<A>> = HashMap::new();
        // Preserve declaration order so earlier actions win ties.
        for &a in A::all() {
            for k in &by_action[&a] {
                by_key.entry(*k).or_default().push(a);
            }
        }
        (Self { by_key, by_action }, warnings)
    }

    /// All actions bound to this key, in declaration order.
    pub fn actions_for(&self, key: &KeyCombo) -> &[A] {
        self.by_key.get(key).map(Vec::as_slice).unwrap_or(&[])
    }

    pub fn keys_for(&self, action: A) -> &[KeyCombo] {
        self.by_action.get(&action).map(Vec::as_slice).unwrap_or(&[])
    }

    /// Short label for footers: first bound key, or None if unbound.
    pub fn hint(&self, action: A) -> Option<String> {
        self.keys_for(action).first().map(|k| k.to_string())
    }

    /// All keys joined, for the help popup.
    pub fn keys_label(&self, action: A) -> String {
        let ks = self.keys_for(action);
        if ks.is_empty() {
            "—".into()
        } else {
            ks.iter().map(|k| k.to_string()).collect::<Vec<_>>().join(" ")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyCode, KeyModifiers};

    crate::define_actions! {
        enum TestAction {
            Up => "up", "Move up", ["k", "up"],
            Quit => "quit", "Quit", ["q", "ctrl-c"],
            Other => "other", "Shares q", ["q"],
        }
    }

    #[test]
    fn defaults_and_order() {
        let (km, w) = Keymap::<TestAction>::build(&HashMap::new());
        assert!(w.is_empty());
        let q = KeyCombo::plain(KeyCode::Char('q'));
        assert_eq!(km.actions_for(&q), &[TestAction::Quit, TestAction::Other]);
        let cc = KeyCombo::new(KeyCode::Char('c'), KeyModifiers::CONTROL);
        assert_eq!(km.actions_for(&cc), &[TestAction::Quit]);
    }

    #[test]
    fn overrides_replace_and_warn() {
        let mut o = HashMap::new();
        o.insert("up".to_string(), vec!["w".to_string(), "bogus-key".to_string()]);
        o.insert("nope".to_string(), vec!["x".to_string()]);
        o.insert("other".to_string(), vec![]);
        let (km, w) = Keymap::<TestAction>::build(&o);
        assert_eq!(w.len(), 2);
        assert!(km.actions_for(&KeyCombo::plain(KeyCode::Char('k'))).is_empty());
        assert_eq!(km.actions_for(&KeyCombo::plain(KeyCode::Char('w'))), &[TestAction::Up]);
        assert_eq!(km.actions_for(&KeyCombo::plain(KeyCode::Char('q'))), &[TestAction::Quit]);
        assert_eq!(km.hint(TestAction::Other), None);
    }
}
