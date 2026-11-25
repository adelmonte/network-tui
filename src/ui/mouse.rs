//! Mouse hit-testing (pattern borrowed from wiremix): while rendering, each
//! interactive widget registers its rectangle and a target value. When a mouse
//! event arrives we look up the topmost rectangle under the cursor.
//! Areas registered later (popups) win over earlier ones.

use ratatui::layout::{Position, Rect};

#[derive(Debug)]
pub struct MouseMap<T> {
    areas: Vec<(Rect, T)>,
}

impl<T> Default for MouseMap<T> {
    fn default() -> Self {
        Self { areas: Vec::new() }
    }
}

impl<T: Clone> MouseMap<T> {
    pub fn clear(&mut self) {
        self.areas.clear();
    }

    pub fn add(&mut self, rect: Rect, target: T) {
        if rect.width > 0 && rect.height > 0 {
            self.areas.push((rect, target));
        }
    }

    /// Topmost target under (col, row), with the rect it was registered with.
    pub fn hit(&self, col: u16, row: u16) -> Option<(Rect, T)> {
        let p = Position::new(col, row);
        self.areas.iter().rev().find(|(r, _)| r.contains(p)).map(|(r, t)| (*r, t.clone()))
    }

    /// Mark everything registered so far as covered by a modal: only areas
    /// added after this call will be hit.
    pub fn modal_barrier(&mut self) {
        self.areas.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn later_areas_win() {
        let mut m = MouseMap::default();
        m.add(Rect::new(0, 0, 10, 10), 1);
        m.add(Rect::new(2, 2, 3, 3), 2);
        assert_eq!(m.hit(3, 3).map(|h| h.1), Some(2));
        assert_eq!(m.hit(0, 0).map(|h| h.1), Some(1));
        assert_eq!(m.hit(20, 0), None);
        m.modal_barrier();
        assert_eq!(m.hit(0, 0), None);
    }
}
