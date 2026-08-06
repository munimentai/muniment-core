use std::sync::Mutex;

#[derive(Debug, Default)]
pub struct EntitlementSnapshotTracker {
    previous: Mutex<Option<u64>>,
}

impl EntitlementSnapshotTracker {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn observe(&self, next: Option<u64>) -> Option<u64> {
        let mut previous = self
            .previous
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let changed = match (*previous, next) {
            (Some(previous), Some(next)) if previous != next => Some(next),
            _ => None,
        };
        *previous = next;
        changed
    }

    pub fn clear(&self) {
        *self
            .previous
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
    }
}
