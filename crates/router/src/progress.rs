//! Bounded, request-scoped progress for the local provider bridge.
use std::collections::BTreeMap;
use std::sync::Mutex;

use serde::Serialize;

const MAX_REQUESTS: usize = 128;
const MAX_EVENTS: usize = 64;
const TTL_MS: i64 = 15 * 60 * 1000;

#[derive(Clone, Default, Serialize)]
pub(super) struct Snapshot {
    pub stages: Vec<&'static str>,
    pub done: bool,
    #[serde(skip)]
    touched: i64,
}

#[derive(Default)]
pub(super) struct Progress(Mutex<BTreeMap<String, Snapshot>>);

impl Progress {
    pub fn start(&self, id: Option<&str>, now: i64) -> Option<String> {
        let id = id.filter(|id| uuid::Uuid::parse_str(id).is_ok())?;
        let mut entries = self.0.lock().ok()?;
        entries.retain(|_, entry| now.saturating_sub(entry.touched) < TTL_MS);
        if entries.contains_key(id) {
            return None;
        }
        if entries.len() >= MAX_REQUESTS {
            let oldest = entries
                .iter()
                .min_by_key(|(_, entry)| entry.touched)
                .map(|(id, _)| id.clone());
            if let Some(oldest) = oldest {
                entries.remove(&oldest);
            }
        }
        entries.insert(
            id.into(),
            Snapshot {
                touched: now,
                ..Snapshot::default()
            },
        );
        Some(id.into())
    }

    pub fn stage(&self, id: Option<&str>, stage: &'static str, now: i64) {
        let Some(id) = id else { return };
        if let Ok(mut entries) = self.0.lock() {
            if let Some(entry) = entries.get_mut(id) {
                entry.touched = now;
                if entry.stages.last() != Some(&stage) && entry.stages.len() < MAX_EVENTS {
                    entry.stages.push(stage);
                }
            }
        }
    }

    pub fn finish(&self, id: Option<&str>) {
        if let (Some(id), Ok(mut entries)) = (id, self.0.lock()) {
            if let Some(entry) = entries.get_mut(id) {
                entry.done = true;
            }
        }
    }

    pub fn get(&self, id: &str, now: i64) -> Option<Snapshot> {
        self.0
            .lock()
            .ok()?
            .get(id)
            .filter(|entry| now.saturating_sub(entry.touched) < TTL_MS)
            .cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn progress_is_isolated_bounded_and_expires() {
        let progress = Progress::default();
        let a = uuid::Uuid::new_v4().to_string();
        let b = uuid::Uuid::new_v4().to_string();
        assert!(progress.start(Some("invalid"), 0).is_none());
        progress.start(Some(&a), 0).unwrap();
        progress.start(Some(&b), 0).unwrap();
        assert!(progress.start(Some(&a), 1).is_none());
        for n in 0..100 {
            progress.stage(
                Some(&a),
                if n % 2 == 0 {
                    "waiting-for-account"
                } else {
                    "fallback"
                },
                1,
            );
        }
        progress.finish(Some(&a));
        assert_eq!(progress.get(&a, 1).unwrap().stages.len(), MAX_EVENTS);
        assert!(progress.get(&a, 1).unwrap().done);
        assert!(progress.get(&b, 1).unwrap().stages.is_empty());
        assert!(progress.get(&a, TTL_MS + 1).is_none());
        for n in 0..200 {
            progress
                .start(Some(&uuid::Uuid::new_v4().to_string()), n)
                .unwrap();
        }
        assert_eq!(progress.0.lock().unwrap().len(), MAX_REQUESTS);
    }
}
