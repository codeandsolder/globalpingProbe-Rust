use std::collections::HashMap;
use std::time::{Duration, Instant};

const MAX_DISCONNECTS: usize = 3;
const TTL: Duration = Duration::from_mins(5);

pub struct DisconnectTracker {
    entries: HashMap<String, Instant>,
}

impl DisconnectTracker {
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    pub fn record(&mut self) -> bool {
        self.evict_expired();
        let id = uuid::Uuid::new_v4().to_string();
        self.entries.insert(id, Instant::now());
        self.entries.len() >= MAX_DISCONNECTS
    }

    fn evict_expired(&mut self) {
        self.entries.retain(|_, t| t.elapsed() < TTL);
    }

    pub fn count(&mut self) -> usize {
        self.evict_expired();
        self.entries.len()
    }
}

impl Default for DisconnectTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn triggers_at_max_disconnects() {
        let mut tracker = DisconnectTracker::new();
        assert!(!tracker.record());
        assert!(!tracker.record());
        assert!(tracker.record()); // 3rd disconnect → true
    }

    #[test]
    fn count_starts_at_zero() {
        let mut tracker = DisconnectTracker::new();
        assert_eq!(tracker.count(), 0);
    }
}
