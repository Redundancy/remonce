//! In-memory replay cache for recently-seen execution signatures.
//!
//! Keyed by the hex of the *most recent* signature in an `ExecutionBundle`
//! (operator cosign if present, else approver signature). First-seen wins;
//! a second submission of the same bundle is rejected.
//!
//! TTL bounds the cache against the operator short-validity window — once
//! a signature is too old to pass freshness checks anyway, there's no need
//! to keep it pinned here.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const SWEEP_THRESHOLD: usize = 10_000;

#[derive(Clone, Default)]
pub struct ReplayCache {
    inner: Arc<Mutex<HashMap<String, Instant>>>,
}

impl ReplayCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Check whether `sig_hex` has been seen within the last `ttl`.
    /// If not, record it as seen-now and return `Ok(())`.
    /// If it has been seen, return `Err(())`.
    pub fn check_and_insert(&self, sig_hex: &str, ttl: Duration) -> Result<(), ()> {
        let mut map = self.inner.lock().expect("replay cache lock poisoned");
        let now = Instant::now();

        if map.len() > SWEEP_THRESHOLD {
            map.retain(|_, seen_at| now.duration_since(*seen_at) < ttl);
        }

        if let Some(seen_at) = map.get(sig_hex) {
            if now.duration_since(*seen_at) < ttl {
                return Err(());
            }
        }

        map.insert(sig_hex.to_string(), now);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_seen_wins_same_ttl() {
        let cache = ReplayCache::new();
        let ttl = Duration::from_secs(60);
        assert!(cache.check_and_insert("abc", ttl).is_ok());
        assert!(cache.check_and_insert("abc", ttl).is_err());
    }

    #[test]
    fn distinct_sigs_independent() {
        let cache = ReplayCache::new();
        let ttl = Duration::from_secs(60);
        assert!(cache.check_and_insert("abc", ttl).is_ok());
        assert!(cache.check_and_insert("def", ttl).is_ok());
    }
}
