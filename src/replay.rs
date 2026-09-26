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

    /// Forget `sig_hex`, e.g. when execution failed before the process
    /// started, so the signer can retry without re-signing.
    pub fn release(&self, sig_hex: &str) {
        let mut map = self.inner.lock().expect("replay cache lock poisoned");
        map.remove(sig_hex);
    }
}

/// In-memory set of revoked approver-signature hashes. Each entry carries
/// its own expiry: the moment the underlying bundle would have aged out of
/// `approver_max_validity` anyway, after which keeping it is pointless.
#[derive(Clone, Default)]
pub struct RevocationCache {
    inner: Arc<Mutex<HashMap<String, Instant>>>,
}

impl RevocationCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record `sig_hex` as revoked for the next `remaining` duration.
    pub fn revoke(&self, sig_hex: &str, remaining: Duration) {
        let mut map = self.inner.lock().expect("revocation cache lock poisoned");
        let now = Instant::now();
        if map.len() > SWEEP_THRESHOLD {
            map.retain(|_, expires_at| *expires_at > now);
        }
        let expires_at = now + remaining;
        // Keep the later expiry if revoked twice.
        match map.get(sig_hex) {
            Some(existing) if *existing >= expires_at => {}
            _ => {
                map.insert(sig_hex.to_string(), expires_at);
            }
        }
    }

    pub fn is_revoked(&self, sig_hex: &str) -> bool {
        let map = self.inner.lock().expect("revocation cache lock poisoned");
        map.get(sig_hex)
            .map(|expires_at| *expires_at > Instant::now())
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn revoked_sig_is_reported() {
        let cache = RevocationCache::new();
        cache.revoke("abc", Duration::from_secs(60));
        assert!(cache.is_revoked("abc"));
        assert!(!cache.is_revoked("def"));
    }

    #[test]
    fn expired_revocation_is_forgotten() {
        let cache = RevocationCache::new();
        cache.revoke("abc", Duration::from_secs(0));
        assert!(!cache.is_revoked("abc"));
    }

    #[test]
    fn re_revoke_keeps_later_expiry() {
        let cache = RevocationCache::new();
        cache.revoke("abc", Duration::from_secs(60));
        cache.revoke("abc", Duration::from_secs(0));
        assert!(cache.is_revoked("abc"));
    }

    #[test]
    fn first_seen_wins_same_ttl() {
        let cache = ReplayCache::new();
        let ttl = Duration::from_secs(60);
        assert!(cache.check_and_insert("abc", ttl).is_ok());
        assert!(cache.check_and_insert("abc", ttl).is_err());
    }

    #[test]
    fn released_sig_can_be_used_again() {
        let cache = ReplayCache::new();
        let ttl = Duration::from_secs(60);
        assert!(cache.check_and_insert("abc", ttl).is_ok());
        cache.release("abc");
        assert!(cache.check_and_insert("abc", ttl).is_ok());
    }

    #[test]
    fn distinct_sigs_independent() {
        let cache = ReplayCache::new();
        let ttl = Duration::from_secs(60);
        assert!(cache.check_and_insert("abc", ttl).is_ok());
        assert!(cache.check_and_insert("def", ttl).is_ok());
    }
}
