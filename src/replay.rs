//! In-memory replay cache for recently-used executions.
//!
//! Keyed by the *executor's key binding* (operator if delegated, else
//! approver) — the IdP-attested `nonce`, which unlike signature bytes can't
//! be mauled into a fresh-looking variant. First-seen wins; a second
//! submission of the same bundle is rejected.
//!
//! Each entry expires when the executor signature would fail freshness
//! anyway, so there's no need to keep it pinned past that.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const SWEEP_THRESHOLD: usize = 10_000;

#[derive(Clone, Default)]
pub struct ReplayCache {
    /// Key → the instant the entry may be forgotten. Per-entry expiry, so a
    /// sweep triggered by a short-window request can't evict entries that
    /// belong to a longer window.
    inner: Arc<Mutex<HashMap<String, Instant>>>,
}

impl ReplayCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record `key` as used for the next `ttl` and return `Ok(())`, or
    /// `Err(())` if it is already recorded and unexpired.
    pub fn check_and_insert(&self, key: &str, ttl: Duration) -> Result<(), ()> {
        let mut map = self.inner.lock().expect("replay cache lock poisoned");
        let now = Instant::now();

        if map.len() > SWEEP_THRESHOLD {
            map.retain(|_, expires_at| *expires_at > now);
        }

        if map.get(key).is_some_and(|expires_at| *expires_at > now) {
            return Err(());
        }

        map.insert(key.to_string(), now + ttl);
        Ok(())
    }

    /// Forget `key`, e.g. when execution failed before the process
    /// started, so the signer can retry without re-signing.
    pub fn release(&self, key: &str) {
        let mut map = self.inner.lock().expect("replay cache lock poisoned");
        map.remove(key);
    }

    #[cfg(test)]
    fn sweep_now(&self) {
        let now = Instant::now();
        self.inner
            .lock()
            .unwrap()
            .retain(|_, expires_at| *expires_at > now);
    }
}

/// In-memory set of revoked approvals, keyed by the approver's key binding.
/// Each entry carries
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

    /// Record `key` as revoked for the next `remaining` duration.
    pub fn revoke(&self, key: &str, remaining: Duration) {
        let mut map = self.inner.lock().expect("revocation cache lock poisoned");
        let now = Instant::now();
        if map.len() > SWEEP_THRESHOLD {
            map.retain(|_, expires_at| *expires_at > now);
        }
        let expires_at = now + remaining;
        // Keep the later expiry if revoked twice.
        match map.get(key) {
            Some(existing) if *existing >= expires_at => {}
            _ => {
                map.insert(key.to_string(), expires_at);
            }
        }
    }

    pub fn is_revoked(&self, key: &str) -> bool {
        let map = self.inner.lock().expect("revocation cache lock poisoned");
        map.get(key)
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
    fn mixed_ttl_sweep_keeps_long_entries() {
        let cache = ReplayCache::new();
        assert!(cache.check_and_insert("long", Duration::from_secs(3600)).is_ok());
        assert!(cache.check_and_insert("short", Duration::from_secs(0)).is_ok());
        cache.sweep_now();
        assert!(cache.check_and_insert("long", Duration::from_secs(1)).is_err());
        assert!(cache.check_and_insert("short", Duration::from_secs(60)).is_ok());
    }

    #[test]
    fn distinct_sigs_independent() {
        let cache = ReplayCache::new();
        let ttl = Duration::from_secs(60);
        assert!(cache.check_and_insert("abc", ttl).is_ok());
        assert!(cache.check_and_insert("def", ttl).is_ok());
    }
}
