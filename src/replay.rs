//! The agent's replay cache for executed requests, and its local set of
//! revoked requests.
//!
//! Both are keyed by request id — the hash of the signed request, which
//! every approval of it signs, so no re-signing or re-encoding yields a
//! different key for the same request. First-seen wins; a second submission
//! of the same request is rejected, whoever approved it.
//!
//! Each entry expires once no approval that could run the request is still
//! valid (see `security::replay_ttl`), so there's no need to keep it longer.
//!
//! With `[agent] state_dir` set, both are written to disk and survive a
//! restart; otherwise they live in memory, and a restart forgets which
//! requests ran and which were revoked.

use crate::store::ExpiringSet;
use std::path::Path;
use std::time::Duration;

/// File names inside `[agent] state_dir`.
const REPLAY_FILE: &str = "replay.jsonl";
const REVOCATIONS_FILE: &str = "revocations.jsonl";

/// The Unix time `ttl` from now, rounded up to a whole second.
fn expiry(ttl: Duration) -> i64 {
    let secs = ttl.as_secs().saturating_add(u64::from(ttl.subsec_nanos() > 0));
    time::OffsetDateTime::now_utc()
        .unix_timestamp()
        .saturating_add(i64::try_from(secs).unwrap_or(i64::MAX))
}

#[derive(Debug, thiserror::Error)]
pub enum ReplayError {
    /// The request is already recorded and unexpired.
    #[error("request already executed")]
    AlreadyRun,
    /// The record couldn't be written, so the request must not run.
    #[error("could not record the request: {0}")]
    Store(String),
}

#[derive(Clone)]
pub struct ReplayCache {
    set: ExpiringSet,
}

impl Default for ReplayCache {
    fn default() -> Self {
        Self::new()
    }
}

impl ReplayCache {
    /// In memory only.
    pub fn new() -> Self {
        ReplayCache {
            set: ExpiringSet::in_memory(),
        }
    }

    /// Kept in `state_dir`, so it survives a restart.
    pub fn persistent(state_dir: &Path) -> Result<Self, String> {
        Ok(ReplayCache {
            set: ExpiringSet::load(state_dir.join(REPLAY_FILE))?,
        })
    }

    /// Record `key` as used for the next `ttl`. Fails if it is already
    /// recorded and unexpired, or if the record can't be written — a run
    /// that can't be remembered must not start.
    pub fn check_and_insert(&self, key: &str, ttl: Duration) -> Result<(), ReplayError> {
        match self.set.insert_new(key, expiry(ttl)) {
            Ok(true) => Ok(()),
            Ok(false) => Err(ReplayError::AlreadyRun),
            Err(e) => Err(ReplayError::Store(e)),
        }
    }

    /// Forget `key`, e.g. when execution failed before the process
    /// started, so the request can be retried without new approvals.
    pub fn release(&self, key: &str) {
        if let Err(e) = self.set.remove(key) {
            // The entry stays: the request counts as used, which is the
            // safe way to be wrong.
            tracing::error!("Failed to release replay entry: {e}");
        }
    }

    #[cfg(test)]
    fn sweep_now(&self) {
        self.set.sweep_now();
    }
}

/// Revoked requests, keyed by request id. Each entry carries its own
/// expiry: the moment every approval of the request would have aged out of
/// `approval_validity` anyway, after which keeping it is pointless.
#[derive(Clone)]
pub struct RevocationCache {
    set: ExpiringSet,
}

impl Default for RevocationCache {
    fn default() -> Self {
        Self::new()
    }
}

impl RevocationCache {
    /// In memory only.
    pub fn new() -> Self {
        RevocationCache {
            set: ExpiringSet::in_memory(),
        }
    }

    /// Kept in `state_dir`, so it survives a restart.
    pub fn persistent(state_dir: &Path) -> Result<Self, String> {
        Ok(RevocationCache {
            set: ExpiringSet::load(state_dir.join(REVOCATIONS_FILE))?,
        })
    }

    /// Record `key` as revoked for the next `remaining` duration; keeps the
    /// later expiry if revoked twice.
    pub fn revoke(&self, key: &str, remaining: Duration) -> Result<(), String> {
        self.set.insert(key, expiry(remaining))
    }

    pub fn is_revoked(&self, key: &str) -> bool {
        self.set.contains(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn revoked_request_is_reported() {
        let cache = RevocationCache::new();
        cache.revoke("abc", Duration::from_secs(60)).unwrap();
        assert!(cache.is_revoked("abc"));
        assert!(!cache.is_revoked("def"));
    }

    #[test]
    fn expired_revocation_is_forgotten() {
        let cache = RevocationCache::new();
        cache.revoke("abc", Duration::from_secs(0)).unwrap();
        assert!(!cache.is_revoked("abc"));
    }

    #[test]
    fn re_revoke_keeps_later_expiry() {
        let cache = RevocationCache::new();
        cache.revoke("abc", Duration::from_secs(60)).unwrap();
        cache.revoke("abc", Duration::from_secs(0)).unwrap();
        assert!(cache.is_revoked("abc"));
    }

    #[test]
    fn first_seen_wins_same_ttl() {
        let cache = ReplayCache::new();
        let ttl = Duration::from_secs(60);
        assert!(cache.check_and_insert("abc", ttl).is_ok());
        assert!(matches!(cache.check_and_insert("abc", ttl), Err(ReplayError::AlreadyRun)));
    }

    #[test]
    fn released_request_can_be_used_again() {
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
    fn distinct_requests_independent() {
        let cache = ReplayCache::new();
        let ttl = Duration::from_secs(60);
        assert!(cache.check_and_insert("abc", ttl).is_ok());
        assert!(cache.check_and_insert("def", ttl).is_ok());
    }

    #[test]
    fn persistent_caches_remember_across_a_restart() {
        let dir = std::env::temp_dir().join(format!("remonce-state-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let ttl = Duration::from_secs(60);
        {
            let replay = ReplayCache::persistent(&dir).unwrap();
            replay.check_and_insert("ran", ttl).unwrap();
            replay.check_and_insert("failed-to-start", ttl).unwrap();
            replay.release("failed-to-start");
            RevocationCache::persistent(&dir).unwrap().revoke("revoked", ttl).unwrap();
        }
        let replay = ReplayCache::persistent(&dir).unwrap();
        assert!(matches!(replay.check_and_insert("ran", ttl), Err(ReplayError::AlreadyRun)));
        assert!(replay.check_and_insert("failed-to-start", ttl).is_ok());
        assert!(RevocationCache::persistent(&dir).unwrap().is_revoked("revoked"));
        let _ = std::fs::remove_dir_all(dir);
    }
}
