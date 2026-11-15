//! A set of keys that each expire, optionally backed by a JSONL append log
//! so it survives restarts.
//!
//! It holds the request ids an agent has run (replay protection) and the
//! ones that were revoked, on the agent and in the central revocation
//! service. Without a file the set lives in memory only.
//!
//! The log is one JSON object per line: `{"v":2,"request_id":…,
//! "expires_at_unix":…}` records a key, and `{"v":2,"request_id":…,
//! "removed":true}` takes it out again. A write is fsynced before the set
//! reports it, so nothing is acknowledged that a crash could lose. Expired
//! entries are dropped, and the file rewritten, on load and from time to
//! time while running.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::Write as _;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

/// Version tag on every stored line.
const STORE_VERSION: u32 = 2;

/// Entries (or appended lines) beyond which expired entries are swept and
/// the log rewritten.
const SWEEP_THRESHOLD: usize = 10_000;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    v: u32,
    /// The key: a request id (hex SHA-256 of the signed request).
    request_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    expires_at_unix: Option<i64>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    removed: bool,
}

#[derive(Clone)]
pub struct ExpiringSet {
    inner: Arc<Mutex<Inner>>,
}

struct Inner {
    /// Key → the Unix time it may be forgotten.
    map: HashMap<String, i64>,
    path: Option<PathBuf>,
    /// Lines appended since the log was last rewritten.
    appended: usize,
}

fn now_unix() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}

impl ExpiringSet {
    /// A set that is forgotten when the process exits.
    pub fn in_memory() -> Self {
        ExpiringSet {
            inner: Arc::new(Mutex::new(Inner {
                map: HashMap::new(),
                path: None,
                appended: 0,
            })),
        }
    }

    /// The set stored in the log at `path` (created if missing), without
    /// its expired entries.
    pub fn load(path: PathBuf) -> Result<Self, String> {
        let mut map: HashMap<String, i64> = HashMap::new();
        let now = now_unix();

        if path.exists() {
            let contents = std::fs::read_to_string(&path)
                .map_err(|e| format!("Failed to read '{}': {e}", path.display()))?;
            let lines: Vec<&str> = contents
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .collect();
            for (idx, line) in lines.iter().enumerate() {
                // Older logs keyed revocations on approvals, which no longer
                // name anything. Refuse rather than silently dropping them —
                // even as the last line, where the torn-write tolerance
                // below would otherwise swallow it.
                if let Ok(serde_json::Value::Object(obj)) =
                    serde_json::from_str::<serde_json::Value>(line)
                    && obj.get("v").and_then(|v| v.as_u64()) != Some(STORE_VERSION as u64)
                {
                    return Err(format!(
                        "'{}' is a log from an older version of Remonce (line {}); \
                         archive it and start a fresh one (see the upgrade notes in CONFIGURATION.md)",
                        path.display(),
                        idx + 1
                    ));
                }
                let record: Record = match serde_json::from_str(line) {
                    Ok(e) => e,
                    // A crash mid-append leaves a torn final line. Refusing
                    // to start would stop everything that depends on this
                    // set, and the torn write was never acknowledged.
                    Err(e) if idx == lines.len() - 1 => {
                        tracing::warn!("Ignoring torn final entry in '{}': {e}", path.display());
                        continue;
                    }
                    Err(e) => {
                        return Err(format!(
                            "Corrupt entry in '{}' (line {}): {e}",
                            path.display(),
                            idx + 1
                        ));
                    }
                };
                match (record.removed, record.expires_at_unix) {
                    (true, _) => {
                        map.remove(&record.request_id);
                    }
                    (false, Some(expires_at_unix)) => {
                        if expires_at_unix <= now {
                            continue;
                        }
                        let slot = map.entry(record.request_id).or_insert(expires_at_unix);
                        if *slot < expires_at_unix {
                            *slot = expires_at_unix;
                        }
                    }
                    (false, None) => {
                        return Err(format!(
                            "Corrupt entry in '{}' (line {}): no expiry",
                            path.display(),
                            idx + 1
                        ));
                    }
                }
            }
        }

        let mut inner = Inner {
            map,
            path: Some(path),
            appended: 0,
        };
        inner.compact()?;
        Ok(ExpiringSet {
            inner: Arc::new(Mutex::new(inner)),
        })
    }

    /// Record `key` until `expires_at_unix`. Idempotent; keeps the later
    /// expiry if recorded twice.
    pub fn insert(&self, key: &str, expires_at_unix: i64) -> Result<(), String> {
        let mut inner = self.lock();
        match inner.map.get(key) {
            Some(existing) if *existing >= expires_at_unix => return Ok(()),
            _ => {}
        }
        inner.record(key, expires_at_unix)
    }

    /// Record `key` until `expires_at_unix` unless it is already there and
    /// unexpired. `Ok(true)` if this call recorded it.
    pub fn insert_new(&self, key: &str, expires_at_unix: i64) -> Result<bool, String> {
        let mut inner = self.lock();
        if inner.map.get(key).is_some_and(|existing| *existing > now_unix()) {
            return Ok(false);
        }
        inner.record(key, expires_at_unix)?;
        Ok(true)
    }

    /// Forget `key`.
    pub fn remove(&self, key: &str) -> Result<(), String> {
        let mut inner = self.lock();
        if !inner.map.contains_key(key) {
            return Ok(());
        }
        inner.append(&Record {
            v: STORE_VERSION,
            request_id: key.to_string(),
            expires_at_unix: None,
            removed: true,
        })?;
        inner.map.remove(key);
        Ok(())
    }

    /// Whether `key` is recorded and unexpired.
    pub fn contains(&self, key: &str) -> bool {
        self.lock().map.get(key).is_some_and(|expires_at| *expires_at > now_unix())
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        // A panic while holding the lock can't leave the map half-updated
        // (each update is one insert or remove), so keep serving.
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    #[cfg(test)]
    pub(crate) fn sweep_now(&self) {
        self.lock().sweep();
    }

    #[cfg(test)]
    pub(crate) fn failing(path: PathBuf) -> Self {
        ExpiringSet {
            inner: Arc::new(Mutex::new(Inner {
                map: HashMap::new(),
                path: Some(path),
                appended: 0,
            })),
        }
    }
}

impl Inner {
    fn record(&mut self, key: &str, expires_at_unix: i64) -> Result<(), String> {
        if self.map.len() > SWEEP_THRESHOLD || self.appended > SWEEP_THRESHOLD {
            self.sweep();
        }
        // Durable first, then visible: if the append fails, the map must not
        // claim the entry exists (it would vanish on restart).
        self.append(&Record {
            v: STORE_VERSION,
            request_id: key.to_string(),
            expires_at_unix: Some(expires_at_unix),
            removed: false,
        })?;
        self.map.insert(key.to_string(), expires_at_unix);
        Ok(())
    }

    fn append(&mut self, record: &Record) -> Result<(), String> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        let line = serde_json::to_string(record).map_err(|e| format!("Serialize error: {e}"))?;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|e| format!("Failed to open '{}': {e}", path.display()))?;
        writeln!(file, "{line}").map_err(|e| format!("Failed to append to '{}': {e}", path.display()))?;
        file.sync_data()
            .map_err(|e| format!("Failed to sync '{}': {e}", path.display()))?;
        self.appended += 1;
        Ok(())
    }

    /// Drop expired entries and rewrite the log without them. The log as it
    /// stands is still correct if the rewrite fails, so that only warns.
    fn sweep(&mut self) {
        let now = now_unix();
        self.map.retain(|_, expires_at| *expires_at > now);
        if let Err(e) = self.compact() {
            tracing::warn!("{e}");
        }
    }

    /// Rewrite the log with only the live entries (temp file + rename).
    fn compact(&mut self) -> Result<(), String> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        let mut out = String::new();
        for (key, expires_at_unix) in &self.map {
            let line = serde_json::to_string(&Record {
                v: STORE_VERSION,
                request_id: key.clone(),
                expires_at_unix: Some(*expires_at_unix),
                removed: false,
            })
            .map_err(|e| format!("Serialize error: {e}"))?;
            out.push_str(&line);
            out.push('\n');
        }
        let tmp = path.with_extension("tmp");
        let write = || -> std::io::Result<()> {
            let mut file = std::fs::File::create(&tmp)?;
            file.write_all(out.as_bytes())?;
            file.sync_all()
        };
        write().map_err(|e| format!("Failed to write '{}': {e}", tmp.display()))?;
        std::fs::rename(&tmp, path).map_err(|e| format!("Failed to replace '{}': {e}", path.display()))?;
        self.appended = 0;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(name: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("remonce-store-{}-{}.jsonl", name, uuid::Uuid::new_v4()));
        p
    }

    fn far_future() -> i64 {
        now_unix() + 3600
    }

    #[test]
    fn insert_and_check() {
        let path = temp_path("basic");
        let store = ExpiringSet::load(path.clone()).unwrap();
        store.insert("abc", far_future()).unwrap();
        assert!(store.contains("abc"));
        assert!(!store.contains("def"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn entries_survive_reload() {
        let path = temp_path("reload");
        {
            let store = ExpiringSet::load(path.clone()).unwrap();
            store.insert("abc", far_future()).unwrap();
        }
        let store = ExpiringSet::load(path.clone()).unwrap();
        assert!(store.contains("abc"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn expired_entries_dropped_on_load() {
        let path = temp_path("expired");
        {
            let store = ExpiringSet::load(path.clone()).unwrap();
            store.insert("old", now_unix() - 10).unwrap();
            store.insert("live", far_future()).unwrap();
        }
        let store = ExpiringSet::load(path.clone()).unwrap();
        assert!(!store.contains("old"));
        assert!(store.contains("live"));
        // Compaction removed the expired line from disk entirely.
        let contents = std::fs::read_to_string(&path).unwrap();
        assert!(!contents.contains("old"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn reinsert_keeps_later_expiry() {
        let path = temp_path("later");
        let store = ExpiringSet::load(path.clone()).unwrap();
        store.insert("abc", far_future()).unwrap();
        store.insert("abc", now_unix() - 10).unwrap();
        assert!(store.contains("abc"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn insert_new_refuses_a_live_entry_across_reload() {
        let path = temp_path("new");
        {
            let store = ExpiringSet::load(path.clone()).unwrap();
            assert!(store.insert_new("abc", far_future()).unwrap());
            assert!(!store.insert_new("abc", far_future()).unwrap());
        }
        let store = ExpiringSet::load(path.clone()).unwrap();
        assert!(!store.insert_new("abc", far_future()).unwrap());
        assert!(store.insert_new("def", far_future()).unwrap());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn insert_new_replaces_an_expired_entry() {
        let store = ExpiringSet::in_memory();
        assert!(store.insert_new("abc", now_unix() - 1).unwrap());
        assert!(store.insert_new("abc", far_future()).unwrap());
        assert!(store.contains("abc"));
    }

    #[test]
    fn removal_survives_reload() {
        let path = temp_path("removed");
        {
            let store = ExpiringSet::load(path.clone()).unwrap();
            store.insert("abc", far_future()).unwrap();
            store.insert("keep", far_future()).unwrap();
            store.remove("abc").unwrap();
            assert!(!store.contains("abc"));
        }
        let store = ExpiringSet::load(path.clone()).unwrap();
        assert!(!store.contains("abc"));
        assert!(store.contains("keep"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn sweep_rewrites_the_log_without_expired_entries() {
        let path = temp_path("sweep");
        let store = ExpiringSet::load(path.clone()).unwrap();
        store.insert("old", now_unix() - 10).unwrap();
        store.insert("live", far_future()).unwrap();
        store.insert("gone", far_future()).unwrap();
        store.remove("gone").unwrap();
        store.sweep_now();
        let contents = std::fs::read_to_string(&path).unwrap();
        assert_eq!(contents.lines().count(), 1, "{contents}");
        assert!(contents.contains("live"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn corrupt_middle_entry_is_rejected() {
        let path = temp_path("corrupt");
        let live = format!("{{\"v\":2,\"request_id\":\"abc\",\"expires_at_unix\":{}}}", far_future());
        std::fs::write(&path, format!("not json\n{live}\n")).unwrap();
        assert!(ExpiringSet::load(path.clone()).is_err());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn torn_final_entry_is_ignored() {
        // A crash mid-append must not stop the process from starting.
        let path = temp_path("torn");
        let live = format!("{{\"v\":2,\"request_id\":\"abc\",\"expires_at_unix\":{}}}", far_future());
        std::fs::write(&path, format!("{live}\n{{\"v\":2,\"request_id\":\"de")).unwrap();
        let store = ExpiringSet::load(path.clone()).unwrap();
        assert!(store.contains("abc"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn older_log_formats_refused() {
        // Both earlier formats: keyed on approver signature, then on
        // approver key binding.
        for old_key in ["sig", "key"] {
            let path = temp_path("oldformat");
            let old = format!("{{\"{old_key}\":\"abc\",\"expires_at_unix\":{}}}", far_future());
            let new = format!("{{\"v\":2,\"request_id\":\"def\",\"expires_at_unix\":{}}}", far_future());
            std::fs::write(&path, format!("{old}\n{new}\n")).unwrap();
            let err = ExpiringSet::load(path.clone()).err().unwrap();
            assert!(err.contains("older version"), "{err}");
            let _ = std::fs::remove_file(path);
        }
    }

    #[test]
    fn old_format_single_line_not_treated_as_torn() {
        // A one-line old log is also the "last line"; it must not be
        // silently dropped by the torn-write tolerance.
        let path = temp_path("oldsingle");
        let old = format!("{{\"key\":\"abc\",\"expires_at_unix\":{}}}", far_future());
        std::fs::write(&path, format!("{old}\n")).unwrap();
        assert!(ExpiringSet::load(path.clone()).is_err());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn failed_persist_is_not_remembered() {
        // Point the log at a directory so the append fails.
        let dir = temp_path("dir");
        std::fs::create_dir_all(&dir).unwrap();
        let store = ExpiringSet::failing(dir.clone());
        assert!(store.insert("abc", far_future()).is_err());
        assert!(!store.contains("abc"));
        assert!(store.insert_new("abc", far_future()).is_err());
        assert!(!store.contains("abc"));
        let _ = std::fs::remove_dir_all(dir);
    }
}
