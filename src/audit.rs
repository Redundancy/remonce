use serde::Serialize;
use std::io::Write as _;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};
use time::OffsetDateTime;

/// Process-wide flag indicating whether the current run is in `--insecure`
/// mode. When true, every audit log entry carries `insecure: true` so
/// post-incident review can identify runs that executed under a degraded
/// security posture. Set once at startup via `set_insecure_mode`.
static INSECURE_MODE: AtomicBool = AtomicBool::new(false);

pub fn set_insecure_mode(on: bool) {
    INSECURE_MODE.store(on, Ordering::Relaxed);
}

fn insecure_mode_flag() -> Option<bool> {
    if INSECURE_MODE.load(Ordering::Relaxed) {
        Some(true)
    } else {
        None
    }
}

/// Where audit records go besides stdout (`[agent] audit_log_path`).
static AUDIT_FILE: OnceLock<Mutex<std::fs::File>> = OnceLock::new();

/// Also append every audit record to `path`. Call once, at startup.
pub fn set_audit_file(path: &str) -> Result<(), String> {
    let file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| format!("Failed to open audit log '{path}': {e}"))?;
    AUDIT_FILE
        .set(Mutex::new(file))
        .map_err(|_| "The audit log file is already set".to_string())
}

/// How a run ended.
#[derive(Serialize, Clone, Debug)]
pub struct AuditOutcome {
    /// "exited", "timeout" (killed by the agent), "agent_shutdown" (killed
    /// because the agent was stopping) or "wait_error".
    pub result: &'static str,
    /// The process's exit code, when it exited with one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    /// From the process starting to it exiting or being killed.
    pub duration_ms: u64,
    /// Set when the output outgrew `max_output_bytes` and the run log holds
    /// only the start of it.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub output_truncated: bool,
}

#[derive(Serialize)]
pub struct AuditLog {
    pub timestamp: String,
    pub level: &'static str,
    pub target: &'static str,
    pub event_type: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<serde_json::Value>,
    /// Who acted: the executor for a run, the revoker for a revocation, the
    /// viewer for file access; "unauthenticated" before anyone is known.
    pub user: String,
    /// The request's id (hex SHA-256 of the signed request).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    /// The run's id, which names its log (`logs/<execution_id>.log`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub execution_id: Option<String>,
    /// How the run ended (`command_finished` records).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outcome: Option<AuditOutcome>,
    /// Everyone who approved the request, with their signing times.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approvers: Option<Vec<AuditSigner>>,
    pub source_ip: String,
    pub agent_host: String,
    pub decision: &'static str,
    pub reason: String,
    /// Set iff the agent is running with `--insecure`. Omitted otherwise so
    /// normal audit entries stay compact.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub insecure: Option<bool>,
}

#[derive(Serialize, Clone)]
pub struct AuditSigner {
    pub username: String,
    pub sub: String,
    pub signed_at: String,
}

#[derive(Default, Clone)]
pub struct AuditContext {
    pub command: Option<serde_json::Value>,
    pub file: Option<serde_json::Value>,
    pub request_id: Option<String>,
    pub execution_id: Option<String>,
    pub outcome: Option<AuditOutcome>,
    pub approvers: Option<Vec<AuditSigner>>,
    /// Overrides the event type inferred from which fields are set.
    pub event_type: Option<&'static str>,
}

pub fn log_audit(
    decision: &'static str,
    reason: String,
    user: String,
    source_ip: String,
    agent_host: String,
    ctx: AuditContext,
) {
    let now = OffsetDateTime::now_utc();
    let timestamp = now
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "unknown_time".to_string());

    let event_type = if let Some(t) = ctx.event_type {
        t
    } else if ctx.command.is_some() {
        "command_execution"
    } else if ctx.file.is_some() {
        "file_access"
    } else {
        "unknown"
    };

    let audit = AuditLog {
        timestamp,
        level: "INFO",
        target: "audit",
        event_type,
        command: ctx.command,
        file: ctx.file,
        user,
        request_id: ctx.request_id,
        execution_id: ctx.execution_id,
        outcome: ctx.outcome,
        approvers: ctx.approvers,
        source_ip,
        agent_host,
        decision,
        reason,
        insecure: insecure_mode_flag(),
    };

    let Ok(json) = serde_json::to_string(&audit) else {
        tracing::error!("Failed to serialize audit log");
        return;
    };
    println!("{json}");
    if let Some(file) = AUDIT_FILE.get() {
        let mut file = file.lock().unwrap_or_else(|e| e.into_inner());
        if let Err(e) = writeln!(file, "{json}") {
            tracing::error!("Failed to write to the audit log file: {e}");
        }
    }
    #[cfg(test)]
    if let Ok(value) = serde_json::to_value(&audit) {
        test_capture::RECORDS.lock().unwrap_or_else(|e| e.into_inner()).push(value);
    }
}

/// Every audit record made in this test process, for tests to search.
#[cfg(test)]
pub(crate) mod test_capture {
    pub(super) static RECORDS: std::sync::Mutex<Vec<serde_json::Value>> = std::sync::Mutex::new(Vec::new());

    /// The records whose `field` equals `value`, oldest first.
    pub(crate) fn matching(field: &str, value: &str) -> Vec<serde_json::Value> {
        RECORDS
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .filter(|r| r.get(field).and_then(|v| v.as_str()) == Some(value))
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_are_appended_to_the_audit_file() {
        let path = std::env::temp_dir().join(format!("remonce-audit-{}.jsonl", uuid::Uuid::new_v4()));
        set_audit_file(&path.to_string_lossy()).expect("first call sets the file");
        assert!(set_audit_file(&path.to_string_lossy()).is_err(), "it is set once");

        let user = format!("auditor-{}", uuid::Uuid::new_v4());
        log_audit(
            "completed",
            "Command exited: exit code: 0".into(),
            user.clone(),
            "127.0.0.1".into(),
            "host".into(),
            AuditContext {
                event_type: Some("command_finished"),
                execution_id: Some("run-1".into()),
                outcome: Some(AuditOutcome {
                    result: "exited",
                    exit_code: Some(0),
                    duration_ms: 12,
                    output_truncated: false,
                }),
                ..Default::default()
            },
        );

        // Other tests in this process audit too; find ours among the lines.
        let text = std::fs::read_to_string(&path).unwrap();
        let ours: Vec<serde_json::Value> = text
            .lines()
            .map(|l| serde_json::from_str(l).expect("each line is one JSON record"))
            .filter(|r: &serde_json::Value| r["user"] == user.as_str())
            .collect();
        assert_eq!(ours.len(), 1, "{text}");
        assert_eq!(ours[0]["event_type"], "command_finished");
        assert_eq!(ours[0]["execution_id"], "run-1");
        assert_eq!(ours[0]["outcome"], serde_json::json!({ "result": "exited", "exit_code": 0, "duration_ms": 12 }));
        let _ = std::fs::remove_file(path);
    }
}
