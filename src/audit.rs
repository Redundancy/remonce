use serde::Serialize;
use std::sync::atomic::{AtomicBool, Ordering};
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

#[derive(Default)]
pub struct AuditContext {
    pub command: Option<serde_json::Value>,
    pub file: Option<serde_json::Value>,
    pub request_id: Option<String>,
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
        approvers: ctx.approvers,
        source_ip,
        agent_host,
        decision,
        reason,
        insecure: insecure_mode_flag(),
    };

    if let Ok(json) = serde_json::to_string(&audit) {
        println!("{}", json);
    } else {
        tracing::error!("Failed to serialize audit log");
    }
}
