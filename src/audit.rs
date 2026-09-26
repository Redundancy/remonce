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
    /// The approver (authorizing identity). For file access / unauthenticated
    /// rejections this is just the caller identity.
    pub user: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signed_at: Option<String>,
    /// The operator (executing identity). Equals `user` when self-executing.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operator_user: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operator_signed_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub self_executed: Option<bool>,
    pub source_ip: String,
    pub agent_host: String,
    pub decision: &'static str,
    pub reason: String,
    /// Set iff the agent is running with `--insecure`. Omitted otherwise so
    /// normal audit entries stay compact.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub insecure: Option<bool>,
}

#[derive(Default)]
pub struct AuditContext {
    pub signed_at: Option<String>,
    pub command: Option<serde_json::Value>,
    pub file: Option<serde_json::Value>,
    pub operator_user: Option<String>,
    pub operator_signed_at: Option<String>,
    pub self_executed: Option<bool>,
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
        signed_at: ctx.signed_at,
        operator_user: ctx.operator_user,
        operator_signed_at: ctx.operator_signed_at,
        self_executed: ctx.self_executed,
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
