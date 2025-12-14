use serde::Serialize;
use time::OffsetDateTime;

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
    pub user: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signed_at: Option<String>,
    pub source_ip: String,
    pub agent_host: String,
    pub decision: &'static str,
    pub reason: String,
}

pub fn log_audit(
    decision: &'static str,
    reason: String,
    user: String,
    source_ip: String,
    agent_host: String,
    signed_at: Option<String>,
    command: Option<serde_json::Value>,
    file: Option<serde_json::Value>,
) {
    let now = OffsetDateTime::now_utc();
    let timestamp = now
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "unknown_time".to_string());

    let event_type = if command.is_some() {
        "command_execution"
    } else if file.is_some() {
        "file_access"
    } else {
        "unknown"
    };

    let audit = AuditLog {
        timestamp,
        level: "INFO",
        target: "audit",
        event_type,
        command,
        file,
        user,
        signed_at,
        source_ip,
        agent_host,
        decision,
        reason,
    };

    if let Ok(json) = serde_json::to_string(&audit) {
        println!("{}", json);
    } else {
        tracing::error!("Failed to serialize audit log");
    }
}
