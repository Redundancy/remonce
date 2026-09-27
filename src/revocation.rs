//! Revocation verification shared by the agent and the central revocation
//! service, plus the service itself (`remonce revocation-service`).
//!
//! The service is a small TLS server holding a persistent (JSONL append-log)
//! set of revoked requests, by request id. Agents configured with
//! `[agent] revocation_service_url` consult it before every execution and
//! fail closed if it is unreachable.

use axum::{
    Router,
    extract::{ConnectInfo, Json, Path, State},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::Write as _;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use crate::config::Config;

// --- Shared verification -------------------------------------------------

pub struct RevocationCtx<'a> {
    pub config: &'a Config,
    pub jwks: &'a jsonwebtoken::jwk::JwkSet,
    pub trusted_roots: &'a [Vec<u8>],
    pub policy: &'a crate::policy::Policy,
    pub hostname: &'a str,
    /// Minimum time to keep a revocation. The central service sets this to
    /// its retention period: agents may allow longer approval validity than
    /// the service's own `[[commands]]` say, and a revocation must not lapse
    /// while any agent would still accept the request.
    pub retention: Option<std::time::Duration>,
    /// Accept revocations for commands missing from this process's config
    /// (default validity, third parties judged by the default OPA rule). The
    /// central service serves agents whose command sets it may not mirror;
    /// an agent only needs its own commands.
    pub allow_unknown_commands: bool,
}

/// Default OPA rule for revocations of commands this process doesn't know.
const DEFAULT_OPA_RULE: &str = "data.remonce.authz.decision";

pub struct VerifiedRevocation {
    pub authorized: crate::security::AuthorizedRevocation,
    /// Until when to keep the revocation.
    pub keep_until: time::OffsetDateTime,
}

/// Verify a revocation and authorize the revoker: any of the request's
/// approvers may revoke it; anyone else needs an OPA decision for
/// `action = "revoke"`. Audit-logs every denial; the caller logs success.
/// The returned error string is safe to show the client.
pub async fn verify_and_authorize(
    ctx: &RevocationCtx<'_>,
    req: &crate::security::RevocationBundle,
    ip: &str,
) -> Result<VerifiedRevocation, &'static str> {
    use crate::audit::{AuditContext, AuditSigner};

    let command_json = req.request.command.clone();
    let audit_ctx = || AuditContext {
        event_type: Some("request_revocation"),
        command: Some(command_json.clone()),
        ..Default::default()
    };
    let deny = |reason: String, user: &str, ctx_: AuditContext| {
        crate::audit::log_audit("deny", reason, user.to_string(), ip.to_string(), ctx.hostname.to_string(), ctx_);
    };

    let Some(command_name) = command_json.get("command").and_then(|v| v.as_str()) else {
        deny("Revocation rejected: missing 'command' field".into(), "unauthenticated", audit_ctx());
        return Err("Invalid Request");
    };

    // The command's config supplies the approval validity (for retention)
    // and the OPA rule governing third-party revocation.
    let (validity, opa_rule) = match ctx.config.commands.iter().find(|c| c.name == command_name) {
        Some(c) => (c.approval_validity_or_default(), c.opa_rule.clone()),
        None if ctx.allow_unknown_commands => (
            crate::config::DEFAULT_APPROVAL_VALIDITY,
            DEFAULT_OPA_RULE.to_string(),
        ),
        None => {
            deny(
                format!("Revocation rejected: command '{command_name}' not configured"),
                "unauthenticated",
                audit_ctx(),
            );
            return Err("Invalid Request");
        }
    };

    // Approvals and revoker attestations are both signing-client tokens;
    // viewer tokens have no place here.
    let verifier_config = crate::security::VerifierConfig {
        client_id: ctx.config.oidc.signing_client_id.clone(),
        issuer_url: ctx.config.oidc.issuer_url.clone(),
        jwks: ctx.jwks.clone(),
        trusted_roots: ctx.trusted_roots.to_vec(),
        approval_validity: validity,
    };
    let now = time::OffsetDateTime::now_utc();
    let revocation = match crate::security::verify_revocation(req, &verifier_config, now) {
        Ok(r) => r,
        Err(e) => {
            deny(format!("Revocation verification failed: {e}"), "unauthenticated", audit_ctx());
            return Err("Verification Failed");
        }
    };

    let signed_at = |t: time::OffsetDateTime| {
        t.format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_else(|_| "unknown_time".to_string())
    };
    let revoker_user = revocation.revoker.username.clone();
    let revoke_ctx = || AuditContext {
        event_type: Some("request_revocation"),
        command: Some(command_json.clone()),
        request_id: Some(revocation.request_id.clone()),
        approvers: Some(
            revocation
                .approvers
                .iter()
                .map(|a| AuditSigner {
                    username: a.username.clone(),
                    sub: a.subject().to_string(),
                    signed_at: signed_at(a.signed_at),
                })
                .collect(),
        ),
        ..Default::default()
    };

    // Approvers may always cancel their own request; anyone else needs an
    // explicit OPA decision for action = "revoke".
    if !revocation.self_revoked {
        let input = crate::policy::RequestInput::Revoke {
            command: command_json.clone(),
            request_id: revocation.request_id.clone(),
            approvers: revocation
                .approvers
                .iter()
                .map(|a| crate::policy::Signer {
                    username: a.username.clone(),
                    claims: a.claims.clone(),
                    signed_at: signed_at(a.signed_at),
                })
                .collect(),
            revoker: crate::policy::Signer {
                username: revoker_user.clone(),
                claims: revocation.revoker.claims.clone(),
                signed_at: signed_at(revocation.revoker.signed_at),
            },
            host: ctx.hostname.to_string(),
        };
        let decision = match ctx.policy.decide(&opa_rule, &input).await {
            Ok(d) => d,
            Err(e) => {
                crate::audit::log_audit(
                    "error",
                    format!("Policy evaluation failed during revocation: {e}"),
                    revoker_user.clone(),
                    ip.to_string(),
                    ctx.hostname.to_string(),
                    revoke_ctx(),
                );
                return Err("Internal Error");
            }
        };
        if !decision.allow {
            deny(
                format!("Third-party revocation denied: {}", decision.reason),
                &revoker_user,
                revoke_ctx(),
            );
            return Err("Authorization Denied");
        }
    }

    let keep_until = crate::security::revocation_keep_until(
        now,
        &revocation.approvers,
        validity,
        ctx.retention.unwrap_or(validity),
    );
    Ok(VerifiedRevocation {
        authorized: revocation,
        keep_until,
    })
}

// --- Persistent store -----------------------------------------------------

/// Version tag on every stored line.
const STORE_VERSION: u32 = 2;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredRevocation {
    v: u32,
    /// The revoked request's id (hex SHA-256 of the signed request).
    request_id: String,
    expires_at_unix: i64,
}

/// Revoked requests (by request id) backed by a JSONL append log, so the
/// set survives service restarts. Expired entries are dropped (and the file
/// compacted) on load.
#[derive(Clone)]
pub struct PersistentRevocationStore {
    inner: Arc<Mutex<StoreInner>>,
}

struct StoreInner {
    map: HashMap<String, i64>,
    path: PathBuf,
}

impl PersistentRevocationStore {
    pub fn load(path: PathBuf) -> Result<Self, String> {
        let mut map: HashMap<String, i64> = HashMap::new();
        let now = time::OffsetDateTime::now_utc().unix_timestamp();

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
                        "'{}' is a revocation log from an older version of Remonce (line {}); \
                         archive it and start a fresh one (see the upgrade notes in CONFIGURATION.md)",
                        path.display(),
                        idx + 1
                    ));
                }
                let entry: StoredRevocation = match serde_json::from_str(line) {
                    Ok(e) => e,
                    // A crash mid-append leaves a torn final line. Refusing
                    // to start would halt every agent (they fail closed), and
                    // the torn write was never acknowledged to a client.
                    Err(e) if idx == lines.len() - 1 => {
                        tracing::warn!(
                            "Ignoring torn final entry in '{}': {e}",
                            path.display()
                        );
                        continue;
                    }
                    Err(e) => {
                        return Err(format!(
                            "Corrupt revocation entry in '{}' (line {}): {e}",
                            path.display(),
                            idx + 1
                        ));
                    }
                };
                if entry.expires_at_unix <= now {
                    continue;
                }
                let slot = map.entry(entry.request_id).or_insert(entry.expires_at_unix);
                if *slot < entry.expires_at_unix {
                    *slot = entry.expires_at_unix;
                }
            }
        }

        let store = Self {
            inner: Arc::new(Mutex::new(StoreInner { map, path })),
        };
        store.compact()?;
        Ok(store)
    }

    /// Rewrite the log with only the live entries (atomic via temp + rename).
    fn compact(&self) -> Result<(), String> {
        let inner = self.inner.lock().expect("revocation store lock poisoned");
        let mut out = String::new();
        for (key, expires_at_unix) in &inner.map {
            let line = serde_json::to_string(&StoredRevocation {
                v: STORE_VERSION,
                request_id: key.clone(),
                expires_at_unix: *expires_at_unix,
            })
            .map_err(|e| format!("Serialize error: {e}"))?;
            out.push_str(&line);
            out.push('\n');
        }
        let tmp = inner.path.with_extension("tmp");
        std::fs::write(&tmp, out).map_err(|e| format!("Failed to write '{}': {e}", tmp.display()))?;
        std::fs::rename(&tmp, &inner.path)
            .map_err(|e| format!("Failed to replace '{}': {e}", inner.path.display()))?;
        Ok(())
    }

    /// Record `key` as revoked until `expires_at_unix`, appending to the
    /// log. Idempotent; keeps the later expiry if revoked twice.
    pub fn revoke(&self, key: &str, expires_at_unix: i64) -> Result<(), String> {
        let mut inner = self.inner.lock().expect("revocation store lock poisoned");
        match inner.map.get(key) {
            Some(existing) if *existing >= expires_at_unix => return Ok(()),
            _ => {}
        }

        // Durable first, then visible: if the append fails, the in-memory map
        // must not claim the revocation exists (a retry would short-circuit
        // above and the revocation would vanish on restart).
        let line = serde_json::to_string(&StoredRevocation {
            v: STORE_VERSION,
            request_id: key.to_string(),
            expires_at_unix,
        })
        .map_err(|e| format!("Serialize error: {e}"))?;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&inner.path)
            .map_err(|e| format!("Failed to open '{}': {e}", inner.path.display()))?;
        writeln!(file, "{line}").map_err(|e| format!("Failed to append revocation: {e}"))?;
        file.sync_data()
            .map_err(|e| format!("Failed to sync revocation log: {e}"))?;
        inner.map.insert(key.to_string(), expires_at_unix);
        Ok(())
    }

    pub fn is_revoked(&self, key: &str) -> bool {
        let inner = self.inner.lock().expect("revocation store lock poisoned");
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        inner
            .map
            .get(key)
            .map(|expires_at| *expires_at > now)
            .unwrap_or(false)
    }
}

// --- Service --------------------------------------------------------------

#[derive(Clone)]
pub struct ServiceState {
    pub policy: std::sync::Arc<crate::policy::Policy>,
    pub config: Config,
    pub jwks: jsonwebtoken::jwk::JwkSet,
    pub hostname: String,
    pub trusted_roots: Vec<Vec<u8>>,
    pub store: PersistentRevocationStore,
    pub retention: std::time::Duration,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: &'static str,
}

impl IntoResponse for ErrorResponse {
    fn into_response(self) -> Response {
        (axum::http::StatusCode::BAD_REQUEST, Json(self)).into_response()
    }
}

#[derive(Serialize)]
pub struct RevokedStatus {
    pub revoked: bool,
}

pub async fn run(insecure: bool) -> Result<(), Box<dyn std::error::Error>> {
    let config: Config = crate::config::load("config.toml")?;

    let insecure_mode = crate::insecure::validate(&config, insecure)
        .map_err(|e| -> Box<dyn std::error::Error> { e.to_string().into() })?;
    crate::audit::set_insecure_mode(insecure_mode.as_bool());

    let svc_config = config.revocation_service.clone().ok_or(
        "Missing [revocation_service] section in config.toml — the revocation service requires a `[revocation_service]` block with TLS configuration. See CONFIGURATION.md.",
    )?;

    let http_client = crate::http_client();

    // The service performs the same bundle verification as the agent, so it
    // needs the OIDC keys and TSA trust anchors too.
    let discovery_url = format!("{}/.well-known/openid-configuration", config.oidc.issuer_url);
    let discovery: crate::web::OidcMetadata =
        http_client.get(&discovery_url).send().await?.json().await?;
    let jwks = http_client
        .get(&discovery.jwks_uri)
        .send()
        .await?
        .json()
        .await?;

    let trusted_roots = crate::tsa::load_trust_anchors(
        config.timestamp_authority.ca_path.as_deref(),
        config.timestamp_authority.trust_system_store,
    );
    tracing::info!("Loaded {} trusted TSA roots", trusted_roots.len());

    let hostname = hostname::get()
        .map(|h| h.to_string_lossy().into_owned())
        .unwrap_or_else(|_| "unknown".to_string());

    let store = PersistentRevocationStore::load(PathBuf::from(&svc_config.persist_path))
        .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;

    tracing::info!(
        event = "revocation_service_startup",
        hostname = %hostname,
        persist_path = %svc_config.persist_path,
        "Revocation service starting up"
    );

    let policy = std::sync::Arc::new(crate::policy::Policy::from_config(&config)?);
    tracing::info!(backend = %policy.describe(), "Policy ready");
    let state = ServiceState {
        policy,
        config,
        jwks,
        hostname,
        trusted_roots,
        store,
        retention: svc_config.retention_or_default(),
    };

    let app = Router::new()
        .route("/revoke", post(revoke_handler))
        .route("/v2/revoked/{request_id}", get(revoked_handler))
        .with_state(state);

    let addr: SocketAddr = svc_config
        .listen_address
        .parse()
        .map_err(|e| format!("Invalid revocation_service.listen_address: {e}"))?;
    tracing::info!(event = "tcp_listen", address = %addr, tls_mode = ?svc_config.tls, "Revocation service listening (TLS)");

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    crate::tls::serve_with_tls(listener, app, &svc_config.tls)
        .await
        .map_err(|e| -> Box<dyn std::error::Error> { e.to_string().into() })?;

    Ok(())
}

async fn revoke_handler(
    State(state): State<ServiceState>,
    ConnectInfo(addr): ConnectInfo<crate::tls::PeerAddr>,
    Json(req): Json<crate::security::RevocationBundle>,
) -> Result<Json<crate::agent::RevocationResponse>, ErrorResponse> {
    let ip = addr.ip_string();

    let ctx = RevocationCtx {
        config: &state.config,
        jwks: &state.jwks,
        trusted_roots: &state.trusted_roots,
        policy: &state.policy,
        hostname: &state.hostname,
        retention: Some(state.retention),
        allow_unknown_commands: true,
    };
    let verified = verify_and_authorize(&ctx, &req, &ip)
        .await
        .map_err(|error| ErrorResponse { error })?;
    let revocation = &verified.authorized;
    let audit_ctx = || crate::audit::AuditContext {
        event_type: Some("request_revocation"),
        command: Some(req.request.command.clone()),
        request_id: Some(revocation.request_id.clone()),
        ..Default::default()
    };

    state
        .store
        .revoke(&revocation.request_id, verified.keep_until.unix_timestamp())
        .map_err(|e| {
            crate::audit::log_audit(
                "error",
                format!("Failed to persist revocation: {e}"),
                revocation.revoker.username.clone(),
                ip.clone(),
                state.hostname.clone(),
                audit_ctx(),
            );
            ErrorResponse { error: "Internal Error" }
        })?;

    crate::audit::log_audit(
        "allow",
        format!(
            "Request revoked by '{}'{}",
            revocation.revoker.username,
            if revocation.self_revoked { " (an approver)" } else { "" }
        ),
        revocation.revoker.username.clone(),
        ip,
        state.hostname.clone(),
        audit_ctx(),
    );

    Ok(Json(crate::agent::RevocationResponse {
        status: "revoked".to_string(),
        message: "Request revoked on the revocation service".to_string(),
    }))
}

async fn revoked_handler(
    State(state): State<ServiceState>,
    Path(request_id): Path<String>,
) -> Result<Json<RevokedStatus>, (axum::http::StatusCode, &'static str)> {
    // A request id is a lowercase hex SHA-256. Rejecting anything else
    // keeps a malformed query from ever reading as "not revoked".
    if request_id.len() != 64 || !request_id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return Err((axum::http::StatusCode::BAD_REQUEST, "Invalid request id"));
    }
    Ok(Json(RevokedStatus {
        revoked: state.store.is_revoked(&request_id),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(name: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("remonce-revstore-{}-{}.jsonl", name, uuid::Uuid::new_v4()));
        p
    }

    fn far_future() -> i64 {
        time::OffsetDateTime::now_utc().unix_timestamp() + 3600
    }

    #[test]
    fn revoke_and_check() {
        let path = temp_path("basic");
        let store = PersistentRevocationStore::load(path.clone()).unwrap();
        store.revoke("abc", far_future()).unwrap();
        assert!(store.is_revoked("abc"));
        assert!(!store.is_revoked("def"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn revocations_survive_reload() {
        let path = temp_path("reload");
        {
            let store = PersistentRevocationStore::load(path.clone()).unwrap();
            store.revoke("abc", far_future()).unwrap();
        }
        let store = PersistentRevocationStore::load(path.clone()).unwrap();
        assert!(store.is_revoked("abc"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn expired_entries_dropped_on_load() {
        let path = temp_path("expired");
        let past = time::OffsetDateTime::now_utc().unix_timestamp() - 10;
        {
            let store = PersistentRevocationStore::load(path.clone()).unwrap();
            store.revoke("old", past).unwrap();
            store.revoke("live", far_future()).unwrap();
        }
        let store = PersistentRevocationStore::load(path.clone()).unwrap();
        assert!(!store.is_revoked("old"));
        assert!(store.is_revoked("live"));
        // Compaction removed the expired line from disk entirely.
        let contents = std::fs::read_to_string(&path).unwrap();
        assert!(!contents.contains("old"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn re_revoke_keeps_later_expiry() {
        let path = temp_path("later");
        let store = PersistentRevocationStore::load(path.clone()).unwrap();
        store.revoke("abc", far_future()).unwrap();
        store
            .revoke("abc", time::OffsetDateTime::now_utc().unix_timestamp() - 10)
            .unwrap();
        assert!(store.is_revoked("abc"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn corrupt_middle_entry_is_rejected() {
        let path = temp_path("corrupt");
        let live = format!(
            "{{\"v\":2,\"request_id\":\"abc\",\"expires_at_unix\":{}}}",
            far_future()
        );
        std::fs::write(&path, format!("not json\n{live}\n")).unwrap();
        assert!(PersistentRevocationStore::load(path.clone()).is_err());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn torn_final_entry_is_ignored() {
        // A crash mid-append must not stop the service from starting.
        let path = temp_path("torn");
        let live = format!(
            "{{\"v\":2,\"request_id\":\"abc\",\"expires_at_unix\":{}}}",
            far_future()
        );
        std::fs::write(&path, format!("{live}\n{{\"v\":2,\"request_id\":\"de")).unwrap();
        let store = PersistentRevocationStore::load(path.clone()).unwrap();
        assert!(store.is_revoked("abc"));
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
            let err = PersistentRevocationStore::load(path.clone()).err().unwrap();
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
        assert!(PersistentRevocationStore::load(path.clone()).is_err());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn failed_persist_is_not_remembered() {
        // Point the log at a directory so the append fails.
        let dir = temp_path("dir");
        std::fs::create_dir_all(&dir).unwrap();
        let store = PersistentRevocationStore {
            inner: Arc::new(Mutex::new(StoreInner {
                map: HashMap::new(),
                path: dir.clone(),
            })),
        };
        assert!(store.revoke("abc", far_future()).is_err());
        assert!(!store.is_revoked("abc"));
        let _ = std::fs::remove_dir_all(dir);
    }
}
