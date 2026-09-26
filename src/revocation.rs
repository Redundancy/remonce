//! Revocation verification shared by the agent and the central revocation
//! service, plus the service itself (`remonce revocation-service`).
//!
//! The service is a small TLS server holding a persistent (JSONL append-log)
//! set of revoked approver signatures. Agents configured with
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
    pub http_client: &'a reqwest::Client,
    pub hostname: &'a str,
    /// Lower bound on the approver validity used for verification and for
    /// how long the revocation is kept. The central service sets this to its
    /// retention period: agents may allow longer approver validity than the
    /// service's own `[[commands]]` say, and a revocation must not lapse
    /// while any agent would still accept the bundle.
    pub min_approver_validity: Option<std::time::Duration>,
    /// Accept revocations for commands missing from this process's config
    /// (verified with default windows, third parties judged by the default
    /// OPA rule). The central service serves agents whose command sets it
    /// may not mirror; an agent only needs its own commands.
    pub allow_unknown_commands: bool,
}

/// Default OPA rule for revocations of commands this process doesn't know.
const DEFAULT_OPA_RULE: &str = "data.remonce.authz.decision";

pub struct VerifiedRevocation {
    pub authorized: crate::security::AuthorizedRevocation,
    pub approver_max_validity: std::time::Duration,
}

/// Verify a revocation bundle and authorize the revoker: self-revocation
/// (same OIDC `sub`) is always allowed, anyone else needs an OPA decision
/// for `action = "revoke"`. Audit-logs every denial; the caller logs the
/// success path. The returned error string is safe to show the client.
pub async fn verify_and_authorize(
    ctx: &RevocationCtx<'_>,
    req: &crate::security::RevocationBundle,
    ip: &str,
) -> Result<VerifiedRevocation, &'static str> {
    use crate::audit::AuditContext;

    let command_json = req.approver.command.clone();
    let audit_ctx = || AuditContext {
        event_type: Some("approval_revocation"),
        command: Some(command_json.clone()),
        ..Default::default()
    };

    // Resolve the command config: it supplies the validity windows and the
    // OPA rule governing third-party revocation.
    let command_name = match command_json.get("command").and_then(|v| v.as_str()) {
        Some(s) => s.to_string(),
        None => {
            crate::audit::log_audit(
                "deny",
                "Revocation rejected: missing 'command' field".into(),
                "unauthenticated".into(),
                ip.to_string(),
                ctx.hostname.to_string(),
                audit_ctx(),
            );
            return Err("Invalid Request");
        }
    };

    let (approver_max, operator_max, opa_rule) =
        match ctx.config.commands.iter().find(|c| c.name == command_name) {
            Some(c) => (
                c.approver_max_validity_or_default(),
                c.operator_max_validity_or_default(),
                c.opa_rule.clone(),
            ),
            None if ctx.allow_unknown_commands => (
                crate::config::DEFAULT_APPROVER_MAX_VALIDITY,
                crate::config::DEFAULT_OPERATOR_MAX_VALIDITY,
                DEFAULT_OPA_RULE.to_string(),
            ),
            None => {
                crate::audit::log_audit(
                    "deny",
                    format!("Revocation rejected: command '{}' not configured", command_name),
                    "unauthenticated".into(),
                    ip.to_string(),
                    ctx.hostname.to_string(),
                    audit_ctx(),
                );
                return Err("Invalid Request");
            }
        };
    let approver_max = approver_max.max(ctx.min_approver_validity.unwrap_or_default());

    // Approver bundles and revoker attestations are both signing-client
    // tokens; viewer tokens have no place here.
    let verifier_config = crate::security::VerifierConfig {
        client_id: ctx.config.oidc.client_id.clone(),
        issuer_url: ctx.config.oidc.issuer_url.clone(),
        jwks: ctx.jwks.clone(),
        trusted_roots: ctx.trusted_roots.to_vec(),
        approver_max_validity: approver_max,
        operator_max_validity: operator_max,
    };

    let revocation = match crate::security::verify_revocation(req, &verifier_config) {
        Ok(r) => r,
        Err(e) => {
            crate::audit::log_audit(
                "deny",
                format!("Revocation verification failed: {}", e),
                "unauthenticated".into(),
                ip.to_string(),
                ctx.hostname.to_string(),
                audit_ctx(),
            );
            return Err("Verification Failed");
        }
    };

    let revoker_user = revocation.revoker.username.clone();
    let approver_user = revocation.approver.username.clone();

    let revoke_ctx = || AuditContext {
        event_type: Some("approval_revocation"),
        command: Some(command_json.clone()),
        operator_user: Some(approver_user.clone()),
        ..Default::default()
    };

    // Authorization: self-revocation is always allowed; anyone else needs an
    // explicit OPA decision for action = "revoke".
    if !revocation.self_revoked {
        let opa_input = crate::opa::OpaInput {
            action: "revoke".into(),
            command: command_json.clone(),
            approver: crate::opa::SignerContext {
                username: approver_user.clone(),
                claims: revocation.approver.claims.clone(),
                signed_at: revocation
                    .approver
                    .signed_at
                    .format(&time::format_description::well_known::Rfc3339)
                    .unwrap_or_else(|_| "unknown_time".to_string()),
            },
            operator: crate::opa::SignerContext {
                username: revoker_user.clone(),
                claims: revocation.revoker.claims.clone(),
                signed_at: revocation
                    .revoker
                    .signed_at
                    .format(&time::format_description::well_known::Rfc3339)
                    .unwrap_or_else(|_| "unknown_time".to_string()),
            },
            self_executed: false,
            host: ctx.hostname.to_string(),
        };

        let decision = match crate::opa::check_authorization(
            ctx.http_client,
            &ctx.config.opa_url,
            &opa_rule,
            opa_input,
        )
        .await
        {
            Ok(d) => d,
            Err(e) => {
                crate::audit::log_audit(
                    "error",
                    format!("OPA evaluation failed during revocation: {}", e),
                    revoker_user.clone(),
                    ip.to_string(),
                    ctx.hostname.to_string(),
                    revoke_ctx(),
                );
                return Err("Internal Error");
            }
        };

        if !decision.allow {
            crate::audit::log_audit(
                "deny",
                format!("Third-party revocation denied: {}", decision.reason),
                revoker_user.clone(),
                ip.to_string(),
                ctx.hostname.to_string(),
                revoke_ctx(),
            );
            return Err("Authorization Denied");
        }
    }

    Ok(VerifiedRevocation {
        authorized: revocation,
        approver_max_validity: approver_max,
    })
}

// --- Persistent store -----------------------------------------------------

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredRevocation {
    /// The revoked approval's key binding (`hex(SHA256(approver pubkey))`).
    key: String,
    expires_at_unix: i64,
}

/// Revoked approvals (by approver key binding) backed by a JSONL append log,
/// so the set survives service restarts. Expired entries are dropped (and
/// the file compacted) on load.
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
                // Logs from before key-binding revocation keyed on signature
                // hex, which no longer matches anything. Refuse rather than
                // silently dropping them — even as the last line, where the
                // torn-write tolerance below would otherwise swallow it.
                if let Ok(serde_json::Value::Object(obj)) =
                    serde_json::from_str::<serde_json::Value>(line)
                    && obj.contains_key("sig")
                {
                    return Err(format!(
                        "'{}' is a pre-key-binding revocation log (line {}); archive it \
                         and start a fresh one (see the upgrade notes in CONFIGURATION.md)",
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
                let slot = map.entry(entry.key).or_insert(entry.expires_at_unix);
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
                key: key.clone(),
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
            key: key.to_string(),
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
    pub http_client: reqwest::Client,
    pub config: Config,
    pub jwks: jsonwebtoken::jwk::JwkSet,
    pub hostname: String,
    pub trusted_roots: Vec<Vec<u8>>,
    pub store: PersistentRevocationStore,
    pub retention: std::time::Duration,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
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
    let config_str = std::fs::read_to_string("config.toml")?;
    let config: Config = toml::from_str(&config_str)?;

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

    let state = ServiceState {
        http_client,
        config,
        jwks,
        hostname,
        trusted_roots,
        store,
        retention: svc_config.retention_or_default(),
    };

    let app = Router::new()
        .route("/revoke", post(revoke_handler))
        .route("/revoked/{key}", get(revoked_handler))
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
        http_client: &state.http_client,
        hostname: &state.hostname,
        min_approver_validity: Some(state.retention),
        allow_unknown_commands: true,
    };

    let verified = verify_and_authorize(&ctx, &req, &ip)
        .await
        .map_err(|e| ErrorResponse { error: e.into() })?;
    let revocation = &verified.authorized;

    let expiry = revocation
        .approver
        .usable_until(verified.approver_max_validity);
    if expiry > time::OffsetDateTime::now_utc() {
        state
            .store
            .revoke(&revocation.approver_key_binding, expiry.unix_timestamp())
            .map_err(|e| {
                crate::audit::log_audit(
                    "error",
                    format!("Failed to persist revocation: {}", e),
                    revocation.revoker.username.clone(),
                    ip.clone(),
                    state.hostname.clone(),
                    crate::audit::AuditContext {
                        event_type: Some("approval_revocation"),
                        command: Some(req.approver.command.clone()),
                        ..Default::default()
                    },
                );
                ErrorResponse {
                    error: "Internal Error".into(),
                }
            })?;
    }

    crate::audit::log_audit(
        "allow",
        format!(
            "Approval by '{}' revoked by '{}'{}",
            revocation.approver.username,
            revocation.revoker.username,
            if revocation.self_revoked { " (self)" } else { "" }
        ),
        revocation.revoker.username.clone(),
        ip,
        state.hostname.clone(),
        crate::audit::AuditContext {
            event_type: Some("approval_revocation"),
            command: Some(req.approver.command.clone()),
            operator_user: Some(revocation.approver.username.clone()),
            ..Default::default()
        },
    );

    Ok(Json(crate::agent::RevocationResponse {
        status: "revoked".to_string(),
        message: "Approval revoked on revocation service".to_string(),
    }))
}

async fn revoked_handler(
    State(state): State<ServiceState>,
    Path(key): Path<String>,
) -> Result<Json<RevokedStatus>, (axum::http::StatusCode, &'static str)> {
    // A key binding is a lowercase hex SHA-256. Rejecting anything else
    // keeps a malformed query from ever reading as "not revoked".
    if key.len() != 64 || !key.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return Err((axum::http::StatusCode::BAD_REQUEST, "Invalid key binding"));
    }
    Ok(Json(RevokedStatus {
        revoked: state.store.is_revoked(&key),
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
            "{{\"key\":\"abc\",\"expires_at_unix\":{}}}",
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
            "{{\"key\":\"abc\",\"expires_at_unix\":{}}}",
            far_future()
        );
        std::fs::write(&path, format!("{live}\n{{\"key\":\"de")).unwrap();
        let store = PersistentRevocationStore::load(path.clone()).unwrap();
        assert!(store.is_revoked("abc"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn old_format_log_refused() {
        let path = temp_path("oldformat");
        let old = format!("{{\"sig\":\"abc\",\"expires_at_unix\":{}}}", far_future());
        let new = format!("{{\"key\":\"def\",\"expires_at_unix\":{}}}", far_future());
        std::fs::write(&path, format!("{old}\n{new}\n")).unwrap();
        let err = PersistentRevocationStore::load(path.clone()).err().unwrap();
        assert!(err.contains("pre-key-binding"), "{err}");
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn old_format_single_line_not_treated_as_torn() {
        // A one-line old log is also the "last line"; it must not be
        // silently dropped by the torn-write tolerance.
        let path = temp_path("oldsingle");
        let old = format!("{{\"sig\":\"abc\",\"expires_at_unix\":{}}}", far_future());
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
