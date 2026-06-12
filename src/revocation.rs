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
}

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

    let cmd_config = match ctx.config.commands.iter().find(|c| c.name == command_name) {
        Some(c) => c.clone(),
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

    let verifier_config = crate::security::VerifierConfig {
        client_id: ctx.config.oidc.client_id.clone(),
        issuer_url: ctx.config.oidc.issuer_url.clone(),
        jwks: ctx.jwks.clone(),
        trusted_roots: ctx.trusted_roots.to_vec(),
        approver_max_validity: cmd_config.approver_max_validity_or_default(),
        operator_max_validity: cmd_config.operator_max_validity_or_default(),
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
            &cmd_config.opa_rule,
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
        approver_max_validity: cmd_config.approver_max_validity_or_default(),
    })
}

// --- Persistent store -----------------------------------------------------

#[derive(Serialize, Deserialize)]
struct StoredRevocation {
    sig: String,
    expires_at_unix: i64,
}

/// Revoked approver-signature hashes backed by a JSONL append log, so the
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
            for line in contents.lines() {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                let entry: StoredRevocation = serde_json::from_str(line)
                    .map_err(|e| format!("Corrupt revocation entry in '{}': {e}", path.display()))?;
                if entry.expires_at_unix <= now {
                    continue;
                }
                let slot = map.entry(entry.sig).or_insert(entry.expires_at_unix);
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
        for (sig, expires_at_unix) in &inner.map {
            let line = serde_json::to_string(&StoredRevocation {
                sig: sig.clone(),
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

    /// Record `sig_hex` as revoked until `expires_at_unix`, appending to the
    /// log. Idempotent; keeps the later expiry if revoked twice.
    pub fn revoke(&self, sig_hex: &str, expires_at_unix: i64) -> Result<(), String> {
        let mut inner = self.inner.lock().expect("revocation store lock poisoned");
        match inner.map.get(sig_hex) {
            Some(existing) if *existing >= expires_at_unix => return Ok(()),
            _ => {}
        }
        inner.map.insert(sig_hex.to_string(), expires_at_unix);

        let line = serde_json::to_string(&StoredRevocation {
            sig: sig_hex.to_string(),
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
        Ok(())
    }

    pub fn is_revoked(&self, sig_hex: &str) -> bool {
        let inner = self.inner.lock().expect("revocation store lock poisoned");
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        inner
            .map
            .get(sig_hex)
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

    let http_client = reqwest::Client::new();

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
    };

    let app = Router::new()
        .route("/revoke", post(revoke_handler))
        .route("/revoked/{sig}", get(revoked_handler))
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
    };

    let verified = verify_and_authorize(&ctx, &req, &ip)
        .await
        .map_err(|e| ErrorResponse { error: e.into() })?;
    let revocation = &verified.authorized;

    let expiry = revocation.approver.signed_at + verified.approver_max_validity;
    if expiry > time::OffsetDateTime::now_utc() {
        state
            .store
            .revoke(&revocation.approver_signature_hex, expiry.unix_timestamp())
            .map_err(|e| {
                crate::audit::log_audit(
                    "error",
                    format!("Failed to persist revocation: {}", e),
                    revocation.revoker.username.clone(),
                    ip.clone(),
                    state.hostname.clone(),
                    crate::audit::AuditContext {
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
    Path(sig): Path<String>,
) -> Json<RevokedStatus> {
    Json(RevokedStatus {
        revoked: state.store.is_revoked(&sig),
    })
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
    fn corrupt_log_is_rejected() {
        let path = temp_path("corrupt");
        std::fs::write(&path, "not json\n").unwrap();
        assert!(PersistentRevocationStore::load(path.clone()).is_err());
        let _ = std::fs::remove_file(path);
    }
}
