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
use serde::Serialize;
use std::net::SocketAddr;
use std::path::PathBuf;

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

// --- Service --------------------------------------------------------------

#[derive(Clone)]
pub struct ServiceState {
    pub policy: std::sync::Arc<crate::policy::Policy>,
    pub config: Config,
    /// The IdP's token-signing keys, refreshed as it rotates them.
    pub idp_keys: crate::idp_keys::IdpKeys,
    pub hostname: String,
    pub trusted_roots: Vec<Vec<u8>>,
    pub store: crate::store::ExpiringSet,
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
    let (_, idp_keys) = crate::idp_keys::IdpKeys::discover(&http_client, &config.oidc.issuer_url).await?;

    let trusted_roots = crate::tsa::load_trust_anchors(
        config.timestamp_authority.ca_path.as_deref(),
        config.timestamp_authority.trust_system_store,
    );
    tracing::info!("Loaded {} trusted TSA roots", trusted_roots.len());

    let hostname = hostname::get()
        .map(|h| h.to_string_lossy().into_owned())
        .unwrap_or_else(|_| "unknown".to_string());

    let store = crate::store::ExpiringSet::load(PathBuf::from(&svc_config.persist_path))
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
        idp_keys,
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

    let keys = state.idp_keys.for_tokens(req.id_tokens()).await;
    let ctx = RevocationCtx {
        config: &state.config,
        jwks: &keys,
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
        .insert(&revocation.request_id, verified.keep_until.unix_timestamp())
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
        revoked: state.store.contains(&request_id),
    }))
}
