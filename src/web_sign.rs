//! Per-signature signing in the local signer.
//!
//! Every approval, cosign and revocation gets its own OIDC login to the
//! *signing* client, with a fresh ephemeral key and forced re-authentication:
//!
//! 1. `POST /api/sign/begin` validates the request, generates the key, and
//!    parks the action in this session under a fresh OIDC `state`. It returns
//!    the IdP authorization URL; the browser navigates there.
//! 2. The IdP redirects back to `/oidc/callback`, which (seeing a pending
//!    `state`) exchanges the code, checks the login really re-authenticated,
//!    signs the *server-stored* payload, and drops the key. A revocation is
//!    submitted to the agent right there.
//! 3. The browser lands on a server-chosen page with `?sign_result=<id>` and
//!    fetches the result once from `GET /api/sign/result/{id}`.
//!
//! Pending state lives in the session, not global state: a callback that
//! completes someone else's flow lands in a session that never issued that
//! `state`, and the browser can't swap the payload during the redirect.

use crate::security::{
    ApproverBundle, ExecutionBundle, OperatorConstraint, OperatorCosign, RevocationBundle,
    RevokerAttestation,
};
use crate::web::{AppError, AppState, CallbackQuery, require_profile};
use axum::{
    extract::{Path, State},
    response::Redirect,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use tower_sessions::Session;

const PENDING_KEY: &str = "remonce.pending_signs";
const RESULTS_KEY: &str = "remonce.sign_results";
/// Concurrent signing flows per session; the oldest is dropped beyond this.
const MAX_PENDING: usize = 4;
/// How long a started signing flow or an unread result is kept.
const TTL_SECS: i64 = 10 * 60;

/// What the user asked to sign.
#[derive(Serialize, Deserialize, Clone)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum SignAction {
    /// Approve a command (self-execute, or delegated via `operator_requires`).
    Approve {
        command: serde_json::Value,
        #[serde(default)]
        operator_requires: Option<OperatorConstraint>,
    },
    /// Co-sign someone else's delegated approval as the operator.
    Cosign { approver: ApproverBundle },
    /// Revoke an approval on an agent.
    Revoke {
        approver: ApproverBundle,
        #[serde(default)]
        agent_url: Option<String>,
    },
}

impl SignAction {
    fn name(&self) -> &'static str {
        match self {
            SignAction::Approve { .. } => "approve",
            SignAction::Cosign { .. } => "cosign",
            SignAction::Revoke { .. } => "revoke",
        }
    }

    /// The page the browser returns to. Chosen by the server — never from
    /// the request — so the callback is not an open redirect.
    fn return_page(&self) -> &'static str {
        match self {
            SignAction::Approve { .. } | SignAction::Cosign { .. } => "/ui/review",
            SignAction::Revoke { .. } => "/ui/execute",
        }
    }
}

#[derive(Serialize, Deserialize)]
struct PendingSign {
    action: SignAction,
    /// Raw P-256 scalar. The local signer is loopback-only with an in-memory
    /// session store, and the key lives only for one redirect round trip.
    signing_key_hex: String,
    public_key_pem: String,
    pkce_verifier: String,
    started_at_unix: i64,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum SignOutcome {
    Bundle {
        bundle: Box<ExecutionBundle>,
        /// Who signed, from the verified ID token.
        signer: String,
        /// RFC 3339 time from the verified TSA timestamp.
        signed_at: String,
    },
    Revoked { status: u16, body: serde_json::Value },
    Error { message: String },
}

#[derive(Serialize, Deserialize)]
pub struct SignResult {
    action: String,
    #[serde(flatten)]
    outcome: SignOutcome,
    created_unix: i64,
}

fn now_unix() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}

async fn load_pending(session: &Session) -> Result<BTreeMap<String, PendingSign>, AppError> {
    let mut map: BTreeMap<String, PendingSign> =
        session.get(PENDING_KEY).await?.unwrap_or_default();
    let cutoff = now_unix() - TTL_SECS;
    map.retain(|_, p| p.started_at_unix > cutoff);
    Ok(map)
}

async fn load_results(session: &Session) -> Result<BTreeMap<String, SignResult>, AppError> {
    let mut map: BTreeMap<String, SignResult> =
        session.get(RESULTS_KEY).await?.unwrap_or_default();
    let cutoff = now_unix() - TTL_SECS;
    map.retain(|_, r| r.created_unix > cutoff);
    Ok(map)
}

#[derive(Serialize)]
pub struct BeginResponse {
    authorize_url: String,
}

/// POST /api/sign/begin — park a signing action and return the IdP URL for
/// its dedicated, re-authenticating login.
pub async fn begin_handler(
    State(state): State<AppState>,
    session: Session,
    headers: axum::http::HeaderMap,
    axum::Json(mut action): axum::Json<SignAction>,
) -> Result<axum::Json<BeginResponse>, AppError> {
    crate::agent_proxy::require_same_origin(&headers)?;
    require_profile(&session).await?;

    // Validate before sending the user through a login.
    match &mut action {
        SignAction::Approve { command, .. } => {
            if !command.is_object() {
                return Err(AppError::Forbidden("The command must be a JSON object".into()));
            }
        }
        SignAction::Cosign { approver } => {
            if approver.operator_requires.is_none() {
                return Err(AppError::Forbidden(
                    "This approval is self-execute only and cannot be co-signed; ask the \
                     approver for a delegated approval"
                        .into(),
                ));
            }
        }
        SignAction::Revoke { agent_url, .. } => {
            let resolved = crate::agent_proxy::resolve_agent_url(&state, agent_url.as_deref())?;
            *agent_url = Some(resolved.to_string());
        }
    }

    let ephemeral = crate::signing::new_ephemeral().map_err(AppError::Internal)?;
    let oidc_state = crate::oidc_client::random_token();
    let (pkce_challenge, pkce_verifier) = crate::oidc_client::pkce_pair();

    let mut pending = load_pending(&session).await?;
    while pending.len() >= MAX_PENDING {
        let oldest = pending
            .iter()
            .min_by_key(|(_, p)| p.started_at_unix)
            .map(|(k, _)| k.clone());
        match oldest {
            Some(k) => pending.remove(&k),
            None => break,
        };
    }
    pending.insert(
        oidc_state.clone(),
        PendingSign {
            action,
            signing_key_hex: crate::signing::key_to_hex(&ephemeral.key),
            public_key_pem: ephemeral.public_key_pem,
            pkce_verifier,
            started_at_unix: now_unix(),
        },
    );
    session.insert(PENDING_KEY, pending).await?;

    let url = crate::oidc_client::authorize_url(
        &state.oidc_metadata,
        &crate::oidc_client::AuthorizeParams {
            client_id: &state.config.oidc.client_id,
            redirect_uri: &state.config.get_redirect_uri(),
            state: &oidc_state,
            nonce: &ephemeral.nonce,
            pkce_challenge: &pkce_challenge,
            reauth: Some(crate::oidc_client::Reauth::from_config(&state.config.oidc)),
        },
    )
    .map_err(AppError::Internal)?;

    Ok(axum::Json(BeginResponse {
        authorize_url: url.to_string(),
    }))
}

/// Whether `state` names a signing flow this session started.
pub async fn is_pending(session: &Session, state: &str) -> Result<bool, AppError> {
    Ok(load_pending(session).await?.contains_key(state))
}

/// Complete a pending signing flow from the OIDC callback. Always ends in a
/// redirect to the action's page; failures are reported through the result.
pub(crate) async fn complete(
    state: &AppState,
    session: &Session,
    query: CallbackQuery,
) -> Result<Redirect, AppError> {
    // Single use: remove and persist before doing anything else, so the
    // `state` is spent even if a later step fails.
    let mut pending = load_pending(session).await?;
    let entry = pending
        .remove(&query.state)
        .ok_or_else(|| AppError::Auth("Unknown signing flow".into()))?;
    session.insert(PENDING_KEY, pending).await?;

    let action_name = entry.action.name().to_string();
    let page = entry.action.return_page();
    let outcome = match sign(state, &query, entry).await {
        Ok(outcome) => outcome,
        Err(message) => {
            tracing::warn!(action = %action_name, "Signing flow failed: {message}");
            SignOutcome::Error { message }
        }
    };

    let id = crate::oidc_client::random_token();
    let mut results = load_results(session).await?;
    results.insert(
        id.clone(),
        SignResult {
            action: action_name,
            outcome,
            created_unix: now_unix(),
        },
    );
    session.insert(RESULTS_KEY, results).await?;

    Ok(Redirect::to(&format!("{page}?sign_result={id}")))
}

/// Exchange the code, check the re-authentication, and sign. The ephemeral
/// key is dropped (and zeroized) when this returns.
async fn sign(
    state: &AppState,
    query: &CallbackQuery,
    entry: PendingSign,
) -> Result<SignOutcome, String> {
    if let Some(err) = &query.error {
        let desc = query.error_description.as_deref().unwrap_or("No description");
        return Err(format!("OIDC error: {err} - {desc}"));
    }
    let code = query.code.as_deref().ok_or("Missing authorization code")?;

    let client_id = &state.config.oidc.client_id;
    let id_token = crate::oidc_client::exchange_code(
        &state.http_client,
        &state.oidc_metadata,
        client_id,
        &state.config.get_redirect_uri(),
        code,
        &entry.pkce_verifier,
    )
    .await?;
    let started_at = time::OffsetDateTime::from_unix_timestamp(entry.started_at_unix)
        .map_err(|_| "Invalid start time".to_string())?;
    let claims = crate::oidc_client::validate_id_token(
        &id_token,
        &state.jwks,
        &state.config.oidc.issuer_url,
        client_id,
        &crate::security::key_binding(&entry.public_key_pem),
        Some(started_at),
    )?;
    let signer = claims
        .get("username")
        .or_else(|| claims.get("sub"))
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();

    let key = crate::signing::key_from_hex(&entry.signing_key_hex)?;
    let tsa_url = &state.config.timestamp_authority.url;
    let pem = &entry.public_key_pem;

    match entry.action {
        SignAction::Approve {
            command,
            operator_requires,
        } => {
            let payload = crate::security::canonical_approver_payload(&command, &operator_requires);
            let a = crate::signing::attest(
                &state.http_client,
                tsa_url,
                &key,
                pem,
                id_token,
                payload.as_bytes(),
            )
            .await?;
            let signed_at = timestamp_time(state, &a)?;
            Ok(SignOutcome::Bundle {
                signer,
                signed_at,
                bundle: Box::new(ExecutionBundle {
                    approver: ApproverBundle {
                        command,
                        operator_requires,
                        signature: a.signature,
                        id_token: a.id_token,
                        public_key: a.public_key,
                        timestamp_token: a.timestamp_token,
                    },
                    operator: None,
                }),
            })
        }
        SignAction::Cosign { approver } => {
            let payload = crate::security::operator_payload(&approver.signature, pem);
            let a = crate::signing::attest(&state.http_client, tsa_url, &key, pem, id_token, &payload)
                .await?;
            let signed_at = timestamp_time(state, &a)?;
            Ok(SignOutcome::Bundle {
                signer,
                signed_at,
                bundle: Box::new(ExecutionBundle {
                    operator: Some(OperatorCosign {
                        approver_sig: approver.signature.clone(),
                        signature: a.signature,
                        id_token: a.id_token,
                        public_key: a.public_key,
                        timestamp_token: a.timestamp_token,
                    }),
                    approver,
                }),
            })
        }
        SignAction::Revoke {
            approver,
            agent_url,
        } => {
            let payload = crate::security::revocation_payload(&approver.signature, pem);
            let a = crate::signing::attest(&state.http_client, tsa_url, &key, pem, id_token, &payload)
                .await?;
            let bundle = RevocationBundle {
                approver,
                revoker: RevokerAttestation {
                    signature: a.signature,
                    id_token: a.id_token,
                    public_key: a.public_key,
                    timestamp_token: a.timestamp_token,
                },
            };
            // Resolved and allow-listed at begin; re-check in case the
            // config changed while the user was at the IdP.
            let base = crate::agent_proxy::resolve_agent_url(state, agent_url.as_deref())
                .map_err(|e| e.to_string())?;
            let url = base.join("revoke").map_err(|e| format!("URL join: {e}"))?;
            let resp = state
                .agent_http
                .post(url)
                .json(&bundle)
                .send()
                .await
                .map_err(|e| format!("Agent unreachable: {}", e.without_url()))?;
            let status = resp.status().as_u16();
            let text = resp.text().await.unwrap_or_default();
            let body = serde_json::from_str(&text)
                .unwrap_or_else(|_| serde_json::json!({ "error": text }));
            Ok(SignOutcome::Revoked { status, body })
        }
    }
}

/// Verify the attestation's TSA token the way an agent will, and return its
/// time. Catches a misconfigured or untrusted TSA here, before the bundle is
/// handed out, rather than at execution.
fn timestamp_time(
    state: &AppState,
    a: &crate::signing::Attestation,
) -> Result<String, String> {
    let token = hex::decode(&a.timestamp_token).map_err(|_| "Invalid TSA token".to_string())?;
    let mut data = hex::decode(&a.signature).map_err(|_| "Invalid signature".to_string())?;
    data.extend_from_slice(a.id_token.as_bytes());
    let at = crate::tsa::verify_timestamp(&token, &data, &state.trusted_roots)
        .map_err(|e| format!("The timestamp from the TSA does not verify: {e}"))?;
    at.format(&time::format_description::well_known::Rfc3339)
        .map_err(|e| e.to_string())
}

/// GET /api/sign/result/{id} — read (and forget) a signing result.
pub async fn result_handler(
    session: Session,
    Path(id): Path<String>,
) -> Result<axum::Json<SignResult>, AppError> {
    require_profile(&session).await?;
    let mut results = load_results(&session).await?;
    let result = results
        .remove(&id)
        .ok_or_else(|| AppError::Forbidden("Unknown or already-read signing result".into()))?;
    session.insert(RESULTS_KEY, results).await?;
    Ok(axum::Json(result))
}
