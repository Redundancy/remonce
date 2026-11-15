use axum::{
    Router,
    extract::{
        ConnectInfo, Json, Path, State, Query,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    response::{IntoResponse, Response},
    routing::{get, post},
};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::Stdio;
use tokio::io::{AsyncReadExt, AsyncWriteExt, AsyncSeekExt};
use tokio::net::TcpListener;
// Removed unused imports
use crate::config::Config;
use crate::files;
use tower_http::cors::CorsLayer;

#[derive(Clone)]
pub struct AgentState {
    pub http_client: Client,
    pub config: Config,
    /// The IdP's token-signing keys, refreshed as it rotates them.
    pub idp_keys: crate::idp_keys::IdpKeys,
    pub hostname: String,
    pub trusted_roots: Vec<Vec<u8>>,
    pub replay_cache: crate::replay::ReplayCache,
    pub revocations: crate::replay::RevocationCache,
    /// Central revocation service (client, base URL). When set, every
    /// execution checks it and FAILS CLOSED if it is unreachable.
    pub revocation_service: Option<(Client, url::Url)>,
    /// The authorization policy, evaluated in-process.
    pub policy: std::sync::Arc<crate::policy::Policy>,
    /// The commands running now.
    pub runs: Runs,
}

// ExecutionRequest is imported from security module

/// Verify a viewer bearer token against the IdP's current keys. Used by
/// `/api/files`, `/api/files/stream` and `/stream/{id}`, where the bearer
/// token is the only auth. Returns the JWT claims.
///
/// Only tokens for the *viewer* client are accepted (strict audience), so a
/// signing token — including an approver's token carried inside a delegated
/// bundle — can never be used to browse. Without `viewer_client_id` the
/// endpoints are disabled.
async fn verify_query_token(
    token: &str,
    state: &AgentState,
) -> Result<serde_json::Value, (axum::http::StatusCode, &'static str)> {
    use axum::http::StatusCode;
    let Some(viewer) = state.config.oidc.viewer_client_id.as_deref() else {
        return Err((
            StatusCode::FORBIDDEN,
            "File viewing disabled (no viewer_client_id configured)",
        ));
    };
    let keys = state.idp_keys.for_tokens([token]).await;
    crate::security::verify_bearer_token(token, &keys, &state.config.oidc.issuer_url, viewer)
        .map_err(|_| (StatusCode::UNAUTHORIZED, "Invalid Token"))
}

/// How long to keep draining a command's output after it exits or is killed.
const LOG_DRAIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Parse an optional RFC 3339 time bound from the signed command. `Ok(None)`
/// when absent; `Err(field)` when present but not a valid RFC 3339 string.
fn parse_time_bound(
    command: &serde_json::Value,
    field: &'static str,
) -> Result<Option<time::OffsetDateTime>, &'static str> {
    match command.get(field) {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::String(s)) => {
            time::OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339)
                .map(Some)
                .map_err(|_| field)
        }
        Some(_) => Err(field),
    }
}

#[derive(Serialize)]
pub struct ExecutionResponse {
    pub status: String,
    /// The execution id: the client streams the run's log by it.
    pub message: String,
    pub request_id: String,
    /// When the run started (RFC 3339).
    pub execution_time: Option<String>,
}

#[derive(Serialize)]
struct ErrorResponse {
    #[serde(skip)]
    status: axum::http::StatusCode,
    error: String,
}

impl ErrorResponse {
    fn new(status: axum::http::StatusCode, error: impl Into<String>) -> Self {
        Self { status, error: error.into() }
    }

    fn bad(error: impl Into<String>) -> Self {
        Self::new(axum::http::StatusCode::BAD_REQUEST, error)
    }
}

impl IntoResponse for ErrorResponse {
    fn into_response(self) -> Response {
        (self.status, Json(self)).into_response()
    }
}

pub async fn run(insecure: bool) -> Result<(), Box<dyn std::error::Error>> {
    // 1. Load Config (Reuse web::Config for simplicity)
    let config: Config = crate::config::load("config.toml")?;

    let insecure_mode = crate::insecure::validate(&config, insecure)
        .map_err(|e| -> Box<dyn std::error::Error> { e.to_string().into() })?;
    crate::audit::set_insecure_mode(insecure_mode.as_bool());

    let agent_config = config
        .agent
        .clone()
        .ok_or("Missing [agent] section in config.toml — the agent requires an `[agent]` block with TLS configuration. See CONFIGURATION.md.")?;

    if let Some(path) = &agent_config.audit_log_path {
        crate::audit::set_audit_file(path)?;
        tracing::info!(path = %path, "Audit records are also appended to a file");
    }

    let http_client = crate::http_client();

    // 2. The IdP's signing keys, to verify tokens with; kept current.
    let (_, idp_keys) = crate::idp_keys::IdpKeys::discover(&http_client, &config.oidc.issuer_url).await?;

    // 3. Load TSA Trusted Roots
    let trusted_roots = crate::tsa::load_trust_anchors(
        config.timestamp_authority.ca_path.as_deref(),
        config.timestamp_authority.trust_system_store,
    );
    tracing::info!("Loaded {} trusted TSA roots", trusted_roots.len());

    if config.oidc.viewer_client_id.is_none() {
        return Err("oidc.viewer_client_id must be set: executors, file and log viewing, and the command catalog \
             all authenticate with viewer-client logins"
            .into());
    }

    let hostname = hostname::get()
        .map(|h| h.to_string_lossy().into_owned())
        .unwrap_or_else(|_| "unknown".to_string());

    tracing::info!(event = "agent_startup", hostname = %hostname, "Agent starting up");

    let revocation_service = match &agent_config.revocation_service_url {
        Some(raw) => {
            let mut parsed: url::Url = raw
                .trim()
                .parse()
                .map_err(|e| format!("Invalid agent.revocation_service_url: {e}"))?;
            // Treat the path as a base directory so the service can sit
            // behind a path prefix: endpoints are joined relative to it.
            if !parsed.path().ends_with('/') {
                let with_slash = format!("{}/", parsed.path());
                parsed.set_path(&with_slash);
            }
            parsed.set_query(None);
            parsed.set_fragment(None);
            if parsed.scheme() != "https" {
                return Err(format!(
                    "agent.revocation_service_url must be https (got '{raw}')"
                )
                .into());
            }
            let client = crate::agent_proxy::build_agent_http(
                agent_config.revocation_service_ca_path.as_deref(),
            )
            .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
            tracing::info!(url = %parsed, "Central revocation service enabled (fail-closed)");
            Some((client, parsed))
        }
        None => None,
    };

    let policy = std::sync::Arc::new(crate::policy::Policy::from_config(&config)?);
    tracing::info!(backend = %policy.describe(), "Policy ready");

    // Which requests have run, and which were revoked here.
    let (replay_cache, revocations) = match &agent_config.state_dir {
        Some(dir) => {
            let dir = PathBuf::from(dir);
            std::fs::create_dir_all(&dir)
                .map_err(|e| format!("Failed to create agent.state_dir '{}': {e}", dir.display()))?;
            tracing::info!(dir = %dir.display(), "Executed and revoked requests are remembered across restarts");
            (
                crate::replay::ReplayCache::persistent(&dir)?,
                crate::replay::RevocationCache::persistent(&dir)?,
            )
        }
        None => {
            tracing::warn!(
                "agent.state_dir is not set: a restart forgets which requests ran and which were revoked here"
            );
            (crate::replay::ReplayCache::new(), crate::replay::RevocationCache::new())
        }
    };

    let state = AgentState {
        http_client,
        config,
        idp_keys,
        hostname,
        trusted_roots,
        replay_cache,
        revocations,
        revocation_service,
        policy,
        runs: Runs::default(),
    };
    let runs = state.runs.clone();

    let app = build_router(state, &agent_config.cors_allowed_origins);

    let addr: SocketAddr = agent_config
        .listen_address
        .parse()
        .map_err(|e| format!("Invalid agent.listen_address: {e}"))?;
    tracing::info!(event = "tcp_listen", address = %addr, tls_mode = ?agent_config.tls, "Agent listening (TLS)");

    let listener = TcpListener::bind(&addr).await?;
    tokio::select! {
        served = crate::tls::serve_with_tls(listener, app, &agent_config.tls) => {
            served.map_err(|e| -> Box<dyn std::error::Error> { e.to_string().into() })?;
        }
        // Asked to stop: no more requests, and nothing left running behind
        // us with nobody to time it out.
        _ = shutdown_signal() => {
            tracing::info!(event = "agent_shutdown", "Shutting down: stopping running commands");
            runs.stop_all(SHUTDOWN_GRACE).await;
        }
    }

    Ok(())
}

/// How long shutdown waits for stopped commands' logs and audit records.
const SHUTDOWN_GRACE: std::time::Duration = std::time::Duration::from_secs(10);

/// Resolves when the process is asked to stop: Ctrl-C, or SIGTERM on Unix.
async fn shutdown_signal() {
    let ctrl_c = async {
        if tokio::signal::ctrl_c().await.is_err() {
            std::future::pending::<()>().await;
        }
    };
    #[cfg(unix)]
    {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut term) => {
                tokio::select! {
                    _ = ctrl_c => {}
                    _ = term.recv() => {}
                }
            }
            Err(_) => ctrl_c.await,
        }
    }
    #[cfg(not(unix))]
    ctrl_c.await;
}

/// The agent's routes over `state`, with CORS for `cors_allowed_origins`
/// (none when empty). Handlers read the peer address from
/// `ConnectInfo<PeerAddr>`, so serve it with that connect info.
pub fn build_router(state: AgentState, cors_allowed_origins: &[String]) -> Router {
    let mut app = Router::new()
        .route("/execute", post(execute_handler))
        .route("/revoke", post(revoke_handler))
        .route("/api/commands", get(catalog_handler))
        .route("/api/requirements/match", post(match_handler))
        .route("/stream/{id}", get(stream_logs_handler))
        .route("/api/files", get(list_files_handler))
        .route("/api/files/stream", get(stream_file_handler))
        .with_state(state);

    if !cors_allowed_origins.is_empty() {
        use tower_http::cors::AllowOrigin;
        use axum::http::HeaderValue;
        // "*" (which needs `--insecure`) is any origin; it can't be mixed
        // into a list of named ones.
        let allow_origin = if cors_allowed_origins.iter().any(|o| o == "*") {
            AllowOrigin::any()
        } else {
            let origins: Vec<HeaderValue> = cors_allowed_origins
                .iter()
                .filter_map(|o| HeaderValue::from_str(o).ok())
                .collect();
            AllowOrigin::list(origins)
        };
        app = app.layer(
            CorsLayer::new()
                .allow_origin(allow_origin)
                .allow_headers(tower_http::cors::Any)
                .allow_methods(tower_http::cors::Any),
        );
    }
    app
}

/// Replace control characters so a value can't break the log's line
/// structure (e.g. forge an `--- EXIT ---` trailer through a username).
fn sanitize_log_field(s: &str) -> String {
    s.chars().map(|c| if c.is_control() { ' ' } else { c }).collect()
}

fn claims_username(claims: &serde_json::Value) -> String {
    claims
        .get("username")
        .or_else(|| claims.get("sub"))
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string()
}

fn rfc3339(t: time::OffsetDateTime) -> String {
    t.format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "unknown_time".to_string())
}

/// The block written at the top of every execution log. The run page reads
/// these lines back, so every field is sanitized.
#[allow(clippy::too_many_arguments)]
fn log_header(
    execution_id: &str,
    request_id: &str,
    approvers: &[crate::security::SignerIdentity],
    executor: &str,
    started: &str,
    command: &str,
    executable: &str,
    args: &[String],
) -> String {
    let mut h = String::from("--- EXECUTION LOG ---\n");
    h += &format!("ID: {}\n", sanitize_log_field(execution_id));
    h += &format!("Request: {}\n", sanitize_log_field(request_id));
    for a in approvers {
        h += &format!(
            "Approver: {} ({})\n",
            sanitize_log_field(&a.username),
            rfc3339(a.signed_at)
        );
    }
    h += &format!("Executor: {}\n", sanitize_log_field(executor));
    h += &format!("Time: {}\n", sanitize_log_field(started));
    h += &format!("Command: {}\n", sanitize_log_field(command));
    h += &format!(
        "Executable: {}\n",
        sanitize_log_field(&format!("{} {}", executable, args.join(" ")))
    );
    h += "---------------------\n";
    h
}

/// Command-level checks that need no policy: this host is a target, the
/// time bounds hold, and the parameters validate. Returns the rendered
/// argv, or (audit reason, client message).
fn check_command(
    command_json: &serde_json::Value,
    cmd_config: &crate::config::CommandConfig,
    hostname: &str,
    now: time::OffsetDateTime,
) -> Result<Vec<String>, (String, String)> {
    let targets: Vec<String> = match command_json.get("target_machines").and_then(|v| v.as_array()) {
        Some(arr) => arr.iter().filter_map(|v| v.as_str().map(String::from)).collect(),
        None => {
            return Err((
                "Missing mandatory 'target_machines' field".into(),
                "Missing Target Restriction".into(),
            ));
        }
    };
    if !targets.iter().any(|t| t == hostname) {
        return Err((
            format!("Hostname '{hostname}' not in target list {targets:?}"),
            format!("Target Machine Mismatch ({hostname} not in {targets:?})"),
        ));
    }

    // A time bound that is present but unparsable must deny, not vanish:
    // the approvers believe the command is time-limited.
    let (not_before, not_after) = match (
        parse_time_bound(command_json, "not_before"),
        parse_time_bound(command_json, "not_after"),
    ) {
        (Ok(nbf), Ok(naf)) => (nbf, naf),
        (Err(field), _) | (_, Err(field)) => {
            return Err((
                format!("Malformed '{field}' (expected an RFC 3339 string)"),
                "Invalid Time Constraint".into(),
            ));
        }
    };
    if let Some(nbf) = not_before
        && now < nbf
    {
        return Err((
            format!("Command not yet valid (nbf: {nbf}, now: {now})"),
            format!("Command Not Yet Valid (Starts at {nbf})"),
        ));
    }
    if let Some(exp) = not_after
        && now > exp
    {
        return Err((
            format!("Command expired (not_after: {exp}, now: {now})"),
            format!("Command Expired (Expired at {exp})"),
        ));
    }

    // Validate signed params against the declarations and render the args
    // template. Fail-closed: any violation rejects the execution.
    let resolved = crate::params::validate_params(cmd_config, command_json.get("params"))
        .map_err(|e| (format!("Parameter validation failed: {e}"), "Invalid Parameters".to_string()))?;
    crate::params::render_args(&cmd_config.args, &resolved)
        .map_err(|e| (format!("Argument rendering failed: {e}"), "Invalid Parameters".to_string()))
}

/// Run a request. In order: who is executing (a viewer login session,
/// always — never anonymous), the bundle, the command, every approval, the
/// command's own constraints, revocation, policy (the command's requirement +
/// executor), and replay — last, so a rejection earlier doesn't use up the
/// request.
async fn execute_handler(
    State(state): State<AgentState>,
    ConnectInfo(addr): ConnectInfo<crate::tls::PeerAddr>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Result<Json<ExecutionResponse>, ErrorResponse> {
    use crate::audit::{AuditContext, AuditSigner};
    use axum::http::StatusCode;

    let ip = addr.ip_string();
    let hostname = state.hostname.clone();
    let audit = |decision: &'static str, reason: String, user: &str, mut ctx: AuditContext| {
        ctx.event_type.get_or_insert("command_execution");
        crate::audit::log_audit(decision, reason, user.to_string(), ip.clone(), hostname.clone(), ctx)
    };

    // 1. The executor: identified by their viewer login.
    let Some(token) = bearer_token(&headers) else {
        audit("deny", "No executor token".into(), "unauthenticated", AuditContext::default());
        return Err(ErrorResponse::new(StatusCode::UNAUTHORIZED, "Log in to execute: missing bearer token"));
    };
    let executor_claims = verify_query_token(&token, &state).await.map_err(|(status, msg)| {
        audit("deny", format!("Executor token rejected: {msg}"), "unauthenticated", AuditContext::default());
        ErrorResponse::new(status, msg)
    })?;
    let executor = crate::policy::Identity {
        username: claims_username(&executor_claims),
        claims: executor_claims,
    };
    let user = executor.username.clone();

    // 2. The bundle.
    let bundle: crate::security::RequestBundle = match serde_json::from_slice(&body) {
        Ok(b) => b,
        Err(e) => {
            let old_format = serde_json::from_slice::<serde_json::Value>(&body)
                .ok()
                .is_some_and(|v| v.get("approver").is_some());
            let msg = if old_format {
                "This bundle was made by an older version of Remonce; ask for a new request".to_string()
            } else {
                format!("Invalid bundle: {e}")
            };
            audit("deny", msg.clone(), &user, AuditContext::default());
            return Err(ErrorResponse::bad(msg));
        }
    };
    let command_json = bundle.command.clone();
    let basic_ctx = || AuditContext {
        command: Some(command_json.clone()),
        ..Default::default()
    };

    // 3. A command this agent runs, with a UUID execution id.
    let Some(command_name) = command_json.get("command").and_then(|v| v.as_str()).map(String::from) else {
        audit("deny", "Missing 'command' field".into(), &user, basic_ctx());
        return Err(ErrorResponse::bad("Invalid Request"));
    };
    let Some(cmd_config) = state.config.commands.iter().find(|c| c.name == command_name).cloned() else {
        audit("deny", format!("Command '{command_name}' not configured here"), &user, basic_ctx());
        return Err(ErrorResponse::bad(format!("This agent has no command '{command_name}'")));
    };
    // The id names the log file, so only a canonical UUID may reach the path.
    let Some(execution_id) = command_json
        .get("id")
        .and_then(|v| v.as_str())
        .and_then(|s| uuid::Uuid::parse_str(s).ok())
        .map(|u| u.to_string())
    else {
        audit("deny", "Request id is not a UUID".into(), &user, basic_ctx());
        return Err(ErrorResponse::bad("The request's id must be a UUID"));
    };

    // 4. Every approval: genuine, fresh, from different people.
    let validity = cmd_config.approval_validity_or_default();
    let keys = state
        .idp_keys
        .for_tokens(bundle.approvals.iter().map(|a| a.id_token.as_str()))
        .await;
    let verifier_config = crate::security::VerifierConfig {
        client_id: state.config.oidc.signing_client_id.clone(),
        issuer_url: state.config.oidc.issuer_url.clone(),
        jwks: (*keys).clone(),
        trusted_roots: state.trusted_roots.clone(),
        approval_validity: validity,
    };
    let now = time::OffsetDateTime::now_utc();
    let verified = match crate::security::verify_request(&bundle, &verifier_config, now) {
        Ok(v) => v,
        Err(e) => {
            use crate::security::ValidationError as V;
            audit("deny", format!("Verification failed: {e}"), &user, basic_ctx());
            let public = match &e {
                V::NoApprovals
                | V::TooManyApprovals { .. }
                | V::ApprovalStale { .. }
                | V::DuplicateApprover { .. } => e.to_string(),
                V::InApproval { index, .. } => format!("Approval #{index} could not be verified"),
                _ => "Verification Failed".to_string(),
            };
            return Err(ErrorResponse::bad(public));
        }
    };
    let request_id = verified.request_id.clone();
    let approvers = verified.approvers;
    let audit_approvers: Vec<AuditSigner> = approvers
        .iter()
        .map(|a| AuditSigner {
            username: a.username.clone(),
            sub: a.subject().to_string(),
            signed_at: rfc3339(a.signed_at),
        })
        .collect();
    let full_ctx = || AuditContext {
        command: Some(command_json.clone()),
        request_id: Some(request_id.clone()),
        approvers: Some(audit_approvers.clone()),
        ..Default::default()
    };

    // 5. The command's own constraints.
    let rendered_args = check_command(&command_json, &cmd_config, &hostname, now).map_err(|(reason, public)| {
        audit("deny", reason, &user, full_ctx());
        ErrorResponse::bad(public)
    })?;

    // 6. Revocation: this agent's list, then the central service (fail-closed).
    if state.revocations.is_revoked(&request_id) {
        audit("deny", "Request has been revoked".into(), &user, full_ctx());
        return Err(ErrorResponse::new(StatusCode::FORBIDDEN, "Request Revoked"));
    }
    if let Some((client, base)) = &state.revocation_service {
        match check_revocation_service(client, base, &request_id).await {
            Ok(false) => {}
            Ok(true) => {
                audit("deny", "Request has been revoked (revocation service)".into(), &user, full_ctx());
                return Err(ErrorResponse::new(StatusCode::FORBIDDEN, "Request Revoked"));
            }
            Err(e) => {
                audit("error", format!("Revocation service check failed: {e}"), &user, full_ctx());
                return Err(ErrorResponse::new(StatusCode::SERVICE_UNAVAILABLE, "Revocation Check Failed"));
            }
        }
    }

    // 7. Policy: are these approvers enough, and may this person execute?
    let input = crate::policy::RequestInput::Execute {
        command: command_json.clone(),
        request_id: request_id.clone(),
        approvers: approvers
            .iter()
            .map(|a| crate::policy::Signer {
                username: a.username.clone(),
                claims: a.claims.clone(),
                signed_at: rfc3339(a.signed_at),
            })
            .collect(),
        executor,
        host: hostname.clone(),
        requirement: cmd_config.requirement(),
    };
    let decision = state.policy.decide(&cmd_config.opa_rule, &input).await.map_err(|e| {
        audit("error", format!("Policy evaluation failed: {e}"), &user, full_ctx());
        ErrorResponse::new(StatusCode::SERVICE_UNAVAILABLE, "Policy engine unavailable")
    })?;
    if !decision.allow {
        audit("deny", decision.reason.clone(), &user, full_ctx());
        return Err(ErrorResponse::new(
            StatusCode::FORBIDDEN,
            format!("Authorization Denied: {}", decision.reason),
        ));
    }

    // 8, 9. Replay, then run — in a task of its own. Once the request is
    //       marked as used, a client that hangs up must not be able to stop
    //       it short of starting (or of having the mark released).
    let run = Run {
        cmd_config,
        command_name,
        command_json,
        execution_id,
        request_id,
        approvers,
        audit_approvers,
        rendered_args,
        user,
        ip,
        validity,
        now,
    };
    match tokio::spawn(start_run(state, run)).await {
        Ok(result) => result.map(Json),
        Err(e) => {
            tracing::error!("Run task failed: {e}");
            Err(ErrorResponse::new(StatusCode::INTERNAL_SERVER_ERROR, "Internal Error"))
        }
    }
}

/// A request that has passed every check, ready to run.
struct Run {
    cmd_config: crate::config::CommandConfig,
    command_name: String,
    command_json: serde_json::Value,
    /// The request's signed id; names the run and its log.
    execution_id: String,
    request_id: String,
    approvers: Vec<crate::security::SignerIdentity>,
    audit_approvers: Vec<crate::audit::AuditSigner>,
    rendered_args: Vec<String>,
    /// The executor.
    user: String,
    ip: String,
    validity: std::time::Duration,
    /// When the request was verified.
    now: time::OffsetDateTime,
}

/// Mark the request as used, then start its command. Returns once the
/// process is running (or couldn't be started, in which case the mark is
/// released so the request can be retried).
async fn start_run(state: AgentState, run: Run) -> Result<ExecutionResponse, ErrorResponse> {
    use crate::audit::AuditContext;
    use axum::http::StatusCode;

    let Run {
        cmd_config,
        command_name,
        command_json,
        execution_id,
        request_id,
        approvers,
        audit_approvers,
        rendered_args,
        user,
        ip,
        validity,
        now,
    } = run;
    let hostname = state.hostname.clone();
    let audit_ctx = AuditContext {
        event_type: Some("command_execution"),
        command: Some(command_json),
        request_id: Some(request_id.clone()),
        approvers: Some(audit_approvers),
        ..Default::default()
    };
    let audit = |decision: &'static str, reason: String| {
        crate::audit::log_audit(decision, reason, user.clone(), ip.clone(), hostname.clone(), audit_ctx.clone())
    };

    if state.runs.stop.is_cancelled() {
        audit("error", "Refusing to run: the agent is shutting down".into());
        return Err(ErrorResponse::new(StatusCode::SERVICE_UNAVAILABLE, "The agent is shutting down"));
    }

    // 8. Replay: one run per request. Remembered past every approval that
    //    could exist now; released if we fail before the process starts.
    let ttl = crate::security::replay_ttl(now, &approvers, validity);
    match state.replay_cache.check_and_insert(&request_id, ttl) {
        Ok(()) => {}
        Err(crate::replay::ReplayError::AlreadyRun) => {
            audit("deny", "Replay: request already executed".into());
            return Err(ErrorResponse::new(
                StatusCode::CONFLICT,
                "This request has already been executed on this agent",
            ));
        }
        Err(e @ crate::replay::ReplayError::Store(_)) => {
            // Not running is the only safe answer: a run we can't remember
            // could be repeated.
            audit("error", format!("Refusing to run: {e}"));
            return Err(ErrorResponse::new(StatusCode::INTERNAL_SERVER_ERROR, "Internal Error"));
        }
    }
    let release_replay = || state.replay_cache.release(&request_id);

    // 9. Run it.
    let executable = cmd_config.executable.clone().unwrap_or_else(|| command_name.clone());
    let started = rfc3339(time::OffsetDateTime::now_utc());

    let logs_dir = PathBuf::from(&state.config.logs_dir);
    if !logs_dir.exists() {
        tokio::fs::create_dir_all(&logs_dir).await.map_err(|e| {
            release_replay();
            audit("error", format!("Failed to create logs dir: {e}"));
            ErrorResponse::new(StatusCode::INTERNAL_SERVER_ERROR, "Internal Error")
        })?;
    }

    // `create_new`: a request runs once per agent, but after the replay
    // entry lapses fresh approvals of the same request can run it again,
    // and each run keeps its own log. If the signed id is taken, fall back
    // to a fresh one.
    let open_new = |path: PathBuf| async move {
        tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .await
    };
    let mut execution_id = execution_id;
    let mut log_path = logs_dir.join(format!("{execution_id}.log"));
    let log_result = match open_new(log_path.clone()).await {
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            execution_id = uuid::Uuid::new_v4().to_string();
            log_path = logs_dir.join(format!("{execution_id}.log"));
            open_new(log_path.clone()).await
        }
        other => other,
    };
    let mut log_file = log_result.map_err(|e| {
        release_replay();
        audit("error", format!("Failed to create log file: {e}"));
        ErrorResponse::new(StatusCode::INTERNAL_SERVER_ERROR, "Internal Error")
    })?;

    tracing::info!("Executing command '{}' with ID {}", command_name, execution_id);

    let header = log_header(
        &execution_id,
        &request_id,
        &approvers,
        &user,
        &started,
        &command_name,
        &executable,
        &rendered_args,
    );
    if let Err(e) = log_file.write_all(header.as_bytes()).await {
        tracing::error!("Failed to write header to log file: {}", e);
        // Non-critical, continue
    }

    // Spawn Command — hardened:
    //   - stdin closed (commands that read stdin would otherwise hang forever)
    //   - parent env scrubbed; only operator-configured `env` survives
    //   - at the head of its own process tree, so a wall-clock timeout (or
    //     the agent shutting down) stops everything it started too
    let timeout = cmd_config.command_timeout_or_default();

    let mut spawn_cmd = tokio::process::Command::new(&executable);
    spawn_cmd
        .args(&rendered_args)
        .current_dir(cmd_config.cwd.clone().unwrap_or_else(|| ".".to_string()))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env_clear();
    for (k, v) in &cmd_config.env {
        spawn_cmd.env(k, v);
    }
    crate::process_tree::isolate(&mut spawn_cmd);

    let child = spawn_cmd.spawn().map_err(|e| {
        release_replay();
        audit("error", format!("Failed to spawn command: {e}"));
        ErrorResponse::new(StatusCode::INTERNAL_SERVER_ERROR, "Execution Failed")
    })?;
    let tree = crate::process_tree::ProcessTree::of(&child);

    let process_started = std::time::Instant::now();
    // The run's own records name it, so its start, end and log tie up.
    let run_ctx = AuditContext {
        execution_id: Some(execution_id.clone()),
        ..audit_ctx.clone()
    };
    let finished = {
        let (user, ip, hostname, run_ctx) = (user.clone(), ip.clone(), hostname.clone(), run_ctx.clone());
        move |result: &'static str, exit_code: Option<i32>, output_truncated: bool, reason: String| {
            crate::audit::log_audit(
                "completed",
                reason,
                user,
                ip,
                hostname,
                AuditContext {
                    event_type: Some("command_finished"),
                    outcome: Some(crate::audit::AuditOutcome {
                        result,
                        exit_code,
                        duration_ms: u64::try_from(process_started.elapsed().as_millis()).unwrap_or(u64::MAX),
                        output_truncated,
                    }),
                    ..run_ctx
                },
            )
        }
    };

    // From here the run looks after itself, whatever becomes of this
    // request: its output goes to the log, and it is stopped on timeout or
    // when the agent shuts down.
    state.runs.tasks.spawn(supervise(
        Supervised {
            child,
            tree,
            log_file,
            log_path,
            execution_id: execution_id.clone(),
            timeout,
            max_output: cmd_config.max_output_bytes_or_default(),
            stop: state.runs.stop.clone(),
        },
        finished,
    ));

    crate::audit::log_audit(
        "allow",
        "Command Started".to_string(),
        user.clone(),
        ip.clone(),
        hostname.clone(),
        run_ctx,
    );

    Ok(ExecutionResponse {
        status: "authorized".to_string(),
        // The execution id, which the client streams the log by.
        message: execution_id,
        request_id,
        execution_time: Some(started),
    })
}

/// The commands this agent is running, so they can be stopped when it is.
#[derive(Clone, Default)]
pub struct Runs {
    /// Cancelled when the agent is shutting down.
    stop: tokio_util::sync::CancellationToken,
    /// One task per running command.
    tasks: tokio_util::task::TaskTracker,
}

impl Runs {
    /// Stop every running command (and what each started), and wait up to
    /// `grace` for their logs and audit records to be finished off. No new
    /// command starts afterwards.
    pub async fn stop_all(&self, grace: std::time::Duration) {
        self.stop.cancel();
        self.tasks.close();
        if tokio::time::timeout(grace, self.tasks.wait()).await.is_err() {
            tracing::warn!("Some commands were still being stopped after {grace:?}");
        }
    }
}

/// A started command and what is needed to see it through.
struct Supervised {
    child: tokio::process::Child,
    tree: crate::process_tree::ProcessTree,
    log_file: tokio::fs::File,
    log_path: PathBuf,
    execution_id: String,
    timeout: std::time::Duration,
    /// Bytes of output kept in the log.
    max_output: u64,
    stop: tokio_util::sync::CancellationToken,
}

/// How a supervised command came to an end.
enum Ending {
    Exited(std::io::Result<std::process::ExitStatus>),
    Timeout,
    Shutdown,
}

/// See a command through to its end: copy its output to the run log, stop
/// it (and everything it started) on timeout or shutdown, then record how
/// it ended — `finished(result, exit code, output truncated, reason)` for
/// the audit log, and a trailer in the run log.
async fn supervise(
    run: Supervised,
    finished: impl FnOnce(&'static str, Option<i32>, bool, String),
) {
    use std::sync::atomic::{AtomicBool, Ordering};

    let Supervised {
        mut child,
        tree,
        log_file,
        log_path,
        execution_id,
        timeout,
        max_output,
        stop,
    } = run;

    // Output is copied as the bytes it is: decoding each chunk separately
    // would mangle a character that straddles two of them.
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(100);
    fn pump(pipe: Option<impl tokio::io::AsyncRead + Unpin + Send + 'static>, tx: tokio::sync::mpsc::Sender<Vec<u8>>) {
        let Some(mut pipe) = pipe else { return };
        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            loop {
                let n = pipe.read(&mut buf).await.unwrap_or(0);
                if n == 0 || tx.send(buf[..n].to_vec()).await.is_err() {
                    break;
                }
            }
        });
    }
    pump(child.stdout.take(), tx.clone());
    pump(child.stderr.take(), tx);

    // The writer ends when both pumps have dropped their senders. It runs
    // as its own task so output drains while the child runs; and it keeps
    // draining past the limit, discarding, so a chatty command isn't left
    // blocked on a full pipe.
    let truncated = std::sync::Arc::new(AtomicBool::new(false));
    let mut writer = tokio::spawn({
        let truncated = truncated.clone();
        async move {
            let mut file_out = log_file;
            let mut written: u64 = 0;
            while let Some(chunk) = rx.recv().await {
                let room = usize::try_from(max_output - written).unwrap_or(usize::MAX);
                let keep = chunk.len().min(room);
                if keep > 0 {
                    let _ = file_out.write_all(&chunk[..keep]).await;
                    written += keep as u64;
                }
                if keep < chunk.len() && !truncated.swap(true, Ordering::SeqCst) {
                    let note = format!(
                        "\n--- OUTPUT TRUNCATED: over {max_output} bytes; the rest is not kept (the command runs on) ---\n"
                    );
                    let _ = file_out.write_all(note.as_bytes()).await;
                }
                let _ = file_out.flush().await;
            }
            file_out
        }
    });

    let ending = tokio::select! {
        r = child.wait() => Ending::Exited(r),
        _ = tokio::time::sleep(timeout) => Ending::Timeout,
        _ = stop.cancelled() => Ending::Shutdown,
    };
    if !matches!(ending, Ending::Exited(_)) {
        tracing::warn!(
            "Stopping command {execution_id} ({})",
            if matches!(ending, Ending::Timeout) { "timed out" } else { "agent shutting down" }
        );
        // The whole tree, then the child itself (which also reaps it).
        tree.kill();
        let _ = child.kill().await;
    }

    // Processes the command left running that inherited its stdout/stderr
    // keep the pipes open, so bound the drain, and reopen the log to write
    // the trailer if we had to give up on it.
    let file_out = match tokio::time::timeout(LOG_DRAIN_TIMEOUT, &mut writer).await {
        Ok(Ok(f)) => Some(f),
        _ => {
            writer.abort();
            tracing::warn!(
                "Command {execution_id}: output still open {LOG_DRAIN_TIMEOUT:?} after it ended (it left processes running?)"
            );
            match tokio::fs::OpenOptions::new().append(true).open(&log_path).await {
                Ok(f) => Some(f),
                Err(e) => {
                    tracing::error!("Failed to reopen log for trailer: {e}");
                    None
                }
            }
        }
    };

    let (result, exit_code, reason, trailer) = match &ending {
        Ending::Exited(Ok(status)) => (
            "exited",
            status.code(),
            format!("Command exited: {status}"),
            format!("\n--- EXIT: {status} ---\n"),
        ),
        Ending::Exited(Err(e)) => (
            "wait_error",
            None,
            format!("Waiting for the command failed: {e}"),
            format!("\n--- WAIT ERROR: {e} ---\n"),
        ),
        Ending::Timeout => (
            "timeout",
            None,
            format!(
                "Command killed after exceeding its timeout ({})",
                humantime_serde::re::humantime::format_duration(timeout)
            ),
            "\n--- TIMEOUT: process killed by agent ---\n".to_string(),
        ),
        Ending::Shutdown => (
            "agent_shutdown",
            None,
            "Command killed because the agent was shutting down".to_string(),
            "\n--- STOPPED: the agent shut down ---\n".to_string(),
        ),
    };
    // Audited whatever became of the log.
    finished(result, exit_code, truncated.load(Ordering::SeqCst), reason);
    if let Some(mut file_out) = file_out {
        let _ = file_out.write_all(trailer.as_bytes()).await;
        let _ = file_out.flush().await;
    }
}

#[derive(Serialize)]
pub struct RevocationResponse {
    pub status: String,
    pub message: String,
}

#[derive(Deserialize)]
struct RevokedStatusResponse {
    revoked: bool,
}

/// Ask the central revocation service whether a request is revoked. Any
/// transport or protocol error — including a service that doesn't know the
/// v2 path — is surfaced to the caller, which treats it as fatal
/// (fail-closed).
async fn check_revocation_service(
    client: &Client,
    base: &url::Url,
    request_id: &str,
) -> Result<bool, String> {
    let url = base
        .join(&format!("v2/revoked/{request_id}"))
        .map_err(|e| e.to_string())?;
    let resp = client
        .get(url)
        .timeout(std::time::Duration::from_secs(5))
        .send()
        .await
        .map_err(|e| e.to_string())?
        .error_for_status()
        .map_err(|e| e.to_string())?;
    let status: RevokedStatusResponse = resp.json().await.map_err(|e| e.to_string())?;
    Ok(status.revoked)
}

/// Revoke (cancel) a request. The revoker submits the request with its
/// approvals plus a fresh, nonce-bound attestation over the domain-separated
/// revocation payload. Allowed when the revoker approved the request, or
/// when OPA allows `action = "revoke"`. Idempotent. With a central
/// revocation service configured, it is forwarded there too so it applies
/// estate-wide.
async fn revoke_handler(
    State(state): State<AgentState>,
    ConnectInfo(addr): ConnectInfo<crate::tls::PeerAddr>,
    Json(req): Json<crate::security::RevocationBundle>,
) -> Result<Json<RevocationResponse>, ErrorResponse> {
    use crate::audit::{AuditContext, AuditSigner};

    let ip = addr.ip_string();
    let hostname = state.hostname.clone();

    let keys = state.idp_keys.for_tokens(req.id_tokens()).await;
    let ctx = crate::revocation::RevocationCtx {
        config: &state.config,
        jwks: &keys,
        trusted_roots: &state.trusted_roots,
        policy: &state.policy,
        hostname: &hostname,
        retention: None,
        allow_unknown_commands: false,
    };
    let verified = crate::revocation::verify_and_authorize(&ctx, &req, &ip)
        .await
        .map_err(ErrorResponse::bad)?;
    let revocation = &verified.authorized;
    let revoker_user = revocation.revoker.username.clone();

    let revoke_ctx = || AuditContext {
        event_type: Some("request_revocation"),
        command: Some(req.request.command.clone()),
        request_id: Some(revocation.request_id.clone()),
        approvers: Some(
            revocation
                .approvers
                .iter()
                .map(|a| AuditSigner {
                    username: a.username.clone(),
                    sub: a.subject().to_string(),
                    signed_at: rfc3339(a.signed_at),
                })
                .collect(),
        ),
        ..Default::default()
    };

    // Keep it until no approval of the request could still be valid.
    let now = time::OffsetDateTime::now_utc();
    if verified.keep_until > now {
        let remaining: std::time::Duration = (verified.keep_until - now).try_into().unwrap_or_default();
        if let Err(e) = state.revocations.revoke(&revocation.request_id, remaining) {
            crate::audit::log_audit(
                "error",
                format!("Failed to record revocation: {e}"),
                revoker_user.clone(),
                ip.clone(),
                hostname.clone(),
                revoke_ctx(),
            );
            return Err(ErrorResponse::new(
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "Internal Error",
            ));
        }
    }

    // Forward to the central revocation service so a single submission
    // covers the whole estate. The local pin above stands either way.
    let mut message = "Request revoked on this agent".to_string();
    if let Some((client, base)) = &state.revocation_service {
        let forward = async {
            let url = base.join("revoke").map_err(|e| e.to_string())?;
            client
                .post(url)
                .timeout(std::time::Duration::from_secs(10))
                .json(&req)
                .send()
                .await
                .map_err(|e| e.to_string())?
                .error_for_status()
                .map_err(|e| e.to_string())
        }
        .await;
        if let Err(e) = forward {
            crate::audit::log_audit(
                "error",
                format!("Revocation pinned locally but forwarding to revocation service failed: {e}"),
                revoker_user.clone(),
                ip.clone(),
                hostname.clone(),
                revoke_ctx(),
            );
            return Err(ErrorResponse::new(
                axum::http::StatusCode::SERVICE_UNAVAILABLE,
                "Revocation Service Unavailable (revoked on this agent only)",
            ));
        }
        message = "Request revoked on this agent and the revocation service".to_string();
    }

    crate::audit::log_audit(
        "allow",
        format!(
            "Request revoked by '{}'{}",
            revoker_user,
            if revocation.self_revoked { " (an approver)" } else { "" }
        ),
        revoker_user.clone(),
        ip.clone(),
        hostname.clone(),
        revoke_ctx(),
    );

    Ok(Json(RevocationResponse {
        status: "revoked".to_string(),
        message,
    }))
}

/// Record a read-only action (catalog, file list, logs) in the audit log.
fn audit_view(
    state: &AgentState,
    addr: &crate::tls::PeerAddr,
    event_type: &'static str,
    decision: &'static str,
    reason: impl Into<String>,
    user: &str,
    file: Option<serde_json::Value>,
) {
    crate::audit::log_audit(
        decision,
        reason.into(),
        user.to_string(),
        addr.ip_string(),
        state.hostname.clone(),
        crate::audit::AuditContext {
            file,
            event_type: Some(event_type),
            ..Default::default()
        },
    );
}

/// Who is asking, for a read-only endpoint: their verified viewer claims
/// and username. A missing or invalid login is audited as `event_type` and
/// comes back as the response to send.
async fn authenticate_viewer(
    state: &AgentState,
    addr: &crate::tls::PeerAddr,
    headers: &axum::http::HeaderMap,
    event_type: &'static str,
    file: Option<serde_json::Value>,
) -> Result<(serde_json::Value, String), Box<Response>> {
    let Some(token) = bearer_token(headers) else {
        audit_view(state, addr, event_type, "deny", "Missing bearer token", "unauthenticated", file);
        return Err(Box::new((axum::http::StatusCode::UNAUTHORIZED, "Missing bearer token").into_response()));
    };
    match verify_query_token(&token, state).await {
        Ok(claims) => {
            let user = claims_username(&claims);
            Ok((claims, user))
        }
        Err((status, msg)) => {
            audit_view(state, addr, event_type, "deny", msg, "unauthenticated", file);
            Err(Box::new((status, msg).into_response()))
        }
    }
}

/// Whether policy lets `viewer` see what this agent offers (`view_docs`):
/// the command catalog and the list of files. A refusal is audited as
/// `event_type` and comes back as the response to send.
async fn require_view_docs(
    state: &AgentState,
    addr: &crate::tls::PeerAddr,
    event_type: &'static str,
    claims: serde_json::Value,
    user: &str,
) -> Result<(), Box<Response>> {
    use axum::http::StatusCode;
    let viewer = crate::policy::Identity {
        username: user.to_string(),
        claims,
    };
    match state.policy.allows_viewing(&crate::policy::ViewInput::ViewDocs { viewer }).await {
        Ok(true) => Ok(()),
        Ok(false) => {
            audit_view(state, addr, event_type, "deny", "Denied by policy", user, None);
            Err(Box::new((StatusCode::FORBIDDEN, "Policy does not allow you to view this").into_response()))
        }
        Err(e) => {
            audit_view(state, addr, event_type, "error", format!("Policy evaluation failed: {e}"), user, None);
            Err(Box::new((StatusCode::SERVICE_UNAVAILABLE, "Policy engine unavailable").into_response()))
        }
    }
}

/// The command catalog: what can be requested here and what each command
/// needs (from its config, in policy's words). Viewer-token auth; policy
/// decides who may see it.
async fn catalog_handler(
    State(state): State<AgentState>,
    ConnectInfo(addr): ConnectInfo<crate::tls::PeerAddr>,
    headers: axum::http::HeaderMap,
) -> Response {
    const EVENT: &str = "catalog_access";
    let (claims, user) = match authenticate_viewer(&state, &addr, &headers, EVENT, None).await {
        Ok(v) => v,
        Err(response) => return *response,
    };
    if let Err(response) = require_view_docs(&state, &addr, EVENT, claims, &user).await {
        return *response;
    }
    let requirements = crate::catalog::requirements(&state.config);
    match state.policy.describe_slots(&requirements).await {
        Ok(descriptions) => {
            audit_view(&state, &addr, EVENT, "allow", "Catalog served", &user, None);
            Json(crate::catalog::build(&state.config, &state.hostname, &descriptions)).into_response()
        }
        Err(e) => {
            audit_view(&state, &addr, EVENT, "error", format!("Describing requirements failed: {e}"), &user, None);
            (axum::http::StatusCode::SERVICE_UNAVAILABLE, "Policy could not describe the requirements").into_response()
        }
    }
}

#[derive(Deserialize)]
struct MatchRequest {
    /// The command whose requirement to match against.
    command: String,
    /// Who to try against its approval slots: `{username, claims}` each.
    people: Vec<crate::policy::Identity>,
}

#[derive(Serialize)]
struct MatchResponse {
    /// One row per approval slot, in the catalog's order: whether the slot
    /// would accept each of the people, in the order given.
    accepted: Vec<Vec<bool>>,
}

/// Which approval slots of a command's requirement would accept which
/// people. The UI uses it to show how far a request has got, since what a
/// predicate means is policy's to say and the browser can't evaluate Rego.
///
/// For display only. The claims are whatever the caller sends, nothing is
/// verified and nothing is decided: an execution verifies every approval
/// and asks policy afresh. Open to whoever may see the catalog, and it
/// tells them nothing the catalog doesn't, so only refusals are audited.
async fn match_handler(
    State(state): State<AgentState>,
    ConnectInfo(addr): ConnectInfo<crate::tls::PeerAddr>,
    headers: axum::http::HeaderMap,
    Json(req): Json<MatchRequest>,
) -> Response {
    use axum::http::StatusCode;
    const EVENT: &str = "catalog_access";
    let (claims, user) = match authenticate_viewer(&state, &addr, &headers, EVENT, None).await {
        Ok(v) => v,
        Err(response) => return *response,
    };
    if let Err(response) = require_view_docs(&state, &addr, EVENT, claims, &user).await {
        return *response;
    }
    if req.people.len() > crate::security::MAX_APPROVALS {
        return (StatusCode::BAD_REQUEST, "Too many people").into_response();
    }
    let requirement = state
        .config
        .commands
        .iter()
        .find(|c| c.name == req.command)
        .and_then(|c| c.requirement())
        .and_then(|r| serde_json::to_value(r).ok());
    let rows = match &requirement {
        Some(requirement) => state.policy.accepted(requirement, &req.people).await,
        None => Ok(None),
    };
    match rows {
        Ok(Some(accepted)) => Json(MatchResponse { accepted }).into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, "No requirements to match against").into_response(),
        Err(e) => {
            tracing::warn!("Matching a requirement failed: {e}");
            (StatusCode::SERVICE_UNAVAILABLE, "Policy engine unavailable").into_response()
        }
    }
}

async fn stream_logs_handler(
    Path(id): Path<String>,
    State(state): State<AgentState>,
    ConnectInfo(addr): ConnectInfo<crate::tls::PeerAddr>,
    headers: axum::http::HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    const EVENT: &str = "execution_log_access";

    // Path traversal guard: only allow canonical UUIDs through.
    if uuid::Uuid::parse_str(&id).is_err() {
        audit_view(&state, &addr, EVENT, "deny", "Invalid log id", "unauthenticated", None);
        return (axum::http::StatusCode::BAD_REQUEST, "Invalid log id").into_response();
    }
    let exec_info = Some(serde_json::json!({ "execution_id": id }));

    // Execution output can contain anything the command printed, so it gets
    // the same bearer-token + policy gate as file streaming.
    let (claims, user) = match authenticate_viewer(&state, &addr, &headers, EVENT, exec_info.clone()).await {
        Ok(v) => v,
        Err(response) => return *response,
    };

    let allowed = policy_allows(
        &state,
        &crate::policy::ViewInput::ViewExecution {
            viewer: crate::policy::Identity {
                username: user.clone(),
                claims,
            },
            execution_id: id.to_string(),
        },
    ).await;
    if !allowed {
        audit_view(&state, &addr, EVENT, "deny", "Denied by policy", &user, exec_info);
        return (axum::http::StatusCode::FORBIDDEN, "Denied by policy").into_response();
    }
    audit_view(&state, &addr, EVENT, "allow", "Execution Log Stream Started", &user, exec_info);

    let log_path = PathBuf::from(&state.config.logs_dir).join(format!("{}.log", id));
    ws.on_upgrade(move |socket| tail_file(socket, log_path, None))
}

/// Extract `Authorization: Bearer <token>`. Tokens are never accepted in the
/// query string: URLs end up in logs, proxies and error messages.
fn bearer_token(headers: &axum::http::HeaderMap) -> Option<String> {
    headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty())
}

/// Ask policy about a viewing action. A policy that fails to evaluate
/// denies (and is logged).
async fn policy_allows(state: &AgentState, input: &crate::policy::ViewInput) -> bool {
    state.policy.allows_viewing(input).await.unwrap_or_else(|e| {
        tracing::warn!("Policy evaluation failed: {e}");
        false
    })
}

/// The files this agent will show. Like the catalog, it says what the
/// machine offers, so the same `view_docs` decision covers it.
async fn list_files_handler(
    State(state): State<AgentState>,
    ConnectInfo(addr): ConnectInfo<crate::tls::PeerAddr>,
    headers: axum::http::HeaderMap,
) -> Response {
    const EVENT: &str = "file_list_access";
    let (claims, user) = match authenticate_viewer(&state, &addr, &headers, EVENT, None).await {
        Ok(v) => v,
        Err(response) => return *response,
    };
    if let Err(response) = require_view_docs(&state, &addr, EVENT, claims, &user).await {
        return *response;
    }
    audit_view(&state, &addr, EVENT, "allow", "File list served", &user, None);
    Json(files::list_available_files(&state.config.files)).into_response()
}

#[derive(Deserialize)]
struct StreamFileParams {
    name: Option<String>,
    path: Option<String>,
    #[serde(default = "default_tail_lines")]
    tail_lines: Option<usize>,
}

fn default_tail_lines() -> Option<usize> {
    Some(1000)
}

async fn stream_file_handler(
    State(state): State<AgentState>,
    ConnectInfo(addr): ConnectInfo<crate::tls::PeerAddr>,
    headers: axum::http::HeaderMap,
    Query(params): Query<StreamFileParams>,
    ws: WebSocketUpgrade,
) -> Response {
    let log_audit = |decision: &'static str,
                     reason: String,
                     user: String,
                     file_info: Option<serde_json::Value>| {
        crate::audit::log_audit(
            decision,
            reason,
            user,
            addr.ip_string(),
            state.hostname.clone(),
            crate::audit::AuditContext {
                file: file_info,
                ..Default::default()
            },
        );
    };

    // 1. Verify Token via shared helper.
    let Some(token) = bearer_token(&headers) else {
        log_audit("deny", "Missing bearer token".into(), "unknown".into(), None);
        return (axum::http::StatusCode::UNAUTHORIZED, "Missing bearer token").into_response();
    };
    let claims = match verify_query_token(&token, &state).await {
        Ok(c) => c,
        Err((status, msg)) => {
            log_audit("deny", msg.into(), "unknown".into(), None);
            return (status, msg).into_response();
        }
    };

    let user = claims
        .get("username")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();

    // 2. Resolve File
    let identifier = if let Some(name) = &params.name {
        files::FileIdentifier::Name(name.clone())
    } else if let Some(path) = &params.path {
        files::FileIdentifier::Path(path.clone())
    } else {
        log_audit("deny", "Missing name or path".into(), user.clone(), None);
        return (axum::http::StatusCode::BAD_REQUEST, "Missing name or path").into_response();
    };

    let mut file_info_json = match &identifier {
        files::FileIdentifier::Name(n) => serde_json::json!({ "name": n }),
        files::FileIdentifier::Path(p) => serde_json::json!({ "path": p }),
    };

    let file_path = match files::resolve_file_path(&state.config.files, &identifier) {
        Some(p) => p,
        None => {
             log_audit("deny", "File Access Denied (Not Allowed)".into(), user.clone(), Some(file_info_json));
             return (axum::http::StatusCode::FORBIDDEN, "File Access Denied").into_response();
        }
    };
    // What was asked for can be spelled many ways (`..`, relative paths);
    // policy and the audit log also get the one file it resolved to, as
    // the file list shows it.
    file_info_json["resolved_path"] = serde_json::Value::String(file_path.to_string_lossy().into_owned());

    // 3. Check OPA
    let allowed = policy_allows(
        &state,
        &crate::policy::ViewInput::ReadFile {
            viewer: crate::policy::Identity {
                username: claims_username(&claims),
                claims: claims.clone(),
            },
            file: file_info_json.clone(),
        },
    ).await;
    if !allowed {
         log_audit("deny", "Denied by policy".into(), user.clone(), Some(file_info_json));
         return (axum::http::StatusCode::FORBIDDEN, "Denied by policy").into_response();
    }

    log_audit("allow", "File Stream Started".into(), user.clone(), Some(file_info_json));

    // 4. Stream/Tail
    ws.on_upgrade(move |socket| tail_file(socket, file_path, params.tail_lines))
}

async fn tail_file(mut socket: WebSocket, path: PathBuf, tail_lines: Option<usize>) {
    // Wait for file to exist? (Only if it's potentially created soon, like logs. For generic files, maybe we error if not found?)
    // Reusing log logic which waits.
    let mut attempts = 0;
    while !path.exists() && attempts < 10 {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        attempts += 1;
    }

    if !path.exists() {
        let _ = socket.send(Message::Text("File not found".into())).await;
        return;
    }

    let mut file = match tokio::fs::File::open(&path).await {
        Ok(f) => f,
        Err(_) => {
            let _ = socket.send(Message::Text("Failed to open file".into())).await;
            return;
        }
    };

    // Start near the end: roughly the last `tail_lines` lines, estimated at
    // 200 bytes each rather than counted, so the first line sent may be a
    // partial one. If seeking fails, the stream starts from the top.
    if let Some(n) = tail_lines {
        let len = file.metadata().await.map(|m| m.len()).unwrap_or(0);
        let wanted = u64::try_from(n).unwrap_or(u64::MAX).saturating_mul(200);
        let _ = file.seek(std::io::SeekFrom::Start(len.saturating_sub(wanted))).await;
    }

    // Stream until the client goes away. Watching the socket matters: at EOF
    // we otherwise only sleep and re-read, never send, and so would never
    // notice a disconnect — leaking the task and the file handle forever.
    let mut buf = [0u8; 1024];
    loop {
        tokio::select! {
            msg = socket.recv() => match msg {
                Some(Ok(Message::Close(_))) | Some(Err(_)) | None => break,
                Some(Ok(_)) => {}
            },
            r = file.read(&mut buf) => {
                let n = match r {
                    Ok(n) => n,
                    Err(_) => break,
                };
                if n > 0 {
                    let s = String::from_utf8_lossy(&buf[..n]).to_string();
                    if socket.send(Message::Text(s.into())).await.is_err() {
                        break;
                    }
                } else {
                    // EOF: wait for more output, but keep listening for close.
                    tokio::select! {
                        _ = tokio::time::sleep(std::time::Duration::from_millis(200)) => {}
                        msg = socket.recv() => match msg {
                            Some(Ok(Message::Close(_))) | Some(Err(_)) | None => break,
                            Some(Ok(_)) => {}
                        },
                    }
                }
            }
        }
    }
}
