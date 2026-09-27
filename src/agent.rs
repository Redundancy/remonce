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
use crate::web::OidcMetadata;
use crate::files;
use tower_http::cors::CorsLayer;

#[derive(Clone)]
pub struct AgentState {
    pub http_client: Client,
    pub config: Config,
    #[allow(dead_code)]
    pub oidc_metadata: OidcMetadata,
    pub jwks: jsonwebtoken::jwk::JwkSet,
    pub hostname: String,
    pub trusted_roots: Vec<Vec<u8>>,
    pub replay_cache: crate::replay::ReplayCache,
    pub revocations: crate::replay::RevocationCache,
    /// Central revocation service (client, base URL). When set, every
    /// execution checks it and FAILS CLOSED if it is unreachable.
    pub revocation_service: Option<(Client, url::Url)>,
}

// ExecutionRequest is imported from security module

/// Verify a viewer bearer token against the agent's pinned JWKS. Used by
/// `/api/files`, `/api/files/stream` and `/stream/{id}`, where the bearer
/// token is the only auth. Returns the JWT claims.
///
/// Only tokens for the *viewer* client are accepted (strict audience), so a
/// signing token — including an approver's token carried inside a delegated
/// bundle — can never be used to browse. Without `viewer_client_id` the
/// endpoints are disabled.
fn verify_query_token(
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
    crate::security::verify_bearer_token(token, &state.jwks, &state.config.oidc.issuer_url, viewer)
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

    let http_client = crate::http_client();

    // 2. Fetch OIDC Metadata and Keys (Agent needs to verify JWTs)
    let discovery_url = format!("{}/.well-known/openid-configuration", config.oidc.issuer_url);
    let discovery: OidcMetadata = http_client.get(&discovery_url).send().await?.json().await?;
    let jwks = http_client
        .get(&discovery.jwks_uri)
        .send()
        .await?
        .json()
        .await?;

    // 3. Load TSA Trusted Roots
    let trusted_roots = crate::tsa::load_trust_anchors(
        config.timestamp_authority.ca_path.as_deref(),
        config.timestamp_authority.trust_system_store,
    );
    tracing::info!("Loaded {} trusted TSA roots", trusted_roots.len());

    if config.oidc.viewer_client_id.is_none() {
        return Err("oidc.viewer_client_id must be set: executors, file and log viewing, and the command catalog                     all authenticate with viewer-client logins"
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

    let state = AgentState {
        http_client,
        config,
        oidc_metadata: discovery,
        jwks,
        hostname,
        trusted_roots,
        replay_cache: crate::replay::ReplayCache::new(),
        revocations: crate::replay::RevocationCache::new(),
        revocation_service,
    };

    let mut app = Router::new()
        .route("/execute", post(execute_handler))
        .route("/revoke", post(revoke_handler))
        .route("/api/commands", get(catalog_handler))
        .route("/stream/{id}", get(stream_logs_handler))
        .route("/api/files", get(list_files_handler))
        .route("/api/files/stream", get(stream_file_handler))
        .with_state(state);

    if !agent_config.cors_allowed_origins.is_empty() {
        use tower_http::cors::AllowOrigin;
        use axum::http::HeaderValue;
        let origins: Vec<HeaderValue> = agent_config
            .cors_allowed_origins
            .iter()
            .filter_map(|o| HeaderValue::from_str(o).ok())
            .collect();
        app = app.layer(
            CorsLayer::new()
                .allow_origin(AllowOrigin::list(origins))
                .allow_headers(tower_http::cors::Any)
                .allow_methods(tower_http::cors::Any),
        );
    }

    let addr: SocketAddr = agent_config
        .listen_address
        .parse()
        .map_err(|e| format!("Invalid agent.listen_address: {e}"))?;
    tracing::info!(event = "tcp_listen", address = %addr, tls_mode = ?agent_config.tls, "Agent listening (TLS)");

    let listener = TcpListener::bind(&addr).await?;
    crate::tls::serve_with_tls(listener, app, &agent_config.tls)
        .await
        .map_err(|e| -> Box<dyn std::error::Error> { e.to_string().into() })?;

    Ok(())
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
/// command's own constraints, revocation, policy (published requirements +
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
    let executor_claims = verify_query_token(&token, &state).map_err(|(status, msg)| {
        audit("deny", format!("Executor token rejected: {msg}"), "unauthenticated", AuditContext::default());
        ErrorResponse::new(status, msg)
    })?;
    let executor = crate::opa::Identity {
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
    let verifier_config = crate::security::VerifierConfig {
        client_id: state.config.oidc.client_id.clone(),
        issuer_url: state.config.oidc.issuer_url.clone(),
        jwks: state.jwks.clone(),
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
    let input = crate::opa::OpaInput::Execute {
        command: command_json.clone(),
        request_id: request_id.clone(),
        approvers: approvers
            .iter()
            .map(|a| crate::opa::Signer {
                username: a.username.clone(),
                claims: a.claims.clone(),
                signed_at: rfc3339(a.signed_at),
            })
            .collect(),
        executor,
        host: hostname.clone(),
    };
    let decision = crate::opa::check_authorization(&state.http_client, &state.config.opa_url, &cmd_config.opa_rule, &input)
        .await
        .map_err(|e| {
            audit("error", format!("OPA evaluation failed: {e}"), &user, full_ctx());
            ErrorResponse::new(StatusCode::SERVICE_UNAVAILABLE, "Policy engine unavailable")
        })?;
    if !decision.allow {
        audit("deny", decision.reason.clone(), &user, full_ctx());
        return Err(ErrorResponse::new(
            StatusCode::FORBIDDEN,
            format!("Authorization Denied: {}", decision.reason),
        ));
    }

    // 8. Replay: one run per request. Remembered past every approval that
    //    could exist now; released if we fail before the process starts.
    let ttl = crate::security::replay_ttl(now, &approvers, validity);
    if state.replay_cache.check_and_insert(&request_id, ttl).is_err() {
        audit("deny", "Replay: request already executed".into(), &user, full_ctx());
        return Err(ErrorResponse::new(
            StatusCode::CONFLICT,
            "This request has already been executed on this agent",
        ));
    }
    let release_replay = || state.replay_cache.release(&request_id);

    // 9. Run it.
    let executable = cmd_config.executable.clone().unwrap_or_else(|| command_name.clone());
    let started = rfc3339(time::OffsetDateTime::now_utc());

    let logs_dir = PathBuf::from(&state.config.logs_dir);
    if !logs_dir.exists() {
        tokio::fs::create_dir_all(&logs_dir).await.map_err(|e| {
            release_replay();
            audit("error", format!("Failed to create logs dir: {e}"), &user, full_ctx());
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
        audit("error", format!("Failed to create log file: {e}"), &user, full_ctx());
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
    //   - wall-clock timeout enforced via tokio::time::timeout + child.kill()
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

    let mut child = spawn_cmd.spawn().map_err(|e| {
        release_replay();
        audit("error", format!("Failed to spawn command: {e}"), &user, full_ctx());
        ErrorResponse::new(StatusCode::INTERNAL_SERVER_ERROR, "Execution Failed")
    })?;

    // Pipe Output and enforce timeout in a background task.
    let stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();
    let exec_id_for_log = execution_id.clone();
    let log_path_for_task = log_path.clone();

    tokio::spawn(async move {
        let mut stdout_reader = tokio::io::BufReader::new(stdout);
        let mut stderr_reader = tokio::io::BufReader::new(stderr);

        let (tx, mut rx) = tokio::sync::mpsc::channel::<String>(100);
        let tx2 = tx.clone();

        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            loop {
                let n = stdout_reader.read(&mut buf).await.unwrap_or(0);
                if n == 0 {
                    break;
                }
                let s = String::from_utf8_lossy(&buf[..n]).to_string();
                let _ = tx.send(s).await;
            }
        });

        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            loop {
                let n = stderr_reader.read(&mut buf).await.unwrap_or(0);
                if n == 0 {
                    break;
                }
                let s = String::from_utf8_lossy(&buf[..n]).to_string();
                let _ = tx2.send(s).await;
            }
        });

        // Pipe writer (terminates when both pump tasks drop their senders).
        // Runs as its own task so output drains while the child runs; if it
        // only ran after exit, a full channel would stall the child's pipes.
        let mut writer = tokio::spawn(async move {
            let mut file_out = log_file;
            while let Some(msg) = rx.recv().await {
                let _ = file_out.write_all(msg.as_bytes()).await;
                let _ = file_out.flush().await;
            }
            file_out
        });

        // Race the child's exit against the timeout. If the timer fires first,
        // SIGKILL the child and continue draining its remaining output.
        let wait_result = tokio::select! {
            r = child.wait() => Some(r),
            _ = tokio::time::sleep(timeout) => {
                tracing::warn!(
                    "Command {} exceeded timeout ({:?}); killing",
                    exec_id_for_log, timeout
                );
                let _ = child.kill().await;
                None
            }
        };

        // Grandchildren that inherited stdout/stderr keep the pipes open
        // after the direct child exits or is killed, so bound the drain and
        // reopen the log to write the trailer if we had to give up on it.
        let mut file_out = match tokio::time::timeout(LOG_DRAIN_TIMEOUT, &mut writer).await {
            Ok(Ok(f)) => f,
            _ => {
                writer.abort();
                tracing::warn!(
                    "Command {}: output still open {:?} after exit (orphaned child processes?)",
                    exec_id_for_log,
                    LOG_DRAIN_TIMEOUT
                );
                match tokio::fs::OpenOptions::new()
                    .append(true)
                    .open(&log_path_for_task)
                    .await
                {
                    Ok(f) => f,
                    Err(e) => {
                        tracing::error!("Failed to reopen log for trailer: {}", e);
                        return;
                    }
                }
            }
        };
        match wait_result {
            Some(Ok(status)) => {
                let _ = file_out
                    .write_all(format!("\n--- EXIT: {} ---\n", status).as_bytes())
                    .await;
            }
            Some(Err(e)) => {
                let _ = file_out
                    .write_all(format!("\n--- WAIT ERROR: {} ---\n", e).as_bytes())
                    .await;
            }
            None => {
                let _ = file_out
                    .write_all(b"\n--- TIMEOUT: process killed by agent ---\n")
                    .await;
            }
        }
        let _ = file_out.flush().await;
    });

    audit("allow", "Command Started".to_string(), &user, full_ctx());

    Ok(Json(ExecutionResponse {
        status: "authorized".to_string(),
        // The execution id, which the client streams the log by.
        message: execution_id,
        request_id,
        execution_time: Some(started),
    }))
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

    let ctx = crate::revocation::RevocationCtx {
        config: &state.config,
        jwks: &state.jwks,
        trusted_roots: &state.trusted_roots,
        http_client: &state.http_client,
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
        state.revocations.revoke(&revocation.request_id, remaining);
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

/// The command catalog: what can be requested here and what each command
/// needs (published requirements from OPA). Viewer-token auth; policy
/// decides who may see it.
async fn catalog_handler(State(state): State<AgentState>, headers: axum::http::HeaderMap) -> Response {
    use axum::http::StatusCode;
    let Some(token) = bearer_token(&headers) else {
        return (StatusCode::UNAUTHORIZED, "Missing bearer token").into_response();
    };
    if let Err((status, msg)) = verify_query_token(&token, &state) {
        return (status, msg).into_response();
    }
    match crate::opa::allows_viewing(
        &state.http_client,
        &state.config.opa_url,
        serde_json::json!({ "action": "view_docs", "jwt": token }),
    )
    .await
    {
        Ok(true) => {}
        Ok(false) => {
            return (StatusCode::FORBIDDEN, "Policy does not allow you to view commands").into_response();
        }
        Err(e) => {
            tracing::warn!("OPA view_docs check failed: {e}");
            return (StatusCode::SERVICE_UNAVAILABLE, "Policy engine unavailable").into_response();
        }
    }
    match crate::opa::fetch_requirements(&state.http_client, &state.config.opa_url).await {
        Ok(published) => Json(crate::catalog::build(&state.config, &state.hostname, &published)).into_response(),
        Err(e) => {
            tracing::warn!("Fetching published requirements failed: {e}");
            (StatusCode::SERVICE_UNAVAILABLE, "Could not load published requirements").into_response()
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
    // Path traversal guard: only allow canonical UUIDs through.
    if uuid::Uuid::parse_str(&id).is_err() {
        return (axum::http::StatusCode::BAD_REQUEST, "Invalid log id").into_response();
    }

    // Execution output can contain anything the command printed, so it gets
    // the same bearer-token + OPA gate as file streaming.
    let token = match bearer_token(&headers) {
        Some(t) => t,
        None => return (axum::http::StatusCode::UNAUTHORIZED, "Missing bearer token").into_response(),
    };
    let claims = match verify_query_token(&token, &state) {
        Ok(c) => c,
        Err((status, msg)) => return (status, msg).into_response(),
    };
    let user = claims
        .get("username")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();

    let allowed = opa_allows(
        &state,
        serde_json::json!({ "action": "view_execution", "execution_id": id, "jwt": token }),
    )
    .await;
    let exec_info = Some(serde_json::json!({ "execution_id": id }));
    if !allowed {
        crate::audit::log_audit(
            "deny",
            "Execution log access denied by OPA".into(),
            user,
            addr.ip_string(),
            state.hostname.clone(),
            crate::audit::AuditContext {
                file: exec_info,
                event_type: Some("execution_log_access"),
                ..Default::default()
            },
        );
        return (axum::http::StatusCode::FORBIDDEN, "OPA Denied").into_response();
    }
    crate::audit::log_audit(
        "allow",
        "Execution Log Stream Started".into(),
        user,
        addr.ip_string(),
        state.hostname.clone(),
        crate::audit::AuditContext {
            file: exec_info,
            ..Default::default()
        },
    );

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

/// Ask OPA's `remonce/authz/decision` for a legacy-shape input. Any error
/// (unreachable, malformed response) denies.
async fn opa_allows(state: &AgentState, input: serde_json::Value) -> bool {
    let opa_url = format!("{}/v1/data/remonce/authz/decision", state.config.opa_url);
    let res = state
        .http_client
        .post(&opa_url)
        .json(&serde_json::json!({ "input": input }))
        .send()
        .await;
    let body: serde_json::Value = match res {
        Ok(r) => r.json().await.unwrap_or(serde_json::json!({})),
        Err(e) => {
            tracing::warn!("OPA request failed: {}", e.without_url());
            return false;
        }
    };
    body.pointer("/result/allow")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
}

async fn list_files_handler(
    State(state): State<AgentState>,
    headers: axum::http::HeaderMap,
) -> Response {
    // Same auth posture as `/api/files/stream` — bearer ID token required.
    let Some(token) = bearer_token(&headers) else {
        return (axum::http::StatusCode::UNAUTHORIZED, "Missing bearer token").into_response();
    };
    match verify_query_token(&token, &state) {
        Ok(_claims) => Json(files::list_available_files(&state.config.files)).into_response(),
        Err((status, msg)) => (status, msg).into_response(),
    }
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
    let claims = match verify_query_token(&token, &state) {
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

    let file_info_json = match &identifier {
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

    // 3. Check OPA
    let allowed = opa_allows(
        &state,
        serde_json::json!({ "action": "read_file", "file": file_info_json, "jwt": token }),
    )
    .await;
    if !allowed {
         log_audit("deny", "OPA Denied".into(), user.clone(), Some(file_info_json));
         return (axum::http::StatusCode::FORBIDDEN, "OPA Denied").into_response();
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
    
    // Seek logic for tailing
    if let Some(n) = tail_lines {
        // This is complex for variable length lines.
        // Simplified: read valid utf8 from end?
        // Or just read whole file and take last N lines if file is small?
        // For strict correctness on huge files, we need to seek from end.
        // Let's implement a simple buffer approach: Read entire file (if manageable) or last X bytes.
        // Given complexity, maybe just read from start if not excessively large, or seek to file_len - (avg_line_len * N)?
        
        // Strategy: 
        // 1. Get file size.
        // 2. If small (< 1MB), read all, take last N lines.
        // 3. If large, seek to end - (N * 200 bytes?), read, split lines, take last N.
        
        let len = file.metadata().await.map(|m| m.len()).unwrap_or(0);
        
        // Arbitrary buffer size estimate: 200 chars per line?
        let est_bytes = (n as u64) * 200;
        let start_pos = if len > est_bytes { len - est_bytes } else { 0 };
        
        use std::io::SeekFrom;
        if let Err(_) = file.seek(SeekFrom::Start(start_pos)).await {
            // ignore error, read from start
        }
        
        // We might start in middle of line.
        // Since we are just streaming text, send it? Clients might see partial first line.
        // If we want clean lines, we should read and find first newline.
        // Leaving as simple byte stream for now, client handles display.
        // Wait, current logic sends chunks.
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
