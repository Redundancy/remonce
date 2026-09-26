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

/// Verify an OIDC JWT against the agent's pinned JWKS. Used by the
/// `/api/files` and `/api/files/stream` endpoints, where the bearer token
/// is the only auth (we don't have a session). Returns the JWT claims.
///
/// Note: this is bearer-token auth and intentionally does NOT enforce the
/// nonce-binding to an ephemeral key (that's the approver/operator path
/// in `security::verify_execution`). A leaked ID token grants file-read
/// until it expires; mitigate via short JWT lifetimes and dedicated
/// clientID.
fn verify_query_token(
    token: &str,
    jwks: &jsonwebtoken::jwk::JwkSet,
    issuer: &str,
    audience: &str,
) -> Result<serde_json::Value, (axum::http::StatusCode, &'static str)> {
    use axum::http::StatusCode;
    let header = jsonwebtoken::decode_header(token)
        .map_err(|_| (StatusCode::UNAUTHORIZED, "Invalid Token Header"))?;
    let kid = header
        .kid
        .ok_or((StatusCode::UNAUTHORIZED, "Missing KID"))?;
    let jwk = jwks
        .find(&kid)
        .ok_or((StatusCode::UNAUTHORIZED, "Unknown Key"))?;
    let decoding_key = jsonwebtoken::DecodingKey::from_jwk(jwk)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Key Error"))?;
    let mut validation = jsonwebtoken::Validation::new(header.alg);
    validation.set_audience(&[audience]);
    validation.set_issuer(&[issuer]);
    let token_data = jsonwebtoken::decode::<serde_json::Value>(token, &decoding_key, &validation)
        .map_err(|_| (StatusCode::UNAUTHORIZED, "Invalid Token"))?;
    Ok(token_data.claims)
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
    pub message: String,
    pub execution_time: Option<String>,
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

pub async fn run(insecure: bool) -> Result<(), Box<dyn std::error::Error>> {
    // 1. Load Config (Reuse web::Config for simplicity)
    let config_str = std::fs::read_to_string("config.toml")?;
    let config: Config = toml::from_str(&config_str)?;

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

async fn execute_handler(
    State(state): State<AgentState>,
    ConnectInfo(addr): ConnectInfo<crate::tls::PeerAddr>,
    Json(bundle): Json<crate::security::ExecutionBundle>,
) -> Result<Json<ExecutionResponse>, ErrorResponse> {
    use crate::audit::AuditContext;

    let ip = addr.ip_string();
    let hostname = state.hostname.clone();
    let command_json = bundle.approver.command.clone();

    let audit_ctx_basic = || AuditContext {
        command: Some(command_json.clone()),
        ..Default::default()
    };

    tracing::info!("Verifying execution bundle");

    // 1. Resolve the command config up front so per-command validity windows
    //    can feed into `verify_execution`.
    let command_name = match command_json.get("command").and_then(|v| v.as_str()) {
        Some(s) => s.to_string(),
        None => {
            crate::audit::log_audit(
                "deny",
                "Invalid command format: Missing 'command' field".into(),
                "unauthenticated".into(),
                ip.clone(),
                hostname.clone(),
                audit_ctx_basic(),
            );
            return Err(ErrorResponse {
                error: "Invalid Request".into(),
            });
        }
    };

    let cmd_config = match state.config.commands.iter().find(|c| c.name == command_name) {
        Some(c) => c.clone(),
        None => {
            crate::audit::log_audit(
                "deny",
                format!("Command '{}' not found in agent configuration", command_name),
                "unauthenticated".into(),
                ip.clone(),
                hostname.clone(),
                audit_ctx_basic(),
            );
            return Err(ErrorResponse {
                error: "Invalid Request".into(),
            });
        }
    };

    let operator_max = cmd_config.operator_max_validity_or_default();
    let approver_max = cmd_config.approver_max_validity_or_default();

    // 2. Cryptographic + freshness + claim-predicate verification.
    let verifier_config = crate::security::VerifierConfig {
        client_id: state.config.oidc.client_id.clone(),
        issuer_url: state.config.oidc.issuer_url.clone(),
        jwks: state.jwks.clone(),
        trusted_roots: state.trusted_roots.clone(),
        approver_max_validity: operator_max, // unused for self-exec; kept for symmetry
        operator_max_validity: operator_max,
    };
    // We verify with operator_max_validity reflecting the short window; approver_max_validity
    // needs to come from cmd_config:
    let verifier_config = crate::security::VerifierConfig {
        approver_max_validity: approver_max,
        ..verifier_config
    };

    let authz = match crate::security::verify_execution(&bundle, &verifier_config) {
        Ok(a) => a,
        Err(e) => {
            crate::audit::log_audit(
                "deny",
                format!("Verification failed: {}", e),
                "unauthenticated".into(),
                ip.clone(),
                hostname.clone(),
                audit_ctx_basic(),
            );
            return Err(ErrorResponse {
                error: "Verification Failed".into(),
            });
        }
    };

    let approver_user = authz.approver.username.clone();
    let operator_user = authz.operator.username.clone();
    let approver_signed_at = authz
        .approver
        .signed_at
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "unknown_time".to_string());
    let operator_signed_at = authz
        .operator
        .signed_at
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "unknown_time".to_string());

    let full_ctx = || AuditContext {
        signed_at: Some(approver_signed_at.clone()),
        command: Some(command_json.clone()),
        operator_user: Some(operator_user.clone()),
        operator_signed_at: Some(operator_signed_at.clone()),
        self_executed: Some(authz.self_executed),
        ..Default::default()
    };

    // 3. Revocation check — the approver's signature may have been revoked
    //    after the bundle was issued. Local cache first, then the central
    //    revocation service (fail-closed) if one is configured.
    if state.revocations.is_revoked(&bundle.approver.signature) {
        crate::audit::log_audit(
            "deny",
            "Approval has been revoked".into(),
            approver_user.clone(),
            ip.clone(),
            hostname.clone(),
            full_ctx(),
        );
        return Err(ErrorResponse {
            error: "Approval Revoked".into(),
        });
    }

    if let Some((client, base)) = &state.revocation_service {
        match check_revocation_service(client, base, &bundle.approver.signature).await {
            Ok(false) => {}
            Ok(true) => {
                crate::audit::log_audit(
                    "deny",
                    "Approval has been revoked (revocation service)".into(),
                    approver_user.clone(),
                    ip.clone(),
                    hostname.clone(),
                    full_ctx(),
                );
                return Err(ErrorResponse {
                    error: "Approval Revoked".into(),
                });
            }
            Err(e) => {
                // Fail-closed: a configured revocation service must be
                // available, otherwise we cannot know the approval is live.
                crate::audit::log_audit(
                    "error",
                    format!("Revocation service check failed: {}", e),
                    approver_user.clone(),
                    ip.clone(),
                    hostname.clone(),
                    full_ctx(),
                );
                return Err(ErrorResponse {
                    error: "Revocation Check Failed".into(),
                });
            }
        }
    }

    // 4. Command-level constraints (target machines, not_before/not_after,
    //    declared parameters). The replay check comes last, just before
    //    spawning, so a rejection here doesn't burn the signature.
    let now = time::OffsetDateTime::now_utc();

    let target_machines = command_json
        .get("target_machines")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect::<Vec<_>>()
        });

    // A time bound that is present but unparsable must deny, not vanish:
    // the approver believes the command is time-limited.
    let (not_before, not_after) = match (
        parse_time_bound(&command_json, "not_before"),
        parse_time_bound(&command_json, "not_after"),
    ) {
        (Ok(nbf), Ok(naf)) => (nbf, naf),
        (Err(field), _) | (_, Err(field)) => {
            crate::audit::log_audit(
                "deny",
                format!("Malformed '{}' (expected an RFC 3339 string)", field),
                approver_user.clone(),
                ip.clone(),
                hostname.clone(),
                full_ctx(),
            );
            return Err(ErrorResponse {
                error: "Invalid Time Constraint".into(),
            });
        }
    };

    let targets = match target_machines {
        Some(t) => t,
        None => {
            crate::audit::log_audit(
                "deny",
                "Missing mandatory 'target_machines' field".into(),
                approver_user.clone(),
                ip.clone(),
                hostname.clone(),
                full_ctx(),
            );
            return Err(ErrorResponse {
                error: "Missing Target Restriction".into(),
            });
        }
    };

    if !targets.contains(&hostname) {
        crate::audit::log_audit(
            "deny",
            format!("Hostname '{}' not in target list '{:?}'", hostname, targets),
            approver_user.clone(),
            ip.clone(),
            hostname.clone(),
            full_ctx(),
        );
        return Err(ErrorResponse {
            error: format!("Target Machine Mismatch ({} not in {:?})", hostname, targets),
        });
    }

    if let Some(nbf) = not_before {
        if now < nbf {
            crate::audit::log_audit(
                "deny",
                format!("Command not yet valid (nbf: {}, now: {})", nbf, now),
                approver_user.clone(),
                ip.clone(),
                hostname.clone(),
                full_ctx(),
            );
            return Err(ErrorResponse {
                error: format!("Command Not Yet Valid (Starts at {})", nbf),
            });
        }
    }

    if let Some(exp) = not_after {
        if now > exp {
            crate::audit::log_audit(
                "deny",
                format!("Command expired (not_after: {}, now: {})", exp, now),
                approver_user.clone(),
                ip.clone(),
                hostname.clone(),
                full_ctx(),
            );
            return Err(ErrorResponse {
                error: format!("Command Expired (Expired at {})", exp),
            });
        }
    }

    // Validate signed params against the command's declarations and render
    // the args template. Fail-closed: any violation rejects the execution.
    let resolved_params =
        match crate::params::validate_params(&cmd_config, command_json.get("params")) {
            Ok(r) => r,
            Err(e) => {
                crate::audit::log_audit(
                    "deny",
                    format!("Parameter validation failed: {}", e),
                    approver_user.clone(),
                    ip.clone(),
                    hostname.clone(),
                    full_ctx(),
                );
                return Err(ErrorResponse {
                    error: "Invalid Parameters".into(),
                });
            }
        };

    let rendered_args = match crate::params::render_args(&cmd_config.args, &resolved_params) {
        Ok(a) => a,
        Err(e) => {
            crate::audit::log_audit(
                "deny",
                format!("Argument rendering failed: {}", e),
                approver_user.clone(),
                ip.clone(),
                hostname.clone(),
                full_ctx(),
            );
            return Err(ErrorResponse {
                error: "Invalid Parameters".into(),
            });
        }
    };

    // 5. OPA authorization with both identities.
    let opa_input = crate::opa::OpaInput {
        action: "execute".into(),
        command: command_json.clone(),
        approver: crate::opa::SignerContext {
            username: approver_user.clone(),
            claims: authz.approver.claims.clone(),
            signed_at: approver_signed_at.clone(),
        },
        operator: crate::opa::SignerContext {
            username: operator_user.clone(),
            claims: authz.operator.claims.clone(),
            signed_at: operator_signed_at.clone(),
        },
        self_executed: authz.self_executed,
        host: hostname.clone(),
    };

    let decision = crate::opa::check_authorization(
        &state.http_client,
        &state.config.opa_url,
        &cmd_config.opa_rule,
        opa_input,
    )
    .await
    .map_err(|e| {
        crate::audit::log_audit(
            "error",
            format!("OPA evaluation failed: {}", e),
            approver_user.clone(),
            ip.clone(),
            hostname.clone(),
            full_ctx(),
        );
        ErrorResponse {
            error: "Internal Error".into(),
        }
    })?;

    if !decision.allow {
        crate::audit::log_audit(
            "deny",
            decision.reason.clone(),
            approver_user.clone(),
            ip.clone(),
            hostname.clone(),
            full_ctx(),
        );
        return Err(ErrorResponse {
            error: "Authorization Denied".into(),
        });
    }

    // 6. Replay check — executor signature (operator if delegated, else
    //    approver). The entry must outlive every way the signature could
    //    still pass freshness, including re-timestamping up to token expiry.
    let replay_ttl: std::time::Duration = (authz.operator.usable_until(operator_max)
        - time::OffsetDateTime::now_utc())
    .try_into()
    .unwrap_or(operator_max)
    .max(operator_max);
    if state
        .replay_cache
        .check_and_insert(&authz.executor_signature_hex, replay_ttl)
        .is_err()
    {
        crate::audit::log_audit(
            "deny",
            "Replay detected: executor signature already used".into(),
            approver_user.clone(),
            ip.clone(),
            hostname.clone(),
            full_ctx(),
        );
        return Err(ErrorResponse {
            error: "Replay Detected".into(),
        });
    }
    // Released again if we fail before the process actually starts.
    let release_replay = || state.replay_cache.release(&authz.executor_signature_hex);

    // Preserve legacy locals used below.
    let authenticated_user = approver_user.clone();
    let gen_time_str = approver_signed_at.clone();
    let signed_at_str = Some(gen_time_str.clone());
    let req_command = command_json.clone();

    // 5. Execute Command
    let executable = cmd_config
        .executable
        .clone()
        .unwrap_or_else(|| command_name.to_string());

    // execution_id forms the log filename, so we must reject anything that
    // isn't a canonical UUID — otherwise a signed payload could path-traverse
    // out of `logs_dir`.
    let mut execution_id = req_command
        .get("id")
        .and_then(|v| v.as_str())
        .and_then(|s| uuid::Uuid::parse_str(s).ok().map(|u| u.to_string()))
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

    // Prepare Log File
    let logs_dir = PathBuf::from(&state.config.logs_dir);
    if !logs_dir.exists() {
        tokio::fs::create_dir_all(&logs_dir).await.map_err(|e| {
            release_replay();
            crate::audit::log_audit(
                "error",
                format!("Failed to create logs dir: {}", e),
                authenticated_user.clone(),
                ip.clone(),
                hostname.clone(),
                full_ctx(),
            );
            ErrorResponse {
                error: "Internal Error".into(),
            }
        })?;
    }

    // `create_new`: one approval can legitimately run several times (e.g.
    // multiple operator cosigns), and each run must keep its own log. If the
    // signed id is taken, fall back to a fresh one.
    let open_new = |path: PathBuf| async move {
        tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .await
    };
    let mut log_path = logs_dir.join(format!("{}.log", execution_id));
    let first_try = open_new(log_path.clone()).await;
    let log_result = match first_try {
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            execution_id = uuid::Uuid::new_v4().to_string();
            log_path = logs_dir.join(format!("{}.log", execution_id));
            open_new(log_path.clone()).await
        }
        other => other,
    };
    let mut log_file = log_result.map_err(|e| {
        release_replay();
        crate::audit::log_audit(
            "error",
            format!("Failed to create log file: {}", e),
            authenticated_user.clone(),
            ip.clone(),
            hostname.clone(),
            full_ctx(),
        );
        ErrorResponse {
            error: "Internal Error".into(),
        }
    })?;

    tracing::info!(
        "Executing command '{}' with ID {}",
        command_name,
        execution_id
    );

    // Write Audit Header
    let header = format!(
        "--- EXECUTION LOG ---\nID: {}\nUser: {}\nTime: {}\nCommand: {}\nExecutable: {} {}\n---------------------\n",
        execution_id,
        authenticated_user,
        gen_time_str,
        command_name,
        executable,
        rendered_args.join(" ")
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
        crate::audit::log_audit(
            "error",
            format!("Failed to spawn command: {}", e),
            authenticated_user.clone(),
            ip.clone(),
            hostname.clone(),
            full_ctx(),
        );
        ErrorResponse {
            error: "Execution Failed".into(),
        }
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

    crate::audit::log_audit(
        "allow",
        "Command Started".to_string(),
        authenticated_user.clone(),
        ip.clone(),
        hostname.clone(),
        full_ctx(),
    );
    let _ = signed_at_str;

    Ok(Json(ExecutionResponse {
        status: "authorized".to_string(),
        // Return the UUID here so client knows what to stream
        message: execution_id.clone(),
        execution_time: Some(gen_time_str),
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

/// Query the central revocation service for `sig_hex`. Any transport or
/// protocol error is surfaced to the caller, which treats it as fatal
/// (fail-closed).
async fn check_revocation_service(
    client: &Client,
    base: &url::Url,
    sig_hex: &str,
) -> Result<bool, String> {
    let url = base
        .join(&format!("revoked/{}", sig_hex))
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

/// Revoke an approver bundle. The revoker submits the full approver bundle
/// plus a fresh, nonce-bound attestation signing the domain-separated
/// revocation payload. Authorized when the revoker is the original approver
/// (same OIDC `sub`) or when OPA allows `action = "revoke"`. Idempotent.
/// When a central revocation service is configured, the bundle is also
/// forwarded there so the revocation takes effect estate-wide.
async fn revoke_handler(
    State(state): State<AgentState>,
    ConnectInfo(addr): ConnectInfo<crate::tls::PeerAddr>,
    Json(req): Json<crate::security::RevocationBundle>,
) -> Result<Json<RevocationResponse>, ErrorResponse> {
    use crate::audit::AuditContext;

    let ip = addr.ip_string();
    let hostname = state.hostname.clone();
    let command_json = req.approver.command.clone();

    let ctx = crate::revocation::RevocationCtx {
        config: &state.config,
        jwks: &state.jwks,
        trusted_roots: &state.trusted_roots,
        http_client: &state.http_client,
        hostname: &hostname,
        min_approver_validity: None,
        allow_unknown_commands: false,
    };

    let verified = crate::revocation::verify_and_authorize(&ctx, &req, &ip)
        .await
        .map_err(|e| ErrorResponse { error: e.into() })?;
    let revocation = &verified.authorized;

    let revoker_user = revocation.revoker.username.clone();
    let approver_user = revocation.approver.username.clone();

    let revoke_ctx = || AuditContext {
        event_type: Some("approval_revocation"),
        command: Some(command_json.clone()),
        operator_user: Some(approver_user.clone()),
        ..Default::default()
    };

    // Pin the revocation until the approval would have expired anyway —
    // allowing for the approval being re-timestamped up to its token expiry.
    let now = time::OffsetDateTime::now_utc();
    let expiry = revocation
        .approver
        .usable_until(verified.approver_max_validity);
    if expiry > now {
        let remaining: std::time::Duration =
            (expiry - now).try_into().unwrap_or_default();
        state
            .revocations
            .revoke(&revocation.approver_signature_hex, remaining);
    }

    // Forward to the central revocation service so a single submission
    // covers the whole estate. The local pin above stands either way.
    let mut message = "Approval revoked on this agent".to_string();
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
                format!(
                    "Revocation pinned locally but forwarding to revocation service failed: {}",
                    e
                ),
                revoker_user.clone(),
                ip.clone(),
                hostname.clone(),
                revoke_ctx(),
            );
            return Err(ErrorResponse {
                error: "Revocation Service Unavailable (revoked on this agent only)".into(),
            });
        }
        message = "Approval revoked on this agent and the revocation service".to_string();
    }

    crate::audit::log_audit(
        "allow",
        format!(
            "Approval by '{}' revoked by '{}'{}",
            approver_user,
            revoker_user,
            if revocation.self_revoked { " (self)" } else { "" }
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
    let claims = match verify_query_token(
        &token,
        &state.jwks,
        &state.config.oidc.issuer_url,
        &state.config.oidc.client_id,
    ) {
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
    match verify_query_token(
        &token,
        &state.jwks,
        &state.config.oidc.issuer_url,
        &state.config.oidc.client_id,
    ) {
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
    let claims = match verify_query_token(
        &token,
        &state.jwks,
        &state.config.oidc.issuer_url,
        &state.config.oidc.client_id,
    ) {
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
