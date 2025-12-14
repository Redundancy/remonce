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
use tower_http::cors::{Any, CorsLayer};

#[derive(Clone)]
pub struct AgentState {
    pub http_client: Client,
    pub config: Config,
    #[allow(dead_code)]
    pub oidc_metadata: OidcMetadata,
    pub jwks: jsonwebtoken::jwk::JwkSet,
    pub hostname: String,
    pub trusted_roots: Vec<Vec<u8>>,
}

// ExecutionRequest is imported from security module

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

pub async fn run() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Load Config (Reuse web::Config for simplicity)
    let config_str = std::fs::read_to_string("config.toml")?;
    let config: Config = toml::from_str(&config_str)?;

    let http_client = Client::new();

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
    let trusted_roots = crate::tsa::load_trust_anchors(config.timestamp_authority.ca_path.as_deref());
    tracing::info!("Loaded {} trusted TSA roots", trusted_roots.len());

    let hostname = hostname::get()
        .map(|h| h.to_string_lossy().into_owned())
        .unwrap_or_else(|_| "unknown".to_string());

    tracing::info!(event = "agent_startup", hostname = %hostname, "Agent starting up");

    let state = AgentState {
        http_client,
        config,
        oidc_metadata: discovery,
        jwks,
        hostname,
        trusted_roots,
    };

    let app = Router::new()
        .route("/execute", post(execute_handler))
        .route("/stream/{id}", get(stream_logs_handler))
        .route("/api/files", get(list_files_handler))
        .route("/api/files/stream", get(stream_file_handler))
        .with_state(state)
        .layer(
            CorsLayer::new()
                .allow_origin(Any) // For local dev, Any is fine. In prod, strict origin.
                .allow_headers(Any)
                .allow_methods(Any),
        );

    let addr = SocketAddr::from(([127, 0, 0, 1], 10022));
    tracing::info!(event = "tcp_listen", address = %addr, "Agent listening");

    let listener = TcpListener::bind(&addr).await?;
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;

    Ok(())
}

async fn execute_handler(
    State(state): State<AgentState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(req): Json<crate::security::ExecutionRequest>,
) -> Result<Json<ExecutionResponse>, ErrorResponse> {
    // Helper to log audit events on exit
    // Helper to log audit events on exit
    let log_audit = |decision: &'static str,
                     reason: String,
                     user: String,
                     signed_at: Option<String>,
                     command: Option<serde_json::Value>| {
        crate::audit::log_audit(
            decision,
            reason,
            user,
            addr.ip().to_string(),
            state.hostname.clone(),
            signed_at,
            command,
            None,
        );
    };

    tracing::info!("Verifying request for command execution");

    // 1. Verify Request via Security Module
    let verifier_config = crate::security::VerifierConfig {
        client_id: state.config.oidc.client_id.clone(),
        issuer_url: state.config.oidc.issuer_url.clone(),
        jwks: state.jwks.clone(),
        trusted_roots: state.trusted_roots.clone(),
    };

    let authorized_user = match crate::security::verify_execution(&req, &verifier_config) {
        Ok(user) => user,
        Err(e) => {
            log_audit(
                "deny",
                format!("Verification failed: {}", e),
                "unauthenticated".into(),
                None, // No signed_at for invalid signature
                Some(req.command.clone()),
            );
            return Err(ErrorResponse {
                error: "Verification Failed".into(),
            });
        }
    };

    let authenticated_user = authorized_user.username;
    let gen_time_str = authorized_user
        .timestamp
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "unknown_time".to_string());
    
    let signed_at_str = Some(gen_time_str.clone());

    // 4. OPA Authorization
    let command_name = match req.command.get("command").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => {
            log_audit(
                "deny",
                "Invalid command format: Missing 'command' field".into(),
                authenticated_user,
                signed_at_str,
                Some(req.command.clone()),
            );
            return Err(ErrorResponse {
                error: "Invalid Request".into(),
            });
        }
    };

    tracing::info!("Authorizing command '{}' with OPA", command_name);

    let cmd_config = match state
        .config
        .commands
        .iter()
        .find(|c| c.name == command_name)
    {
        Some(c) => c,
        None => {
            log_audit(
                "deny",
                format!(
                    "Command '{}' not found in agent configuration",
                    command_name
                ),
                authenticated_user,
                signed_at_str,
                Some(req.command.clone()),
            );
            return Err(ErrorResponse {
                error: "Invalid Request".into(),
            });
        }
    };

    // 4b. Verify Validity and Constraints
    let now = time::OffsetDateTime::now_utc();
    
    // Check 1: Max Validity
    let max_validity = cmd_config
        .max_validity
        .and_then(|d| time::Duration::try_from(d).ok())
        .unwrap_or(time::Duration::days(3));

    let age = now - authorized_user.timestamp;
    if age > max_validity {
        log_audit(
            "deny",
            format!("Command signature expired (max validity: {}, age: {})", max_validity, age),
            authenticated_user.clone(),
            signed_at_str.clone(),
            Some(req.command.clone()),
        );
        return Err(ErrorResponse {
            error: format!("Command Signature Expired (age: {} > max: {})", age, max_validity),
        });
    }

    // Parse constraints from command payload
    let target_machines = req.command.get("target_machines")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect::<Vec<_>>());

    let not_before = req.command.get("not_before")
        .and_then(|v| v.as_str())
        .and_then(|s| time::OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339).ok());

    let not_after = req.command.get("not_after")
        .and_then(|v| v.as_str())
        .and_then(|s| time::OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339).ok());

    // Check 2: Target Machine (Mandatory)
    let targets = target_machines.ok_or_else(|| {
        log_audit(
            "deny",
            "Missing mandatory 'target_machines' field".to_string(),
            authenticated_user.clone(),
            signed_at_str.clone(),
            Some(req.command.clone()),
        );
        ErrorResponse {
            error: "Missing Target Restriction".into(),
        }
    })?;

    if !targets.contains(&state.hostname) {
        log_audit(
            "deny",
            format!("Hostname '{}' not in target list '{:?}'", state.hostname, targets),
            authenticated_user.clone(),
            signed_at_str.clone(),
            Some(req.command.clone()),
        );
        return Err(ErrorResponse {
            error: format!("Target Machine Mismatch ({} not in {:?})", state.hostname, targets),
        });
    }

    // Check 3: Time Constraints
    if let Some(nbf) = not_before {
        if now < nbf {
            log_audit(
                "deny",
                format!("Command not yet valid (nbf: {}, now: {})", nbf, now),
                authenticated_user.clone(),
                signed_at_str.clone(),
                Some(req.command.clone()),
            );
            return Err(ErrorResponse {
                error: format!("Command Not Yet Valid (Starts at {})", nbf),
            });
        }
    }

    if let Some(exp) = not_after {
        if now > exp {
            log_audit(
                "deny",
                format!("Command expired (not_after: {}, now: {})", exp, now),
                authenticated_user.clone(),
                signed_at_str.clone(),
                Some(req.command.clone()),
            );
            return Err(ErrorResponse {
                error: format!("Command Expired (Expired at {})", exp),
            });
        }
    }

    // Call OPA
    let decision = crate::opa::check_authorization(
        &state.http_client,
        &state.config.opa_url,
        &cmd_config.opa_rule,
        req.command.clone(),
        req.id_token.clone(),
        gen_time_str.clone(),
        state.hostname.clone(),
    )
    .await
    .map_err(|e| {
        log_audit(
            "error",
            format!("OPA evaluation failed: {}", e),
            authenticated_user.clone(),
            signed_at_str.clone(),
            Some(req.command.clone()),
        );
        ErrorResponse {
            error: "Internal Error".into(),
        }
    })?;

    if !decision.allow {
            log_audit(
                "deny",
                decision.reason.clone(),
                authenticated_user,
                signed_at_str,
                Some(req.command.clone()),
            );
        // Do not leak reason to client
        return Err(ErrorResponse {
            error: "Authorization Denied".into(),
        });
    }

    // 5. Execute Command
    let executable = cmd_config
        .executable
        .clone()
        .unwrap_or_else(|| command_name.to_string());

    // Check for explicit ID in payload, else generate one?
    // Plan said UI generates it.
    let execution_id = req
        .command
        .get("id")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

    tracing::info!(
        "Executing command '{}' with ID {}",
        command_name,
        execution_id
    );

    // Prepare Log File
    let logs_dir = PathBuf::from(&state.config.logs_dir);
    if !logs_dir.exists() {
        tokio::fs::create_dir_all(&logs_dir).await.map_err(|e| {
            log_audit(
                "error",
                format!("Failed to create logs dir: {}", e),
                authenticated_user.clone(),
                signed_at_str.clone(),
                Some(req.command.clone()),
            );
            ErrorResponse {
                error: "Internal Error".into(),
            }
        })?;
    }
    let log_path = logs_dir.join(format!("{}.log", execution_id));
    let mut log_file = tokio::fs::File::create(&log_path).await.map_err(|e| {
        log_audit(
            "error",
            format!("Failed to create log file: {}", e),
            authenticated_user.clone(),
            signed_at_str.clone(),
            Some(req.command.clone()),
        );
        ErrorResponse {
            error: "Internal Error".into(),
        }
    })?;

    // Write Audit Header
    let header = format!(
        "--- EXECUTION LOG ---\nID: {}\nUser: {}\nTime: {}\nCommand: {}\nExecutable: {} {}\n---------------------\n",
        execution_id,
        authenticated_user,
        gen_time_str,
        command_name,
        executable,
        cmd_config.args.join(" ")
    );

    if let Err(e) = log_file.write_all(header.as_bytes()).await {
        tracing::error!("Failed to write header to log file: {}", e);
        // Non-critical, continue
    }

    // Spawn Command
    let mut child = tokio::process::Command::new(&executable)
        .args(&cmd_config.args)
        .current_dir(cmd_config.cwd.clone().unwrap_or(".".to_string()))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| {
            log_audit(
                "error",
                format!("Failed to spawn command: {}", e),
                authenticated_user.clone(),
                signed_at_str.clone(),
                Some(req.command.clone()),
            );
            ErrorResponse {
                error: "Execution Failed".into(),
            }
        })?;

    // Pipe Output
    // We want to merge stdout and stderr into the log file.
    let stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();

    // Background task to pipe output to file
    tokio::spawn(async move {
        // Simple approach: pipe both to same file. Access via mutex or just let OS handle concurrent writes?
        // Better: Multiplex or just spawn two tasks writing to split owned writers of the file?
        // Tokio File can be cloned? No. `try_clone`.

        // Single writer task via channel
        let mut file_out = log_file;

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

        while let Some(msg) = rx.recv().await {
            let _ = file_out.write_all(msg.as_bytes()).await;
            let _ = file_out.flush().await;
        }
    });

    log_audit(
        "allow",
        "Command Started".to_string(),
        authenticated_user.clone(),
        signed_at_str,
        Some(req.command.clone()),
    );

    Ok(Json(ExecutionResponse {
        status: "authorized".to_string(),
        // Return the UUID here so client knows what to stream
        message: execution_id.clone(),
        execution_time: Some(gen_time_str),
    }))
}

async fn stream_logs_handler(
    Path(id): Path<String>,
    State(state): State<AgentState>,
    ws: WebSocketUpgrade,
) -> Response {
    let log_path = PathBuf::from(&state.config.logs_dir).join(format!("{}.log", id));
    // Default to tailing logs as they are written
    ws.on_upgrade(move |socket| tail_file(socket, log_path, None))
}

async fn list_files_handler(State(state): State<AgentState>) -> Json<Vec<files::FileMetadata>> {
    Json(files::list_available_files(&state.config.files))
}

#[derive(Deserialize)]
struct StreamFileParams {
    token: String,
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
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Query(params): Query<StreamFileParams>,
    ws: WebSocketUpgrade,
) -> Response {
    // Helper for audit logging
    // Helper for audit logging
    let log_audit = |decision: &'static str,
                     reason: String,
                     user: String,
                     file_info: Option<serde_json::Value>| {
        crate::audit::log_audit(
            decision,
            reason,
            user,
            addr.ip().to_string(),
            state.hostname.clone(),
            None,
            None,
            file_info,
        );
    };

    // 1. Verify Token & OPA
    // Note: We are doing this before upgrade to return HTTP error if auth fails.
    /* 
       Optimization: We could reuse security::VerifierConfig logic if we refactored security.rs 
       to expose a simple "verify_jwt(token)" function. 
       For now, manual verification is fine.
    */
    
    // We need the key.
    let header = match jsonwebtoken::decode_header(&params.token) {
        Ok(h) => h,
        Err(_) => {
            log_audit("deny", "Invalid Token Header".into(), "unknown".into(), None);
            return (axum::http::StatusCode::UNAUTHORIZED, "Invalid Token Header").into_response();
        }
    };
    
    // Logic similar to web callback, but here we just need to verify signature against JWKS.
    let kid = match header.kid {
        Some(k) => k,
        None => {
             log_audit("deny", "Missing KID".into(), "unknown".into(), None);
             return (axum::http::StatusCode::UNAUTHORIZED, "Missing KID").into_response();
        }
    };
    
    let jwk = match state.jwks.find(&kid) {
        Some(j) => j,
        None => {
            log_audit("deny", "Unknown Key".into(), "unknown".into(), None);
            return (axum::http::StatusCode::UNAUTHORIZED, "Unknown Key").into_response();
        }
    };
    
    let decoding_key = match jsonwebtoken::DecodingKey::from_jwk(jwk) {
        Ok(k) => k,
        Err(_) => {
            log_audit("deny", "Key Error".into(), "unknown".into(), None);
            return (axum::http::StatusCode::INTERNAL_SERVER_ERROR, "Key Error").into_response();
        }
    };
    
    let mut validation = jsonwebtoken::Validation::new(header.alg);
    validation.set_audience(&[&state.config.oidc.client_id]);
    validation.set_issuer(&[&state.config.oidc.issuer_url]);
    
    let token_data = match jsonwebtoken::decode::<serde_json::Value>(&params.token, &decoding_key, &validation) {
         Ok(t) => t,
         Err(_) => {
             log_audit("deny", "Invalid Token Signature".into(), "unknown".into(), None);
             return (axum::http::StatusCode::UNAUTHORIZED, "Invalid Token").into_response();
         }
    };

    let user = token_data.claims.get("username")
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
    let check_input = serde_json::json!({
        "input": {
            "action": "read_file",
            "file": file_info_json,
            "jwt": params.token
        }
    });
    
    let opa_url = format!("{}/v1/data/remonse/authz/decision", state.config.opa_url);
    let opa_res: serde_json::Value = match state.http_client.post(&opa_url).json(&check_input).send().await {
        Ok(r) => r.json().await.unwrap_or(serde_json::json!({})),
        Err(e) => {
            log_audit("error", format!("OPA Error: {}", e), user.clone(), Some(file_info_json));
            return (axum::http::StatusCode::INTERNAL_SERVER_ERROR, "OPA Error").into_response();
        }
    };

    let allowed = opa_res.pointer("/result/allow").and_then(|v| v.as_bool()).unwrap_or(false);
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
        
        let metadata = file.metadata().await.unwrap();
        let len = metadata.len();
        
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

    let mut buf = [0u8; 1024];
    loop {
        let n = match file.read(&mut buf).await {
            Ok(n) => n,
            Err(_) => break,
        };

        if n > 0 {
            let s = String::from_utf8_lossy(&buf[..n]);
            if socket.send(Message::Text(s.to_string().into())).await.is_err() {
                break;
            }
        } else {
             // EOF. Wait.
             tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        }
    }
}
