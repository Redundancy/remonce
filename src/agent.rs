use axum::{
    Router,
    extract::{
        ConnectInfo, Json, Path, State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    response::{IntoResponse, Response},
    routing::{get, post},
};
use reqwest::Client;
use serde::Serialize;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::Stdio;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
// Removed unused imports
use crate::config::Config;
use crate::web::OidcMetadata;
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
    let log_audit = |decision: &'static str,
                     reason: String,
                     user: String,
                     signed_at: Option<String>,
                     command: Option<serde_json::Value>| {
        #[derive(Serialize)]
        struct AuditLog {
            timestamp: String,
            level: &'static str,
            target: &'static str,
            event_type: &'static str,
            #[serde(skip_serializing_if = "Option::is_none")]
            command: Option<serde_json::Value>,
            user: String,
            #[serde(skip_serializing_if = "Option::is_none")]
            signed_at: Option<String>, // NEW
            source_ip: String,
            agent_host: String,
            decision: &'static str,
            reason: String,
        }

        let now = time::OffsetDateTime::now_utc();
        // Use `time::format_description::well_known::Rfc3339`
        let timestamp = now
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_else(|_| "unknown_time".to_string());

        let audit = AuditLog {
            timestamp,
            level: "INFO",
            target: "audit",
            event_type: "command_execution",
            command,
            user,
            signed_at,
            source_ip: addr.ip().to_string(),
            agent_host: state.hostname.clone(),
            decision,
            reason,
        };

        if let Ok(json) = serde_json::to_string(&audit) {
            println!("{}", json);
        } else {
            tracing::error!("Failed to serialize audit log");
        }
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
    ws.on_upgrade(move |socket| handle_socket(socket, id, state.config.logs_dir))
}

async fn handle_socket(mut socket: WebSocket, id: String, logs_dir: String) {
    let log_path = PathBuf::from(logs_dir).join(format!("{}.log", id));

    // Wait for file to exist (it might be creating)
    let mut attempts = 0;
    while !log_path.exists() && attempts < 10 {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        attempts += 1;
    }

    if !log_path.exists() {
        let _ = socket
            .send(Message::Text("Log file not found".into()))
            .await;
        return;
    }

    let mut file = match tokio::fs::File::open(&log_path).await {
        Ok(f) => f,
        Err(_) => {
            let _ = socket
                .send(Message::Text("Failed to open log file".into()))
                .await;
            return;
        }
    };

    let mut buf = [0u8; 1024];
    loop {
        let n = match file.read(&mut buf).await {
            Ok(n) => n,
            Err(_) => {
                break;
            } // stop on error
        };

        if n > 0 {
            let s = String::from_utf8_lossy(&buf[..n]);
            if socket
                .send(Message::Text(s.to_string().into()))
                .await
                .is_err()
            {
                break; // client disconnected
            }
        } else {
            // EOF reached? Wait for more data (tail)
            // But how do we know if process finished?
            // For now, just keep polling until client disconnects or timeout.
            // We'll sleep briefly.
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        }
    }
}
