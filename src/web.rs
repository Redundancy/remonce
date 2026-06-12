use crate::config::Config;
use crate::security::Claims;
use axum::{
    extract::{Query, State},
    response::{Html, IntoResponse, Redirect},
    routing::{get, post},
    Router,
};

use p256::{
    ecdsa::{SigningKey, signature::Signer},
    pkcs8::EncodePublicKey,
};
use p256::elliptic_curve::generic_array::GenericArray;
use rand::{RngCore, rngs::OsRng};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tower_http::{
    services::ServeDir,
    trace::{DefaultMakeSpan, TraceLayer},
};
use tower_sessions::MemoryStore;
use tower_sessions::{Expiry, Session, SessionManagerLayer, cookie::SameSite};

const SESSION_KEY: &str = "remonce.session";

// Application-wide error type.
#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("Internal error: {0}")]
    Internal(String),
    #[error("Configuration error: {0}")]
    Config(String),
    #[error("Authentication error: {0}")]
    Auth(String),
    #[error(transparent)]
    Reqwest(#[from] reqwest::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Jwt(#[from] jsonwebtoken::errors::Error),
}

impl IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        let body = format!("Error: {self}");
        (axum::http::StatusCode::INTERNAL_SERVER_ERROR, body).into_response()
    }
}

// Represents the application's configuration.

/// Data fetched from the OIDC provider's .well-known endpoint.
#[derive(Clone, Debug, Deserialize)]
pub struct OidcMetadata {
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
}

/// The shared application state.
#[derive(Clone)]
pub struct AppState {
    pub http_client: Client,
    pub config: Config,
    pub oidc_metadata: OidcMetadata,
    pub jwks: jsonwebtoken::jwk::JwkSet,
    pub hostname: String,
    /// HTTP client for agent calls — trusts `agent_ca_path` in addition to
    /// system roots.
    pub agent_http: Client,
    /// rustls config for WebSocket connections to the agent.
    pub agent_tls: std::sync::Arc<rustls::ClientConfig>,
}

/// Data stored in the session during the OIDC login flow.
///
/// `signing_key_hex` is the raw P-256 scalar (hex-encoded for JSON session
/// serialization). The web tier is loopback-only and uses an in-memory session
/// store, so the key never leaves this process; there is no cross-host exposure
/// to encrypt against.
#[derive(Serialize, Deserialize)]
struct OidcFlowState {
    pkce_verifier: String,
    state: String,
    ephemeral_public_key_pem: String,
    signing_key_hex: String,
}

/// Data stored in the session after a user has logged in.
#[derive(Serialize, Deserialize, Default)]
pub(crate) struct UserProfile {
    pub(crate) subject: String,
    pub(crate) id_token: String,
    pub(crate) signing_key_hex: String,
    pub(crate) public_key_pem: String,
}

/// Fetch the logged-in user's profile from the session, or fail with an
/// auth error. Shared by the signing endpoints and the agent proxy.
pub(crate) async fn require_profile(session: &Session) -> Result<UserProfile, AppError> {
    let profile: UserProfile = session
        .get(SESSION_KEY)
        .await?
        .ok_or(AppError::Auth("Not logged in".into()))?;
    if profile.subject.is_empty() {
        return Err(AppError::Auth("Not logged in".into()));
    }
    Ok(profile)
}

pub async fn run(insecure: bool) -> Result<(), AppError> {
    // Load configuration from `config.toml`
    let config_str = std::fs::read_to_string("config.toml")
        .map_err(|e| AppError::Config(format!("Failed to read config.toml: {e}")))?;
    let config: Config = toml::from_str(&config_str)
        .map_err(|e| AppError::Config(format!("Failed to parse config.toml: {e}")))?;

    // Validate the `--insecure` posture up front; refuses to start when any
    // degraded setting is active without the flag.
    let insecure_mode = crate::insecure::validate(&config, insecure)
        .map_err(|e| AppError::Config(format!("{e}")))?;
    crate::audit::set_insecure_mode(insecure_mode.as_bool());

    // Create shared HTTP client and AppState
    let http_client = Client::new();
    let discovery_url = format!("{}/.well-known/openid-configuration", config.oidc.issuer_url);
    let discovery_response_text = http_client.get(&discovery_url).send().await?.text().await?;

    tracing::info!("Discovery URL: {}", discovery_url);
    
    // Attempt to parse OIDC metadata, but don't crash if it fails (yet), though unwrapping effectively crashes
    let oidc_metadata: OidcMetadata = serde_json::from_str(&discovery_response_text)?;

    // TODO: this is good enough for now, but should be refreshed as needed (demand based)
    let jwks = http_client
        .get(&oidc_metadata.jwks_uri)
        .send()
        .await?
        .json()
        .await?;

    let addr: SocketAddr = config
        .listen_address
        .parse()
        .map_err(|e| AppError::Config(format!("Invalid listen_address: {e}")))?;

    if !addr.ip().is_loopback() {
        return Err(AppError::Config(format!(
            "web tier must bind to loopback (got {}); the signer is intended to run on the operator's workstation",
            addr.ip()
        )));
    }

    let hostname = hostname::get()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|_| "unknown".to_string());

    let agent_http = crate::agent_proxy::build_agent_http(config.agent_ca_path.as_deref())
        .map_err(AppError::Config)?;
    let agent_tls = crate::agent_proxy::build_agent_tls(config.agent_ca_path.as_deref())
        .map_err(AppError::Config)?;

    let app_state = AppState {
        http_client: http_client.clone(),
        config: config.clone(),
        oidc_metadata,
        jwks,
        hostname,
        agent_http,
        agent_tls,
    };

    // Session layer for storing OIDC state and user profile.
    // In a real app, the session key should be loaded from a secure location.
    let session_store = MemoryStore::default();
    use time;
    let session_layer = SessionManagerLayer::new(session_store)
        .with_secure(true) // Always secure if TLS is potentially on, though for localhost dev it might cause issues if no TLS. 
                           // But the previous code had false. We should potentially toggle this based on TLS config.
                           // For now, I'll set it to false if no TLS, true if TLS.
        .with_same_site(SameSite::Lax)
        .with_expiry(Expiry::OnInactivity(time::Duration::seconds(3600)));
        
    let secure_cookies = config.tls.is_some();
    let session_layer = session_layer.with_secure(secure_cookies);

    let app = Router::new()
        .route("/", get(|| async { Redirect::to("/auth/login") }))
        .route("/auth/login", get(login_handler))
        .route("/oidc/callback", get(callback_handler))
        .route("/api/sign", post(sign_handler))
        .route("/api/cosign", post(cosign_handler))
        .route("/api/commands", get(get_commands_handler))
        .route("/api/agent/execute", post(crate::agent_proxy::execute_proxy))
        .route("/api/agent/revoke", post(crate::agent_proxy::revoke_proxy))
        .route("/api/agent/files", get(crate::agent_proxy::files_proxy))
        .route("/ws/exec", get(crate::agent_proxy::exec_stream_proxy))
        .route("/ws/file", get(crate::agent_proxy::file_stream_proxy))
        .route("/ui", get(index_page_handler))
        .route("/ui/{page}", get(ui_handler))
        .nest_service("/static", ServeDir::new("ui/static"))
        .with_state(app_state)
        .layer(session_layer)
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(DefaultMakeSpan::default().include_headers(true)),
        );

    tracing::info!("listening on {}", addr);
    let listener = TcpListener::bind(&addr)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to bind to address: {e}")))?;

    if let Some(tls_config) = config.tls {
        tracing::info!("TLS enabled in {:?} mode", tls_config);
        crate::tls::serve_with_tls(listener, app, &tls_config)
            .await
            .map_err(|e| AppError::Internal(format!("Server error: {e}")))?;
    } else {
        tracing::warn!("TLS disabled. running on HTTP.");
        axum::serve(listener, app.into_make_service())
            .await
            .map_err(|e| AppError::Internal(format!("Server error: {e}")))?;
    }

    Ok(())
}

/// Index page handler (root /ui)
async fn index_page_handler(
    State(state): State<AppState>,
    session: Session,
) -> Result<Html<String>, AppError> {
    render_template(session, "index", &state).await
}

/// Generic UI handler for /ui/:page
async fn ui_handler(
    State(state): State<AppState>,
    session: Session,
    axum::extract::Path(page): axum::extract::Path<String>,
) -> Result<Html<String>, AppError> {
    // Basic validation to prevent traversal
    if !page.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
         return Err(AppError::Internal("Invalid page name".into()));
    }
    render_template(session, &page, &state).await
}

/// Helper to render pages using Header/Footer partials
async fn render_template(
    session: Session,
    template_name: &str,
    state: &AppState,
) -> Result<Html<String>, AppError> {
    let hostname = &state.hostname;
    let profile: UserProfile = session.get(SESSION_KEY).await?.unwrap_or_default();

    if profile.subject.is_empty() {
        // Redirect to home if not logged in, or show friendly message?
        // Using simple message for now as per previous logic
        return Ok(Html(
            "<h1>Not Logged In</h1><p><a href='/'>Home</a></p>".to_string(),
        ));
    }

    // Load Partials
    let header = std::fs::read_to_string("ui/header.html").map_err(|e| {
        AppError::Internal(format!("Failed to load header: {e}"))
    })?;
    
    let footer = std::fs::read_to_string("ui/footer.html").map_err(|e| {
        AppError::Internal(format!("Failed to load footer: {e}"))
    })?;

    // Load Content
    let content_path = format!("ui/{}.html", template_name);
    let content = std::fs::read_to_string(&content_path).map_err(|e| {
         AppError::Internal(format!("Page not found ({}): {}", template_name, e))
    })?;

    // Combine
    let full_body = format!("{}{}{}", header, content, footer);

    // Replace Variables
    let body = full_body
        .replace("{{subject}}", &profile.subject)
        .replace("{{id_token}}", &profile.id_token)
        .replace("{{public_key}}", &profile.public_key_pem)
        .replace("{{hostname}}", hostname)
        .replace("{{agent_url}}", &state.config.agent_url);

    Ok(Html(body))
}

/// Initiates the OIDC login flow.
async fn login_handler(
    State(state): State<AppState>,
    session: Session,
) -> Result<Redirect, AppError> {
    // 1. Generate ephemeral keypair for signing. Lives entirely in the
    //    server-side session; we are loopback-only so there is no cross-host
    //    exposure to encrypt against.
    let signing_key = SigningKey::random(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    let signing_key_hex = hex::encode(signing_key.to_bytes());

    // 2. Hash public key to create the OIDC nonce (binds the IdP-issued JWT
    //    to this specific ephemeral key — the core OIDC+ephemeral pattern).
    let public_key_pem = verifying_key
        .to_public_key_pem(spki::der::pem::LineEnding::LF)
        .map_err(|e| AppError::Internal(format!("Failed to encode public key to PEM: {e}")))?;
    let oidc_nonce = hex::encode(Sha256::digest(public_key_pem.as_bytes()));

    // 3. Generate OIDC state and PKCE
    let oidc_state = {
        let mut state_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut state_bytes);
        hex::encode(state_bytes)
    };

    let (pkce_challenge, pkce_verifier) = pkce::generate_pkce_challenge();

    // 4. Store flow state in session.
    let flow_state = OidcFlowState {
        pkce_verifier,
        state: oidc_state.clone(),
        ephemeral_public_key_pem: public_key_pem,
        signing_key_hex,
    };
    session.insert(SESSION_KEY, flow_state).await?;
    tracing::info!("Login: Session state inserted. Redirecting to auth provider.");

    // 5. Build the redirect URL.
    let mut auth_url: url::Url = state
        .oidc_metadata
        .authorization_endpoint
        .parse()
        .map_err(|_| AppError::Internal("Invalid authorization_endpoint URL".to_string()))?;
    auth_url
        .query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", &state.config.oidc.client_id)
        .append_pair("redirect_uri", &state.config.get_redirect_uri())
        .append_pair("scope", "openid groups user_profile")
        .append_pair("state", &oidc_state)
        .append_pair("nonce", &oidc_nonce)
        .append_pair("code_challenge", &pkce_challenge)
        .append_pair("code_challenge_method", "S256");

    Ok(Redirect::to(auth_url.as_ref()))
}

#[derive(Debug, Deserialize)]
struct CallbackQuery {
    code: Option<String>,
    state: String,
    error: Option<String>,
    error_description: Option<String>,
}

#[derive(Deserialize, Serialize)]
struct TokenResponse {
    id_token: String,
}

// Claims imported from security module

/// Handles the OIDC callback after the user authenticates with Vault.
async fn callback_handler(
    State(state): State<AppState>,
    Query(query): Query<CallbackQuery>,
    session: Session,
) -> Result<Redirect, AppError> {
    tracing::info!("Callback: Received OIDC callback. Query: {:?}", query);

    // 0. Check for OIDC errors
    if let Some(err) = &query.error {
        let desc = query
            .error_description
            .as_deref()
            .unwrap_or("No description");
        return Err(AppError::Auth(format!("OIDC Error: {err} - {desc}")));
    }

    let code = query
        .code
        .as_deref()
        .ok_or(AppError::Auth("Missing authorization code".into()))?;

    // 1. Get OIDC flow state from session and validate CSRF token
    let flow_state: OidcFlowState = match session.get(SESSION_KEY).await? {
        Some(s) => s,
        None => {
            tracing::error!("Callback: No session state found in session store!");
            return Err(AppError::Auth(
                "No session state found. Please login again.".into(),
            ));
        }
    };
    tracing::info!("Callback: Session found. Validating state.");
    if query.state != flow_state.state {
        return Err(AppError::Auth(
            "OIDC state mismatch (CSRF detection)".into(),
        ));
    }

    // 2. Exchange authorization code for an ID token
    let token_response: TokenResponse = state
        .http_client
        .post(&state.oidc_metadata.token_endpoint)
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", &state.config.get_redirect_uri()),
            ("client_id", &state.config.oidc.client_id),
            ("code_verifier", &flow_state.pkce_verifier),
        ])
        .send()
        .await?
        .json()
        .await?;

    // 3. Decode and validate the ID token
    let header = jsonwebtoken::decode_header(&token_response.id_token)?;
    let kid = header
        .kid
        .ok_or(AppError::Auth("Token missing 'kid' in header".into()))?;
    let jwk = state
        .jwks
        .find(&kid)
        .ok_or(AppError::Auth("No matching JWK found for token".into()))?;
    let mut validation = jsonwebtoken::Validation::new(header.alg);
    validation.set_audience(&[&state.config.oidc.client_id]);
    validation.set_issuer(&[&state.config.oidc.issuer_url]);

    let token_data = jsonwebtoken::decode::<Claims>(
        &token_response.id_token,
        &jsonwebtoken::DecodingKey::from_jwk(jwk)?,
        &validation,
    )?;

    // 4. *** THE CORE VERIFICATION STEP ***
    // Verify the nonce in the token matches the hash of our ephemeral public key.
    let expected_nonce = hex::encode(Sha256::digest(
        flow_state.ephemeral_public_key_pem.as_bytes(),
    ));
    if token_data.claims.nonce != expected_nonce {
        return Err(AppError::Auth(
            "Nonce mismatch! This token is not bound to our ephemeral key.".into(),
        ));
    }

    // 5. Success! Upgrade the session to a logged-in user profile.
    let user_profile = UserProfile {
        subject: token_data.claims.sub,
        id_token: token_response.id_token,
        signing_key_hex: flow_state.signing_key_hex,
        public_key_pem: flow_state.ephemeral_public_key_pem,
    };
    session.insert(SESSION_KEY, user_profile).await?;

    Ok(Redirect::to("/ui"))
}

#[derive(Deserialize)]
struct SignRequest {
    command: serde_json::Value,
    #[serde(default)]
    operator_requires: Option<crate::security::OperatorConstraint>,
}

#[derive(Deserialize)]
struct CosignRequest {
    approver: crate::security::ApproverBundle,
}

/// Load the session's ephemeral signing key.
///
/// The key is stored raw in the server-side session (see `OidcFlowState`
/// and `UserProfile`). The web tier is loopback-only so there is no
/// cross-host exposure to encrypt at rest against.
pub(crate) fn load_signing_key(profile: &UserProfile) -> Result<SigningKey, AppError> {
    let bytes = hex::decode(&profile.signing_key_hex)
        .map_err(|_| AppError::Internal("Invalid signing key hex".into()))?;
    SigningKey::from_bytes(GenericArray::from_slice(&bytes))
        .map_err(|_| AppError::Internal("Invalid signing key bytes".into()))
}

/// Approver signs a command + optional `operator_requires` constraint.
/// Returns an `ExecutionBundle` with `operator: null`. If the approver also
/// plans to execute themselves immediately (same-person + fresh TSA), this
/// bundle can be submitted directly to the agent.
async fn sign_handler(
    State(state): State<AppState>,
    session: Session,
    axum::Json(req): axum::Json<SignRequest>,
) -> Result<axum::Json<crate::security::ExecutionBundle>, AppError> {
    let profile: UserProfile = session
        .get(SESSION_KEY)
        .await?
        .ok_or(AppError::Auth("Not logged in".into()))?;

    let signing_key = load_signing_key(&profile)?;

    let canonical =
        crate::security::canonical_approver_payload(&req.command, &req.operator_requires);
    let signature: p256::ecdsa::Signature = signing_key.sign(canonical.as_bytes());
    let signature_bytes = signature.to_bytes();

    let mut data_to_timestamp = signature_bytes.to_vec();
    data_to_timestamp.extend_from_slice(profile.id_token.as_bytes());
    let timestamp_token_bytes = crate::tsa::request_timestamp(
        &state.http_client,
        &state.config.timestamp_authority.url,
        &data_to_timestamp,
    )
    .await
    .map_err(|e| AppError::Internal(format!("TSA Error: {e}")))?;

    Ok(axum::Json(crate::security::ExecutionBundle {
        approver: crate::security::ApproverBundle {
            command: req.command,
            operator_requires: req.operator_requires,
            signature: hex::encode(signature_bytes),
            id_token: profile.id_token,
            public_key: profile.public_key_pem,
            timestamp_token: hex::encode(timestamp_token_bytes),
        },
        operator: None,
    }))
}

/// Operator co-signs an existing approver bundle. Produces an `ExecutionBundle`
/// ready to submit to the agent. No validity check is done here — the agent is
/// the enforcement point. The server simply signs `approver_sig || operator_pubkey`.
async fn cosign_handler(
    State(state): State<AppState>,
    session: Session,
    axum::Json(req): axum::Json<CosignRequest>,
) -> Result<axum::Json<crate::security::ExecutionBundle>, AppError> {
    let profile: UserProfile = session
        .get(SESSION_KEY)
        .await?
        .ok_or(AppError::Auth("Not logged in".into()))?;

    let signing_key = load_signing_key(&profile)?;

    let mut payload = req.approver.signature.as_bytes().to_vec();
    payload.extend_from_slice(profile.public_key_pem.as_bytes());
    let signature: p256::ecdsa::Signature = signing_key.sign(&payload);
    let signature_bytes = signature.to_bytes();

    let mut data_to_timestamp = signature_bytes.to_vec();
    data_to_timestamp.extend_from_slice(profile.id_token.as_bytes());
    let timestamp_token_bytes = crate::tsa::request_timestamp(
        &state.http_client,
        &state.config.timestamp_authority.url,
        &data_to_timestamp,
    )
    .await
    .map_err(|e| AppError::Internal(format!("TSA Error: {e}")))?;

    Ok(axum::Json(crate::security::ExecutionBundle {
        operator: Some(crate::security::OperatorCosign {
            approver_sig: req.approver.signature.clone(),
            signature: hex::encode(signature_bytes),
            id_token: profile.id_token,
            public_key: profile.public_key_pem,
            timestamp_token: hex::encode(timestamp_token_bytes),
        }),
        approver: req.approver,
    }))
}

/// A simple PKCE implementation.
pub(crate) mod pkce {
    use super::{Digest, OsRng, RngCore, Sha256};
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

    pub fn generate_pkce_challenge() -> (String, String) {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        let verifier = URL_SAFE_NO_PAD.encode(&bytes);
        let digest = Sha256::digest(verifier.as_bytes());
        let challenge = URL_SAFE_NO_PAD.encode(&digest);
        (challenge, verifier)
    }
}

// Custom (de)serialization for session data
impl<T: Serialize + ?Sized> From<&T> for AppError {
    fn from(err: &T) -> Self {
        AppError::Internal(format!(
            "Session serialization error: {:?}",
            serde_json::to_string(err)
        ))
    }
}
impl From<tower_sessions::session::Error> for AppError {
    fn from(err: tower_sessions::session::Error) -> Self {
        AppError::Internal(format!("Session error: {err}"))
    }
}

/// Helper handler to fetch available commands if authorized.
async fn get_commands_handler(
    State(state): State<AppState>,
    session: Session,
) -> Result<axum::Json<Vec<crate::config::CommandConfig>>, AppError> {
    let profile: UserProfile = session
        .get(SESSION_KEY)
        .await?
        .ok_or(AppError::Auth("Not logged in".into()))?;

    // Query OPA for "view_docs" permission
    let check_input = json!({
        "input": {
            "action": "view_docs",
            "jwt": profile.id_token
        }
    });

    let opa_url = format!("{}/v1/data/remonce/authz/decision", state.config.opa_url);

    let opa_response: serde_json::Value = state
        .http_client
        .post(&opa_url)
        .json(&check_input)
        .send()
        .await?
        .json()
        .await?;

    let allowed = opa_response
        .pointer("/result/allow")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    if !allowed {
        return Err(AppError::Auth("Unauthorized to view commands".into()));
    }

    Ok(axum::Json(state.config.commands.clone()))
}
