use crate::config::Config;
use axum::{
    extract::{Query, State},
    response::{Html, IntoResponse, Redirect},
    routing::{get, post},
    Router,
};

use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tower_http::{
    services::ServeDir,
    trace::{DefaultMakeSpan, TraceLayer},
};
use tower_sessions::MemoryStore;
use tower_sessions::{Expiry, Session, SessionManagerLayer, cookie::SameSite};

/// Logged-in (viewer) profile.
const PROFILE_KEY: &str = "remonce.profile";
/// In-flight viewer login.
const LOGIN_FLOW_KEY: &str = "remonce.login_flow";

// Application-wide error type.
#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("Internal error: {0}")]
    Internal(String),
    #[error("Configuration error: {0}")]
    Config(String),
    #[error("Authentication error: {0}")]
    Auth(String),
    #[error("Forbidden: {0}")]
    Forbidden(String),
    #[error(transparent)]
    Reqwest(#[from] reqwest::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Jwt(#[from] jsonwebtoken::errors::Error),
}

impl IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        use axum::http::StatusCode;
        let status = match &self {
            AppError::Auth(_) => StatusCode::UNAUTHORIZED,
            AppError::Forbidden(_) => StatusCode::FORBIDDEN,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };
        let body = match self {
            // reqwest errors embed the request URL, which may carry secrets.
            AppError::Reqwest(e) => format!("Error: {}", e.without_url()),
            other => format!("Error: {other}"),
        };
        (status, body).into_response()
    }
}

/// Baseline response hardening for every web-tier response.
async fn security_headers(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use axum::http::{HeaderValue, header};
    let mut resp = next.run(req).await;
    let h = resp.headers_mut();
    h.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    h.insert(header::REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    resp
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

/// Data stored in the session during a viewer login.
#[derive(Serialize, Deserialize)]
struct LoginFlow {
    state: String,
    pkce_verifier: String,
    nonce: String,
}

/// Data stored in the session after a user has logged in. Holds only the
/// *viewer* token — a bearer credential for files and logs. No signing key
/// or signing token lives here: every signature gets its own login (see
/// `web_sign`).
#[derive(Serialize, Deserialize, Default)]
pub(crate) struct UserProfile {
    pub(crate) subject: String,
    pub(crate) username: String,
    pub(crate) viewer_id_token: String,
}

/// Fetch the logged-in user's profile from the session, or fail with an
/// auth error. Shared by the signing endpoints and the agent proxy.
pub(crate) async fn require_profile(session: &Session) -> Result<UserProfile, AppError> {
    let profile: UserProfile = session
        .get(PROFILE_KEY)
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

    if config.oidc.viewer_client_id.is_none() {
        return Err(AppError::Config(
            "oidc.viewer_client_id must be set: the local signer logs you in with the viewer \
             client and uses the signing client only for per-signature logins"
                .into(),
        ));
    }

    // Create shared HTTP client and AppState
    let http_client = crate::http_client();
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
        .route("/api/sign/begin", post(crate::web_sign::begin_handler))
        .route("/api/sign/result/{id}", get(crate::web_sign::result_handler))
        .route("/api/commands", get(get_commands_handler))
        .route("/api/agent/execute", post(crate::agent_proxy::execute_proxy))
        .route("/api/agent/files", get(crate::agent_proxy::files_proxy))
        .route("/ws/exec", get(crate::agent_proxy::exec_stream_proxy))
        .route("/ws/file", get(crate::agent_proxy::file_stream_proxy))
        .route("/ui", get(index_page_handler))
        .route("/ui/{page}", get(ui_handler))
        .nest_service("/static", ServeDir::new("ui/static"))
        .with_state(app_state)
        .layer(session_layer)
        .layer(axum::middleware::from_fn(security_headers))
        .layer(
            // Headers stay out of spans: they carry the session cookie.
            TraceLayer::new_for_http()
                .make_span_with(DefaultMakeSpan::default().include_headers(false)),
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
    let profile: UserProfile = session.get(PROFILE_KEY).await?.unwrap_or_default();

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
        .replace("{{hostname}}", hostname)
        .replace("{{agent_url}}", &state.config.agent_url);

    Ok(Html(body))
}

/// Initiates a viewer login (the browsing session). Signing never uses
/// this token; it has its own per-signature login in `web_sign`.
async fn login_handler(
    State(state): State<AppState>,
    session: Session,
) -> Result<Redirect, AppError> {
    let viewer_client_id = viewer_client_id(&state)?;
    let oidc_state = crate::oidc_client::random_token();
    let nonce = crate::oidc_client::random_token();
    let (pkce_challenge, pkce_verifier) = crate::oidc_client::pkce_pair();

    // Starting a login doesn't touch an existing profile; the callback
    // replaces it only once the new login succeeds.
    session
        .insert(
            LOGIN_FLOW_KEY,
            LoginFlow {
                state: oidc_state.clone(),
                pkce_verifier,
                nonce: nonce.clone(),
            },
        )
        .await?;

    let url = crate::oidc_client::authorize_url(
        &state.oidc_metadata,
        &crate::oidc_client::AuthorizeParams {
            client_id: viewer_client_id,
            redirect_uri: &state.config.get_redirect_uri(),
            state: &oidc_state,
            nonce: &nonce,
            pkce_challenge: &pkce_challenge,
            reauth: None,
        },
    )
    .map_err(AppError::Internal)?;
    Ok(Redirect::to(url.as_ref()))
}

fn viewer_client_id(state: &AppState) -> Result<&str, AppError> {
    state
        .config
        .oidc
        .viewer_client_id
        .as_deref()
        .ok_or_else(|| AppError::Config("oidc.viewer_client_id is not set".into()))
}

#[derive(Debug, Deserialize)]
pub(crate) struct CallbackQuery {
    pub(crate) code: Option<String>,
    pub(crate) state: String,
    pub(crate) error: Option<String>,
    pub(crate) error_description: Option<String>,
}

/// Handles every OIDC callback. Both clients share the redirect URI; the
/// `state` decides whether this completes a viewer login or a pending
/// signature. Either way the `state` must be one this session issued.
async fn callback_handler(
    State(state): State<AppState>,
    Query(query): Query<CallbackQuery>,
    session: Session,
) -> Result<Redirect, AppError> {
    // The query holds the single-use authorization code: log its shape only.
    tracing::info!(
        has_code = query.code.is_some(),
        has_error = query.error.is_some(),
        "Callback: Received OIDC callback"
    );

    if crate::web_sign::is_pending(&session, &query.state).await? {
        return crate::web_sign::complete(&state, &session, query).await;
    }

    let flow: LoginFlow = session
        .get(LOGIN_FLOW_KEY)
        .await?
        .ok_or_else(|| AppError::Auth("No login in progress. Please login again.".into()))?;
    if query.state != flow.state {
        return Err(AppError::Auth("OIDC state mismatch (CSRF detection)".into()));
    }
    session.remove::<LoginFlow>(LOGIN_FLOW_KEY).await?;

    if let Some(err) = &query.error {
        let desc = query.error_description.as_deref().unwrap_or("No description");
        return Err(AppError::Auth(format!("OIDC Error: {err} - {desc}")));
    }
    let code = query
        .code
        .as_deref()
        .ok_or(AppError::Auth("Missing authorization code".into()))?;

    let viewer_client_id = viewer_client_id(&state)?;
    let id_token = crate::oidc_client::exchange_code(
        &state.http_client,
        &state.oidc_metadata,
        viewer_client_id,
        &state.config.get_redirect_uri(),
        code,
        &flow.pkce_verifier,
    )
    .await
    .map_err(AppError::Auth)?;
    let claims = crate::oidc_client::validate_id_token(
        &id_token,
        &state.jwks,
        &state.config.oidc.issuer_url,
        viewer_client_id,
        &flow.nonce,
        None,
    )
    .map_err(AppError::Auth)?;

    let subject = claims
        .get("sub")
        .and_then(|v| v.as_str())
        .ok_or(AppError::Auth("ID token has no sub".into()))?
        .to_string();
    let username = claims
        .get("username")
        .and_then(|v| v.as_str())
        .unwrap_or(&subject)
        .to_string();

    // New session id at privilege change: a session id planted before login
    // (e.g. by another local app) must not end up holding the profile.
    session.cycle_id().await?;
    session
        .insert(
            PROFILE_KEY,
            UserProfile {
                subject,
                username,
                viewer_id_token: id_token,
            },
        )
        .await?;

    Ok(Redirect::to("/ui"))
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
    let profile = require_profile(&session).await?;

    // Query OPA for "view_docs" permission
    let check_input = json!({
        "input": {
            "action": "view_docs",
            "jwt": profile.viewer_id_token
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
