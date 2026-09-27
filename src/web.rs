use crate::config::Config;
use axum::{
    extract::{Query, State},
    response::{Html, IntoResponse, Redirect},
    routing::{get, post},
    Router,
};

use reqwest::Client;
use serde::{Deserialize, Serialize};
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
    // The UI is fully self-hosted: no inline scripts, no third-party origins.
    // Signed bundles (with ID tokens) live in these pages, so injected script
    // must have nowhere to load from or send to.
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; \
             connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
        ),
    );
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
    /// TSA trust anchors, to check each timestamp before handing out a bundle.
    pub trusted_roots: Vec<Vec<u8>>,
    /// Agents the UI may use: `config.toml` first (`agent_url` leading), then
    /// the user's agents file. Never empty.
    pub known_agents: Vec<crate::known_agents::KnownAgent>,
}

/// Data stored in the session during a viewer login.
#[derive(Serialize, Deserialize)]
struct LoginFlow {
    state: String,
    pkce_verifier: String,
    nonce: String,
    /// Local UI path to return to after login (validated by `local_ui_path`).
    next: Option<String>,
}

#[derive(Deserialize)]
struct LoginQuery {
    next: Option<String>,
}

/// Accept only same-origin UI paths as a post-login destination, so the
/// login endpoint can't be used as an open redirect.
fn local_ui_path(next: &str) -> Option<String> {
    let ok = (next == "/ui" || next.starts_with("/ui/") || next.starts_with("/ui?"))
        && !next.contains("//")
        && !next.contains('\\')
        && !next.chars().any(|c| c.is_control());
    ok.then(|| next.to_string())
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
    let config: Config = crate::config::load("config.toml").map_err(|e| AppError::Config(e.to_string()))?;

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

    let trusted_roots = crate::tsa::load_trust_anchors(
        config.timestamp_authority.ca_path.as_deref(),
        config.timestamp_authority.trust_system_store,
    );

    let known_agents = crate::known_agents::load(&config).map_err(AppError::Config)?;
    match crate::known_agents::user_file_path() {
        Some(path) => tracing::info!(
            agents = known_agents.len(),
            "Known agents: config.toml plus {} ({})",
            path.display(),
            if path.exists() { "found" } else { "not present" }
        ),
        None => tracing::info!(agents = known_agents.len(), "Known agents: config.toml (no user agents file location)"),
    }

    let app_state = AppState {
        http_client: http_client.clone(),
        config: config.clone(),
        oidc_metadata,
        jwks,
        hostname,
        agent_http,
        agent_tls,
        trusted_roots,
        known_agents,
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
        .route("/", get(|| async { Redirect::to("/ui") }))
        .route("/auth/login", get(login_handler))
        .route("/oidc/callback", get(callback_handler))
        .route("/api/sign/begin", post(crate::web_sign::begin_handler))
        .route("/api/sign/result/{id}", get(crate::web_sign::result_handler))
        .route("/api/agent/commands", get(crate::agent_proxy::commands_proxy))
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

/// The UI pages: `/ui/{name}` renders `ui/{name}.html` inside the layout.
const UI_PAGES: &[(&str, &str)] = &[
    ("commands", "Commands"),
    ("review", "Sign a request"),
    ("execute", "Execute"),
    ("monitor", "Runs"),
    ("files", "Files"),
];

/// `/ui` — the command registry.
async fn index_page_handler(
    State(state): State<AppState>,
    session: Session,
    uri: axum::http::Uri,
) -> Result<axum::response::Response, AppError> {
    render_template(session, "commands", &state, &uri).await
}

/// `/ui/{page}` for the pages in `UI_PAGES`.
async fn ui_handler(
    State(state): State<AppState>,
    session: Session,
    axum::extract::Path(page): axum::extract::Path<String>,
    uri: axum::http::Uri,
) -> Result<axum::response::Response, AppError> {
    render_template(session, &page, &state, &uri).await
}

#[cfg(test)]
mod tests {
    use super::local_ui_path;

    #[test]
    fn login_return_path_is_local_ui_only() {
        assert_eq!(local_ui_path("/ui").as_deref(), Some("/ui"));
        assert_eq!(local_ui_path("/ui/monitor?id=1").as_deref(), Some("/ui/monitor?id=1"));
        for bad in ["https://evil.example/ui", "//evil.example/ui", "/ui//evil", "/uix", "/auth/login", "/ui\\x"] {
            assert_eq!(local_ui_path(bad), None, "{bad}");
        }
    }
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// Render a page into `ui/layout.html`. Every substituted value is
/// HTML-escaped; page fragments contain no script.
async fn render_template(
    session: Session,
    page: &str,
    state: &AppState,
    uri: &axum::http::Uri,
) -> Result<axum::response::Response, AppError> {
    let Some(&(page, title)) = UI_PAGES.iter().find(|(name, _)| *name == page) else {
        return Ok((axum::http::StatusCode::NOT_FOUND, "Page not found").into_response());
    };
    let profile: UserProfile = session.get(PROFILE_KEY).await?.unwrap_or_default();
    if profile.subject.is_empty() {
        let here = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/ui");
        let next: String = url::form_urlencoded::byte_serialize(here.as_bytes()).collect();
        return Ok(Redirect::to(&format!("/auth/login?next={next}")).into_response());
    }

    let read = |path: &str| {
        std::fs::read_to_string(path)
            .map_err(|e| AppError::Internal(format!("Failed to load {path}: {e}")))
    };
    let layout = read("ui/layout.html")?;
    let content = read(&format!("ui/{page}.html"))?;

    let initials: String = profile
        .username
        .split(|c: char| !c.is_alphanumeric())
        .filter(|w| !w.is_empty())
        .take(2)
        .filter_map(|w| w.chars().next())
        .collect::<String>()
        .to_uppercase();
    let agent_options = crate::known_agents::options_html(&state.known_agents, &state.hostname);

    let body = layout
        .replace("{{content}}", &content)
        .replace("{{page}}", page)
        .replace("{{title}}", title)
        .replace("{{username}}", &html_escape(&profile.username))
        .replace("{{initials}}", &html_escape(&initials))
        .replace("{{hostname}}", &html_escape(&state.hostname))
        .replace("{{agent_options}}", &agent_options);

    Ok(Html(body).into_response())
}

/// Initiates a viewer login (the browsing session). Signing never uses
/// this token; it has its own per-signature login in `web_sign`.
async fn login_handler(
    State(state): State<AppState>,
    session: Session,
    Query(query): Query<LoginQuery>,
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
                next: query.next.as_deref().and_then(local_ui_path),
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

    Ok(Redirect::to(flow.next.as_deref().unwrap_or("/ui")))
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

