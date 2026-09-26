//! Loopback web tier → remote agent proxy.
//!
//! The browser never talks to the agent directly. All agent traffic (execute,
//! file listing, log/file streaming) goes through these endpoints on the
//! loopback signer, which holds the TLS trust configuration for the agent
//! (`agent_ca_path` for self-signed certs, system roots otherwise). This keeps
//! the user's ID token out of browser-visible URLs and removes any need for
//! CORS on the agent.

use crate::web::{AppError, AppState};
use axum::{
    extract::{
        Query, State,
        ws::{Message as AxumMessage, WebSocket, WebSocketUpgrade},
    },
    response::{IntoResponse, Response},
};
use futures::{SinkExt, StreamExt};
use serde::Deserialize;
use std::sync::Arc;
use tokio_tungstenite::tungstenite::Message as TungsteniteMessage;
use tower_sessions::Session;

/// Build the rustls client config used for WebSocket connections to the agent:
/// system roots plus the optional `agent_ca_path` PEM.
pub fn build_agent_tls(agent_ca_path: Option<&str>) -> Result<Arc<rustls::ClientConfig>, String> {
    let mut roots = rustls::RootCertStore::empty();
    let native = rustls_native_certs::load_native_certs();
    for cert in native.certs {
        let _ = roots.add(cert);
    }
    if let Some(path) = agent_ca_path {
        let certs = crate::tls::load_certs(path)
            .map_err(|e| format!("Failed to read agent_ca_path '{path}': {e}"))?;
        if certs.is_empty() {
            return Err(format!("agent_ca_path '{path}' contains no certificates"));
        }
        for cert in certs {
            roots
                .add(cert)
                .map_err(|e| format!("Invalid certificate in agent_ca_path '{path}': {e}"))?;
        }
    }
    Ok(Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    ))
}

/// Build the reqwest client used for HTTP calls to the agent, trusting the
/// optional `agent_ca_path` PEM in addition to the system store.
pub fn build_agent_http(agent_ca_path: Option<&str>) -> Result<reqwest::Client, String> {
    // No redirects: a redirect would carry our request (and bearer token) to
    // a host nobody configured.
    let mut builder = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(std::time::Duration::from_secs(10))
        .timeout(std::time::Duration::from_secs(60));
    if let Some(path) = agent_ca_path {
        let certs = crate::tls::load_certs(path)
            .map_err(|e| format!("Failed to read agent_ca_path '{path}': {e}"))?;
        for cert in certs {
            let cert = reqwest::Certificate::from_der(cert.as_ref())
                .map_err(|e| format!("Invalid certificate in agent_ca_path '{path}': {e}"))?;
            builder = builder.add_root_certificate(cert);
        }
    }
    builder
        .build()
        .map_err(|e| format!("Failed to build agent HTTP client: {e}"))
}

/// Normalize an agent URL to its origin (`https://host:port/`). Only https is
/// accepted — the agent has no plaintext mode.
fn normalize_agent_url(raw: &str) -> Result<url::Url, AppError> {
    let mut parsed: url::Url = raw
        .trim()
        .parse()
        .map_err(|e| AppError::Config(format!("Invalid agent URL '{raw}': {e}")))?;
    if parsed.scheme() != "https" {
        return Err(AppError::Config(format!(
            "Agent URL must be https (got '{raw}'); the agent has no plaintext mode"
        )));
    }
    if parsed.host_str().is_none() {
        return Err(AppError::Config(format!("Agent URL '{raw}' has no host")));
    }
    // Normalize: drop any path/query so .join() behaves predictably.
    parsed.set_path("/");
    parsed.set_query(None);
    parsed.set_fragment(None);
    Ok(parsed)
}

/// Resolve the target agent URL. A browser-supplied override must be one of
/// the configured agents (`agent_url` or `allowed_agent_urls`): the proxy
/// attaches the user's ID token and signs on their behalf, so an arbitrary
/// host would receive credentials and could answer with hostile content.
fn resolve_agent_url(state: &AppState, override_url: Option<&str>) -> Result<url::Url, AppError> {
    let default = normalize_agent_url(&state.config.agent_url)?;
    let Some(raw) = override_url.filter(|s| !s.trim().is_empty()) else {
        return Ok(default);
    };
    let requested = normalize_agent_url(raw)?;
    let allowed = std::iter::once(Ok(default))
        .chain(state.config.allowed_agent_urls.iter().map(|u| normalize_agent_url(u)))
        .filter_map(Result::ok)
        .any(|a| a.origin() == requested.origin());
    if !allowed {
        return Err(AppError::Forbidden(format!(
            "Agent '{raw}' is not configured; add it to allowed_agent_urls in config.toml"
        )));
    }
    Ok(requested)
}

/// Reject cross-origin WebSocket upgrades. Cookies are not port-scoped, so a
/// page on another localhost port is "same-site" and would get the session
/// cookie; the browser-set `Origin` header is what tells the two apart.
fn require_same_origin(headers: &axum::http::HeaderMap) -> Result<(), AppError> {
    let host = headers
        .get(axum::http::header::HOST)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| AppError::Forbidden("Missing Host header".into()))?;
    let origin = headers
        .get(axum::http::header::ORIGIN)
        .and_then(|v| v.to_str().ok())
        .and_then(|o| o.parse::<url::Url>().ok())
        .ok_or_else(|| AppError::Forbidden("Missing or invalid Origin header".into()))?;
    if origin_matches_host(&origin, host) {
        Ok(())
    } else {
        Err(AppError::Forbidden("Cross-origin WebSocket request rejected".into()))
    }
}

fn origin_matches_host(origin: &url::Url, host: &str) -> bool {
    let (Some(o_host), Some(o_port)) = (origin.host_str(), origin.port_or_known_default()) else {
        return false;
    };
    let default_port = if origin.scheme() == "https" { 443 } else { 80 };
    // Host may be "name", "name:port", "[v6]" or "[v6]:port".
    let (h_host, h_port) = match host.rsplit_once(':') {
        Some((h, p)) if !p.contains(']') => match p.parse::<u16>() {
            Ok(port) => (h, port),
            Err(_) => return false,
        },
        _ => (host, default_port),
    };
    o_host.eq_ignore_ascii_case(h_host) && o_port == h_port
}

#[derive(Deserialize)]
pub struct ExecuteProxyRequest {
    #[serde(default)]
    pub agent_url: Option<String>,
    pub bundle: crate::security::ExecutionBundle,
}

/// POST /api/agent/execute — forward an ExecutionBundle to the agent.
pub async fn execute_proxy(
    State(state): State<AppState>,
    session: Session,
    axum::Json(req): axum::Json<ExecuteProxyRequest>,
) -> Result<Response, AppError> {
    crate::web::require_profile(&session).await?;

    let url = resolve_agent_url(&state, req.agent_url.as_deref())?
        .join("execute")
        .map_err(|e| AppError::Internal(format!("URL join: {e}")))?;

    let resp = state
        .agent_http
        .post(url)
        .json(&req.bundle)
        .send()
        .await
        .map_err(|e| AppError::Internal(format!("Agent unreachable: {}", e.without_url())))?;

    passthrough(resp).await
}

#[derive(Deserialize)]
pub struct RevokeProxyRequest {
    #[serde(default)]
    pub agent_url: Option<String>,
    pub approver: crate::security::ApproverBundle,
}

/// POST /api/agent/revoke — sign a revocation attestation with the session's
/// ephemeral key and forward the RevocationBundle to the agent.
pub async fn revoke_proxy(
    State(state): State<AppState>,
    session: Session,
    axum::Json(req): axum::Json<RevokeProxyRequest>,
) -> Result<Response, AppError> {
    use p256::ecdsa::signature::Signer;

    let profile = crate::web::require_profile(&session).await?;
    let signing_key = crate::web::load_signing_key(&profile)?;

    let payload =
        crate::security::revocation_payload(&req.approver.signature, &profile.public_key_pem);
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

    let bundle = crate::security::RevocationBundle {
        approver: req.approver,
        revoker: crate::security::RevokerAttestation {
            signature: hex::encode(signature_bytes),
            id_token: profile.id_token,
            public_key: profile.public_key_pem,
            timestamp_token: hex::encode(timestamp_token_bytes),
        },
    };

    let url = resolve_agent_url(&state, req.agent_url.as_deref())?
        .join("revoke")
        .map_err(|e| AppError::Internal(format!("URL join: {e}")))?;

    let resp = state
        .agent_http
        .post(url)
        .json(&bundle)
        .send()
        .await
        .map_err(|e| AppError::Internal(format!("Agent unreachable: {}", e.without_url())))?;

    passthrough(resp).await
}

#[derive(Deserialize)]
pub struct FilesProxyParams {
    #[serde(default)]
    pub agent_url: Option<String>,
}

/// GET /api/agent/files — list the agent's readable files. The session's
/// ID token is attached server-side; it never appears in a browser URL.
pub async fn files_proxy(
    State(state): State<AppState>,
    session: Session,
    Query(params): Query<FilesProxyParams>,
) -> Result<Response, AppError> {
    let profile = crate::web::require_profile(&session).await?;

    let url = resolve_agent_url(&state, params.agent_url.as_deref())?
        .join("api/files")
        .map_err(|e| AppError::Internal(format!("URL join: {e}")))?;

    let resp = state
        .agent_http
        .get(url)
        .bearer_auth(&profile.id_token)
        .send()
        .await
        .map_err(|e| AppError::Internal(format!("Agent unreachable: {}", e.without_url())))?;

    passthrough(resp).await
}

/// Relay an agent response. The body is always served as JSON with
/// `nosniff`: the agent only speaks JSON, and echoing its Content-Type would
/// let a misbehaving agent inject HTML/script into the signer's origin.
async fn passthrough(resp: reqwest::Response) -> Result<Response, AppError> {
    let status = axum::http::StatusCode::from_u16(resp.status().as_u16())
        .unwrap_or(axum::http::StatusCode::BAD_GATEWAY);
    let body = resp.bytes().await.map_err(|e| {
        AppError::Internal(format!("Agent response read failed: {}", e.without_url()))
    })?;
    let body = if serde_json::from_slice::<serde_json::Value>(&body).is_ok() {
        body.to_vec()
    } else {
        // Plain-text agent errors (e.g. "OPA Denied") become a JSON error.
        serde_json::to_vec(&serde_json::json!({ "error": String::from_utf8_lossy(&body) }))
            .unwrap_or_default()
    };
    Ok((
        status,
        [
            (axum::http::header::CONTENT_TYPE, "application/json"),
            (axum::http::header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        ],
        body,
    )
        .into_response())
}

#[derive(Deserialize)]
pub struct StreamProxyParams {
    #[serde(default)]
    pub agent_url: Option<String>,
    /// Execution id (exec stream) — UUID.
    pub id: Option<String>,
    /// File alias / path (file stream).
    pub name: Option<String>,
    pub path: Option<String>,
    pub tail_lines: Option<String>,
}

/// GET /ws/exec?id=… — proxy the agent's execution-log WebSocket.
pub async fn exec_stream_proxy(
    State(state): State<AppState>,
    session: Session,
    headers: axum::http::HeaderMap,
    Query(params): Query<StreamProxyParams>,
    ws: WebSocketUpgrade,
) -> Result<Response, AppError> {
    require_same_origin(&headers)?;
    let profile = crate::web::require_profile(&session).await?;

    let id = params
        .id
        .as_deref()
        .and_then(|s| uuid::Uuid::parse_str(s).ok())
        .ok_or_else(|| AppError::Internal("Missing or invalid execution id".into()))?;

    let mut url = resolve_agent_url(&state, params.agent_url.as_deref())?
        .join(&format!("stream/{id}"))
        .map_err(|e| AppError::Internal(format!("URL join: {e}")))?;
    url.set_scheme("wss")
        .map_err(|_| AppError::Internal("Failed to build wss URL".into()))?;

    let tls = state.agent_tls.clone();
    let token = profile.id_token;
    Ok(ws.on_upgrade(move |client| proxy_ws(client, url, tls, token)))
}

/// GET /ws/file?name=…|path=… — proxy the agent's file-stream WebSocket.
/// The session's ID token is attached upstream-side only.
pub async fn file_stream_proxy(
    State(state): State<AppState>,
    session: Session,
    headers: axum::http::HeaderMap,
    Query(params): Query<StreamProxyParams>,
    ws: WebSocketUpgrade,
) -> Result<Response, AppError> {
    require_same_origin(&headers)?;
    let profile = crate::web::require_profile(&session).await?;

    if params.name.is_none() && params.path.is_none() {
        return Err(AppError::Internal("Missing file name or path".into()));
    }

    let mut url = resolve_agent_url(&state, params.agent_url.as_deref())?
        .join("api/files/stream")
        .map_err(|e| AppError::Internal(format!("URL join: {e}")))?;
    {
        let mut qp = url.query_pairs_mut();
        if let Some(name) = &params.name {
            qp.append_pair("name", name);
        }
        if let Some(path) = &params.path {
            qp.append_pair("path", path);
        }
        if let Some(tail) = &params.tail_lines {
            qp.append_pair("tail_lines", tail);
        }
    }
    url.set_scheme("wss")
        .map_err(|_| AppError::Internal("Failed to build wss URL".into()))?;

    let tls = state.agent_tls.clone();
    let token = profile.id_token;
    Ok(ws.on_upgrade(move |client| proxy_ws(client, url, tls, token)))
}

/// Bidirectional pipe between the browser WebSocket and the agent WebSocket.
async fn proxy_ws(
    mut client: WebSocket,
    upstream_url: url::Url,
    tls: Arc<rustls::ClientConfig>,
    id_token: String,
) {
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;

    // The ID token rides in a header, never the URL (URLs end up in logs).
    let request = upstream_url
        .as_str()
        .into_client_request()
        .map_err(|e| e.to_string())
        .and_then(|mut req| {
            let value = format!("Bearer {id_token}")
                .parse()
                .map_err(|_| "Invalid token for header".to_string())?;
            req.headers_mut()
                .insert(axum::http::header::AUTHORIZATION, value);
            Ok(req)
        });
    let request = match request {
        Ok(r) => r,
        Err(e) => {
            let _ = client
                .send(AxumMessage::Text(format!("[proxy] Bad upstream request: {e}").into()))
                .await;
            let _ = client.close().await;
            return;
        }
    };

    let connector = tokio_tungstenite::Connector::Rustls(tls);
    let upstream = match tokio_tungstenite::connect_async_tls_with_config(
        request,
        None,
        false,
        Some(connector),
    )
    .await
    {
        Ok((stream, _resp)) => stream,
        Err(e) => {
            let _ = client
                .send(AxumMessage::Text(
                    format!("[proxy] Failed to reach agent: {e}").into(),
                ))
                .await;
            let _ = client.close().await;
            return;
        }
    };

    let (mut up_tx, mut up_rx) = upstream.split();
    let (mut cl_tx, mut cl_rx) = client.split();

    loop {
        tokio::select! {
            msg = up_rx.next() => match msg {
                Some(Ok(TungsteniteMessage::Text(t))) => {
                    if cl_tx.send(AxumMessage::Text(t.as_str().to_string().into())).await.is_err() {
                        break;
                    }
                }
                Some(Ok(TungsteniteMessage::Binary(b))) => {
                    if cl_tx.send(AxumMessage::Binary(b.to_vec().into())).await.is_err() {
                        break;
                    }
                }
                Some(Ok(TungsteniteMessage::Ping(_) | TungsteniteMessage::Pong(_))) => {}
                _ => break, // Close, error, or stream end
            },
            msg = cl_rx.next() => match msg {
                Some(Ok(AxumMessage::Text(t))) => {
                    if up_tx.send(TungsteniteMessage::Text(t.as_str().to_string().into())).await.is_err() {
                        break;
                    }
                }
                Some(Ok(AxumMessage::Close(_))) | None => {
                    let _ = up_tx.send(TungsteniteMessage::Close(None)).await;
                    break;
                }
                Some(Ok(_)) => {}
                Some(Err(_)) => break,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn url(s: &str) -> url::Url {
        s.parse().unwrap()
    }

    #[test]
    fn same_origin_accepts_matching_host_and_port() {
        assert!(origin_matches_host(&url("http://localhost:8080"), "localhost:8080"));
        assert!(origin_matches_host(&url("http://127.0.0.1:8080"), "127.0.0.1:8080"));
        assert!(origin_matches_host(&url("https://signer.local"), "signer.local"));
    }

    #[test]
    fn same_origin_rejects_other_ports_and_hosts() {
        // Another app on a different localhost port is "same-site" for
        // cookies but must not reach the WebSocket proxies.
        assert!(!origin_matches_host(&url("http://localhost:3000"), "localhost:8080"));
        assert!(!origin_matches_host(&url("http://evil.example:8080"), "localhost:8080"));
        assert!(!origin_matches_host(&url("http://localhost"), "localhost:8080"));
    }
}
