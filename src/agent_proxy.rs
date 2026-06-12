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
    let mut builder = reqwest::Client::builder();
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

/// Resolve and validate the target agent URL. Only https is accepted —
/// the agent has no plaintext mode.
fn resolve_agent_url(state: &AppState, override_url: Option<&str>) -> Result<url::Url, AppError> {
    let raw = override_url
        .filter(|s| !s.trim().is_empty())
        .unwrap_or(&state.config.agent_url);
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
        .map_err(|e| AppError::Internal(format!("Agent unreachable: {e}")))?;

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
        .map_err(|e| AppError::Internal(format!("Agent unreachable: {e}")))?;

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

    let mut url = resolve_agent_url(&state, params.agent_url.as_deref())?
        .join("api/files")
        .map_err(|e| AppError::Internal(format!("URL join: {e}")))?;
    url.query_pairs_mut().append_pair("token", &profile.id_token);

    let resp = state
        .agent_http
        .get(url)
        .send()
        .await
        .map_err(|e| AppError::Internal(format!("Agent unreachable: {e}")))?;

    passthrough(resp).await
}

async fn passthrough(resp: reqwest::Response) -> Result<Response, AppError> {
    let status = axum::http::StatusCode::from_u16(resp.status().as_u16())
        .unwrap_or(axum::http::StatusCode::BAD_GATEWAY);
    let content_type = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/json")
        .to_string();
    let body = resp
        .bytes()
        .await
        .map_err(|e| AppError::Internal(format!("Agent response read failed: {e}")))?;
    Ok((
        status,
        [(axum::http::header::CONTENT_TYPE, content_type)],
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
    Query(params): Query<StreamProxyParams>,
    ws: WebSocketUpgrade,
) -> Result<Response, AppError> {
    crate::web::require_profile(&session).await?;

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
    Ok(ws.on_upgrade(move |client| proxy_ws(client, url, tls)))
}

/// GET /ws/file?name=…|path=… — proxy the agent's file-stream WebSocket.
/// The session's ID token is attached upstream-side only.
pub async fn file_stream_proxy(
    State(state): State<AppState>,
    session: Session,
    Query(params): Query<StreamProxyParams>,
    ws: WebSocketUpgrade,
) -> Result<Response, AppError> {
    let profile = crate::web::require_profile(&session).await?;

    if params.name.is_none() && params.path.is_none() {
        return Err(AppError::Internal("Missing file name or path".into()));
    }

    let mut url = resolve_agent_url(&state, params.agent_url.as_deref())?
        .join("api/files/stream")
        .map_err(|e| AppError::Internal(format!("URL join: {e}")))?;
    {
        let mut qp = url.query_pairs_mut();
        qp.append_pair("token", &profile.id_token);
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
    Ok(ws.on_upgrade(move |client| proxy_ws(client, url, tls)))
}

/// Bidirectional pipe between the browser WebSocket and the agent WebSocket.
async fn proxy_ws(mut client: WebSocket, upstream_url: url::Url, tls: Arc<rustls::ClientConfig>) {
    let connector = tokio_tungstenite::Connector::Rustls(tls);
    let upstream = match tokio_tungstenite::connect_async_tls_with_config(
        upstream_url.as_str(),
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
