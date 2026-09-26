//! `remonce cosign` — headless operator co-signing.
//!
//! Reads an approver bundle (JSON or the base64 token the UI produces),
//! authenticates the operator via an OIDC authorization-code flow with a
//! loopback redirect (PKCE + nonce bound to a fresh ephemeral key, forced
//! re-authentication), co-signs, timestamps, and emits a ready-to-submit
//! `ExecutionBundle` — optionally POSTing it straight to the agent.

use crate::config::Config;
use crate::security::{ApproverBundle, ExecutionBundle, OperatorCosign};
use base64::Engine as _;

pub struct CosignArgs {
    /// Path to the approver bundle, or "-" for stdin.
    pub bundle: String,
    /// Agent URL override (defaults to config `agent_url`).
    pub agent: Option<String>,
    /// Write the cosigned bundle here instead of stdout.
    pub output: Option<String>,
    /// Submit to the agent after cosigning.
    pub submit: bool,
}

type Error = Box<dyn std::error::Error>;

pub async fn run(args: CosignArgs, insecure: bool) -> Result<(), Error> {
    let config_str = std::fs::read_to_string("config.toml")
        .map_err(|e| format!("Failed to read config.toml: {e}"))?;
    let config: Config = toml::from_str(&config_str)?;

    let insecure_mode = crate::insecure::validate(&config, insecure)
        .map_err(|e| -> Error { e.to_string().into() })?;
    crate::audit::set_insecure_mode(insecure_mode.as_bool());

    // 1. Read + parse the approver bundle.
    let raw = if args.bundle == "-" {
        use std::io::Read;
        let mut buf = String::new();
        std::io::stdin().read_to_string(&mut buf)?;
        buf
    } else {
        std::fs::read_to_string(&args.bundle)
            .map_err(|e| format!("Failed to read bundle '{}': {e}", args.bundle))?
    };
    let approver = parse_approver_bundle(raw.trim())?;
    if approver.operator_requires.is_none() {
        return Err("This approval is self-execute only (no operator_requires); it cannot be \
                    co-signed. Ask the approver for a delegated approval."
            .into());
    }

    let command_str = serde_json::to_string_pretty(&approver.command)?;
    eprintln!("Approver bundle loaded. Command:\n{command_str}");
    if let Some(req) = &approver.operator_requires {
        eprintln!(
            "Operator requirements: {}",
            serde_json::to_string(req).unwrap_or_default()
        );
    }

    // 2. Ephemeral key + its own OIDC login (nonce-bound, re-authenticated).
    let ephemeral = crate::signing::new_ephemeral()?;
    let id_token = oidc_login(&config, &ephemeral.nonce).await?;
    eprintln!("OIDC login complete.");

    // 3. Cosign over (approver_sig_hex || operator_pubkey_pem), timestamped.
    let payload = crate::security::operator_payload(&approver.signature, &ephemeral.public_key_pem);
    let a = crate::signing::attest(
        &crate::http_client(),
        &config.timestamp_authority.url,
        &ephemeral.key,
        &ephemeral.public_key_pem,
        id_token,
        &payload,
    )
    .await?;

    let bundle = ExecutionBundle {
        operator: Some(OperatorCosign {
            approver_sig: approver.signature.clone(),
            signature: a.signature,
            id_token: a.id_token,
            public_key: a.public_key,
            timestamp_token: a.timestamp_token,
        }),
        approver,
    };

    let bundle_json = serde_json::to_string_pretty(&bundle)?;

    if let Some(path) = &args.output {
        std::fs::write(path, &bundle_json)?;
        eprintln!("Cosigned bundle written to {path}");
    } else if !args.submit {
        println!("{bundle_json}");
    }

    // 5. Optional submit.
    if args.submit {
        let agent_url = submit_url(&config, args.agent.as_deref(), "/execute")?;
        eprintln!("Submitting to {agent_url} ...");
        let client = crate::agent_proxy::build_agent_http(config.agent_ca_path.as_deref())
            .map_err(|e| -> Error { e.into() })?;
        let resp = client.post(agent_url).json(&bundle).send().await?;
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        if status.is_success() {
            eprintln!("Agent accepted execution:");
            println!("{body}");
        } else {
            return Err(format!("Agent rejected ({status}): {body}").into());
        }
    }

    Ok(())
}

/// Accepts a bare `ApproverBundle`, a full `ExecutionBundle` (operator is
/// discarded — we re-cosign), or either of those base64-encoded (the UI's
/// copyable token format).
fn parse_approver_bundle(raw: &str) -> Result<ApproverBundle, Error> {
    let json_str = if raw.starts_with('{') {
        raw.to_string()
    } else {
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(raw)
            .map_err(|_| "Input is neither JSON nor base64")?;
        String::from_utf8(decoded).map_err(|_| "Base64 payload is not UTF-8")?
    };

    if let Ok(bundle) = serde_json::from_str::<ExecutionBundle>(&json_str) {
        return Ok(bundle.approver);
    }
    serde_json::from_str::<ApproverBundle>(&json_str)
        .map_err(|e| format!("Failed to parse approver bundle: {e}").into())
}

fn submit_url(config: &Config, agent_override: Option<&str>, path: &str) -> Result<url::Url, Error> {
    let raw = agent_override
        .filter(|s| !s.trim().is_empty())
        .unwrap_or(&config.agent_url);
    let mut parsed: url::Url = raw.trim().parse()?;
    if parsed.scheme() != "https" {
        return Err(format!("Agent URL must be https (got '{raw}')").into());
    }
    parsed.set_path(path);
    parsed.set_query(None);
    Ok(parsed)
}

pub struct RevokeArgs {
    /// Path to the approver bundle, or "-" for stdin.
    pub bundle: String,
    /// Agent URL override (defaults to config `agent_url`).
    pub agent: Option<String>,
}

/// `remonce revoke` — revoke an approver bundle on an agent. Authenticates
/// the revoker via the same nonce-bound OIDC flow as cosigning, signs the
/// domain-separated revocation payload, and submits to the agent's /revoke.
pub async fn run_revoke(args: RevokeArgs, insecure: bool) -> Result<(), Error> {
    let config_str = std::fs::read_to_string("config.toml")
        .map_err(|e| format!("Failed to read config.toml: {e}"))?;
    let config: Config = toml::from_str(&config_str)?;

    let insecure_mode = crate::insecure::validate(&config, insecure)
        .map_err(|e| -> Error { e.to_string().into() })?;
    crate::audit::set_insecure_mode(insecure_mode.as_bool());

    let raw = if args.bundle == "-" {
        use std::io::Read;
        let mut buf = String::new();
        std::io::stdin().read_to_string(&mut buf)?;
        buf
    } else {
        std::fs::read_to_string(&args.bundle)
            .map_err(|e| format!("Failed to read bundle '{}': {e}", args.bundle))?
    };
    let approver = parse_approver_bundle(raw.trim())?;

    let command_str = serde_json::to_string_pretty(&approver.command)?;
    eprintln!("Approver bundle loaded. Command to revoke:\n{command_str}");

    let ephemeral = crate::signing::new_ephemeral()?;
    let id_token = oidc_login(&config, &ephemeral.nonce).await?;
    eprintln!("OIDC login complete.");

    let payload =
        crate::security::revocation_payload(&approver.signature, &ephemeral.public_key_pem);
    let a = crate::signing::attest(
        &crate::http_client(),
        &config.timestamp_authority.url,
        &ephemeral.key,
        &ephemeral.public_key_pem,
        id_token,
        &payload,
    )
    .await?;

    let bundle = crate::security::RevocationBundle {
        approver,
        revoker: crate::security::RevokerAttestation {
            signature: a.signature,
            id_token: a.id_token,
            public_key: a.public_key,
            timestamp_token: a.timestamp_token,
        },
    };

    let agent_url = submit_url(&config, args.agent.as_deref(), "/revoke")?;
    eprintln!("Submitting revocation to {agent_url} ...");
    let client = crate::agent_proxy::build_agent_http(config.agent_ca_path.as_deref())
        .map_err(|e| -> Error { e.into() })?;
    let resp = client.post(agent_url).json(&bundle).send().await?;
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    if status.is_success() {
        eprintln!("Agent accepted revocation:");
        println!("{body}");
        Ok(())
    } else {
        Err(format!("Agent rejected ({status}): {body}").into())
    }
}

/// Authorization-code flow against the signing client, with PKCE, the nonce
/// bound to the ephemeral key, and forced re-authentication. Binds the
/// configured loopback `redirect_uri` to receive the callback, prints the
/// authorization URL for the operator to open, and returns the validated ID
/// token.
async fn oidc_login(config: &Config, nonce: &str) -> Result<String, Error> {
    let http_client = crate::http_client();
    let (metadata, jwks) = crate::oidc_client::discover(&http_client, &config.oidc.issuer_url)
        .await
        .map_err(|e| -> Error { e.into() })?;

    let oidc_state = crate::oidc_client::random_token();
    let (pkce_challenge, pkce_verifier) = crate::oidc_client::pkce_pair();

    let redirect_uri = config.get_redirect_uri();
    let redirect_parsed: url::Url = redirect_uri.parse()?;
    let host = redirect_parsed
        .host_str()
        .ok_or("redirect_uri has no host")?;
    let port = redirect_parsed
        .port_or_known_default()
        .ok_or("redirect_uri has no port")?;
    let callback_path = redirect_parsed.path().to_string();
    let is_loopback = host.eq_ignore_ascii_case("localhost")
        || host
            .trim_matches(|c| c == '[' || c == ']')
            .parse::<std::net::IpAddr>()
            .map(|ip| ip.is_loopback())
            .unwrap_or(false);
    if !is_loopback {
        return Err(format!(
            "oidc.redirect_uri host '{host}' is not loopback; the CLI only listens on \
             loopback for the OIDC callback"
        )
        .into());
    }

    let auth_url = crate::oidc_client::authorize_url(
        &metadata,
        &crate::oidc_client::AuthorizeParams {
            client_id: &config.oidc.client_id,
            redirect_uri: &redirect_uri,
            state: &oidc_state,
            nonce,
            pkce_challenge: &pkce_challenge,
            reauth: Some(crate::oidc_client::Reauth::from_config(&config.oidc)),
        },
    )
    .map_err(|e| -> Error { e.into() })?;

    // Bind the redirect address. This requires `remonce web` to not be running
    // on the same port — the CLI takes its place for the duration of the login.
    let listener = tokio::net::TcpListener::bind((host, port))
        .await
        .map_err(|e| {
            format!(
                "Cannot bind redirect address {host}:{port} ({e}). \
                 If `remonce web` is running, use its pages instead."
            )
        })?;

    let started_at = time::OffsetDateTime::now_utc();
    eprintln!(
        "\nEach signature needs its own login: open this URL in a browser and \
         re-authenticate:\n\n  {auth_url}\n"
    );
    eprintln!("Waiting for the OIDC callback on {host}:{port} ...");

    let code = wait_for_callback(listener, &callback_path, &oidc_state).await?;

    let id_token = crate::oidc_client::exchange_code(
        &http_client,
        &metadata,
        &config.oidc.client_id,
        &redirect_uri,
        &code,
        &pkce_verifier,
    )
    .await
    .map_err(|e| -> Error { e.into() })?;

    crate::oidc_client::validate_id_token(
        &id_token,
        &jwks,
        &config.oidc.issuer_url,
        &config.oidc.client_id,
        nonce,
        Some(started_at),
    )
    .map_err(|e| -> Error { e.into() })?;

    Ok(id_token)
}

/// Minimal one-shot HTTP server: accept connections until one carries the
/// expected callback with a matching `state`, respond with a close-this-tab
/// page, and return the authorization code. 5-minute overall timeout.
async fn wait_for_callback(
    listener: tokio::net::TcpListener,
    callback_path: &str,
    expected_state: &str,
) -> Result<String, Error> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(300);

    loop {
        let (mut stream, _) = tokio::time::timeout_at(deadline, listener.accept())
            .await
            .map_err(|_| "Timed out waiting for OIDC callback (5 minutes)")??;

        let mut buf = vec![0u8; 8192];
        let n = match tokio::time::timeout(
            std::time::Duration::from_secs(10),
            stream.read(&mut buf),
        )
        .await
        {
            Ok(Ok(n)) if n > 0 => n,
            _ => continue,
        };
        let request = String::from_utf8_lossy(&buf[..n]);

        // Parse the request line: GET <path>?<query> HTTP/1.1
        let Some(target) = request
            .lines()
            .next()
            .and_then(|l| l.split_whitespace().nth(1))
        else {
            continue;
        };
        let parsed = match url::Url::parse(&format!("http://localhost{target}")) {
            Ok(u) => u,
            Err(_) => continue,
        };
        if parsed.path() != callback_path {
            let _ = stream
                .write_all(b"HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n")
                .await;
            continue;
        }

        let mut code = None;
        let mut state_param = None;
        let mut error = None;
        for (k, v) in parsed.query_pairs() {
            match k.as_ref() {
                "code" => code = Some(v.to_string()),
                "state" => state_param = Some(v.to_string()),
                "error" => error = Some(v.to_string()),
                _ => {}
            }
        }

        let respond = |body: &str| {
            format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            )
        };

        // State first: without it, any web page could abort the login by
        // sending the browser to `/callback?error=x`.
        if state_param.as_deref() != Some(expected_state) {
            let _ = stream
                .write_all(respond("<h1>State mismatch</h1>Ignoring request.").as_bytes())
                .await;
            continue;
        }

        if let Some(err) = error {
            let _ = stream
                .write_all(respond("<h1>Login failed</h1>You can close this tab.").as_bytes())
                .await;
            return Err(format!("OIDC error: {err}").into());
        }

        let Some(code) = code else {
            let _ = stream
                .write_all(respond("<h1>Missing code</h1>Ignoring request.").as_bytes())
                .await;
            continue;
        };

        let _ = stream
            .write_all(
                respond("<h1>Authenticated</h1>You can close this tab and return to the terminal.")
                    .as_bytes(),
            )
            .await;
        return Ok(code);
    }
}
