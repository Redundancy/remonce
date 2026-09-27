//! Headless request handling: `remonce approve`, `remonce submit` and
//! `remonce revoke`.
//!
//! Each signature gets its own OIDC login to the signing client via an
//! authorization-code flow with a loopback redirect (PKCE, nonce bound to a
//! fresh ephemeral key, forced re-authentication). Submitting is an ordinary
//! login to the viewer client: whoever submits is the executor, identified
//! to the agent and subject to its policy.

use crate::config::Config;
use crate::security::{RequestBundle, RevocationBundle};

type Error = Box<dyn std::error::Error>;

pub struct ApproveArgs {
    /// Path to the request (with or without approvals), or "-" for stdin.
    pub bundle: String,
    /// Write the approved request here instead of stdout.
    pub output: Option<String>,
}

pub struct SubmitArgs {
    /// Path to the approved request, or "-" for stdin.
    pub bundle: String,
    /// Agent URL override (defaults to config `agent_url`).
    pub agent: Option<String>,
}

pub struct RevokeArgs {
    /// Path to the approved request, or "-" for stdin.
    pub bundle: String,
    /// Agent URL override (defaults to config `agent_url`).
    pub agent: Option<String>,
}

fn load_config(insecure: bool) -> Result<Config, Error> {
    let config = crate::config::load("config.toml")?;
    let insecure_mode = crate::insecure::validate(&config, insecure)
        .map_err(|e| -> Error { e.to_string().into() })?;
    crate::audit::set_insecure_mode(insecure_mode.as_bool());
    Ok(config)
}

fn read_input(path: &str) -> Result<String, Error> {
    if path == "-" {
        use std::io::Read;
        let mut buf = String::new();
        std::io::stdin().read_to_string(&mut buf)?;
        Ok(buf)
    } else {
        std::fs::read_to_string(path).map_err(|e| format!("Failed to read '{path}': {e}").into())
    }
}

/// Parse a request file: `{"command": {…}, "approvals": […]}`, or a bare
/// command object (`{"command": "name", "id": …}`) as an unapproved request.
fn parse_request(raw: &str) -> Result<RequestBundle, Error> {
    let value: serde_json::Value =
        serde_json::from_str(raw.trim()).map_err(|e| format!("Not a JSON request: {e}"))?;
    if value.get("approver").is_some() || value.get("operator_requires").is_some() {
        return Err("This file was made by an older version of Remonce (approver/operator \
                    bundles). Requests now collect independent approvals; create the request \
                    again and approve it."
            .into());
    }
    if value.get("command").is_some_and(|c| c.is_string()) {
        return Ok(RequestBundle {
            command: value,
            approvals: Vec::new(),
        });
    }
    let bundle: RequestBundle =
        serde_json::from_value(value).map_err(|e| format!("Not a Remonce request: {e}"))?;
    if !bundle.command.is_object() {
        return Err("The request's command must be a JSON object".into());
    }
    Ok(bundle)
}

fn describe(bundle: &RequestBundle) -> Result<(), Error> {
    eprintln!("Request {}:", crate::security::request_id(&bundle.command));
    eprintln!("{}", serde_json::to_string_pretty(&bundle.command)?);
    let approvers: Vec<String> = bundle
        .approvals
        .iter()
        .map(|a| crate::security::claimed_subject(&a.id_token).unwrap_or_else(|| "?".into()))
        .collect();
    if approvers.is_empty() {
        eprintln!("No approvals yet.");
    } else {
        // Claimed, not verified: the agent verifies every approval.
        eprintln!("Approvals so far (subjects, as claimed): {}", approvers.join(", "));
    }
    Ok(())
}

/// `remonce approve` — add your approval to a request.
pub async fn run_approve(args: ApproveArgs, insecure: bool) -> Result<(), Error> {
    let config = load_config(insecure)?;
    let mut bundle = parse_request(&read_input(&args.bundle)?)?;
    let id_ok = bundle
        .command
        .get("id")
        .and_then(|v| v.as_str())
        .is_some_and(|id| uuid::Uuid::parse_str(id).is_ok());
    if !id_ok {
        return Err("The request needs a UUID 'id'".into());
    }
    if bundle.approvals.len() >= crate::security::MAX_APPROVALS {
        return Err("This request already carries the maximum number of approvals".into());
    }
    describe(&bundle)?;

    let ephemeral = crate::signing::new_ephemeral()?;
    let (id_token, claims) = oidc_login(&config, &config.oidc.client_id, &ephemeral.nonce, true).await?;
    eprintln!("OIDC login complete.");

    // Two approvals must be two people; the agent enforces it too.
    let sub = claims.get("sub").and_then(|v| v.as_str()).unwrap_or_default();
    if bundle
        .approvals
        .iter()
        .any(|a| crate::security::claimed_subject(&a.id_token).as_deref() == Some(sub))
    {
        return Err("You have already approved this request; another person must add the next approval".into());
    }

    let payload = crate::security::canonical_request_payload(&bundle.command);
    let approval = crate::signing::attest(
        &crate::http_client(),
        &config.timestamp_authority.url,
        &ephemeral.key,
        &ephemeral.public_key_pem,
        id_token,
        payload.as_bytes(),
    )
    .await?;
    bundle.approvals.push(approval);

    let json = serde_json::to_string_pretty(&bundle)?;
    match &args.output {
        Some(path) => {
            std::fs::write(path, &json)?;
            eprintln!("Approved request ({} approval(s)) written to {path}", bundle.approvals.len());
        }
        None => println!("{json}"),
    }
    Ok(())
}

/// `remonce submit` — run an approved request on an agent, as yourself.
pub async fn run_submit(args: SubmitArgs, insecure: bool) -> Result<(), Error> {
    let config = load_config(insecure)?;
    let bundle = parse_request(&read_input(&args.bundle)?)?;
    if bundle.approvals.is_empty() {
        return Err("This request has no approvals yet; run `remonce approve` first".into());
    }
    describe(&bundle)?;
    let viewer_client_id = config
        .oidc
        .viewer_client_id
        .clone()
        .ok_or("oidc.viewer_client_id must be set: submitting identifies you with the viewer client")?;

    // An ordinary login: the nonce only ties the token to this flow.
    let nonce = crate::oidc_client::random_token();
    let (viewer_token, _) = oidc_login(&config, &viewer_client_id, &nonce, false).await?;
    eprintln!("OIDC login complete.");

    let agent_url = submit_url(&config, args.agent.as_deref(), "/execute")?;
    eprintln!("Submitting to {agent_url} ...");
    let client = crate::agent_proxy::build_agent_http(config.agent_ca_path.as_deref())
        .map_err(|e| -> Error { e.into() })?;
    let resp = client
        .post(agent_url)
        .bearer_auth(&viewer_token)
        .json(&bundle)
        .send()
        .await?;
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    if status.is_success() {
        eprintln!("Agent accepted execution:");
        println!("{body}");
        Ok(())
    } else {
        Err(format!("Agent rejected ({status}): {body}").into())
    }
}

/// `remonce revoke` — cancel an approved request on an agent. Approvers may
/// always revoke; anyone else needs policy's permission.
pub async fn run_revoke(args: RevokeArgs, insecure: bool) -> Result<(), Error> {
    let config = load_config(insecure)?;
    let request = parse_request(&read_input(&args.bundle)?)?;
    if request.approvals.is_empty() {
        return Err("Only an approved request can be revoked; an unapproved one can't run".into());
    }
    describe(&request)?;

    let ephemeral = crate::signing::new_ephemeral()?;
    let (id_token, _) = oidc_login(&config, &config.oidc.client_id, &ephemeral.nonce, true).await?;
    eprintln!("OIDC login complete.");

    let request_id = crate::security::request_id(&request.command);
    let payload = crate::security::revocation_payload(&request_id, &ephemeral.public_key_pem);
    let revoker = crate::signing::attest(
        &crate::http_client(),
        &config.timestamp_authority.url,
        &ephemeral.key,
        &ephemeral.public_key_pem,
        id_token,
        &payload,
    )
    .await?;
    let bundle = RevocationBundle { request, revoker };

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

/// Authorization-code flow against `client_id` with PKCE and `nonce`. For a
/// signature (`reauth`), the nonce is bound to the ephemeral key and the
/// login must re-authenticate. Binds the configured loopback `redirect_uri`
/// to receive the callback, prints the authorization URL to open, and
/// returns the validated ID token and its claims.
async fn oidc_login(
    config: &Config,
    client_id: &str,
    nonce: &str,
    reauth: bool,
) -> Result<(String, serde_json::Value), Error> {
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
            client_id,
            redirect_uri: &redirect_uri,
            state: &oidc_state,
            nonce,
            pkce_challenge: &pkce_challenge,
            reauth: reauth.then(|| crate::oidc_client::Reauth::from_config(&config.oidc)),
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
    if reauth {
        eprintln!(
            "\nEach signature needs its own login: open this URL in a browser and \
             re-authenticate:\n\n  {auth_url}\n"
        );
    } else {
        eprintln!("\nOpen this URL in a browser to log in:\n\n  {auth_url}\n");
    }
    eprintln!("Waiting for the OIDC callback on {host}:{port} ...");

    let code = wait_for_callback(listener, &callback_path, &oidc_state).await?;

    let id_token = crate::oidc_client::exchange_code(
        &http_client,
        &metadata,
        client_id,
        &redirect_uri,
        &code,
        &pkce_verifier,
    )
    .await
    .map_err(|e| -> Error { e.into() })?;

    let claims = crate::oidc_client::validate_id_token(
        &id_token,
        &jwks,
        &config.oidc.issuer_url,
        client_id,
        nonce,
        reauth.then_some(started_at),
    )
    .map_err(|e| -> Error { e.into() })?;

    Ok((id_token, claims))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bare_command_is_an_unapproved_request() {
        let b = parse_request(r#"{"command":"ping","id":"x"}"#).unwrap();
        assert_eq!(b.command["command"], "ping");
        assert!(b.approvals.is_empty());
    }

    #[test]
    fn request_with_approvals_parses() {
        let b = parse_request(r#"{"command":{"command":"ping"},"approvals":[]}"#).unwrap();
        assert_eq!(b.command["command"], "ping");
    }

    #[test]
    fn older_bundles_get_a_clear_error() {
        let err = parse_request(r#"{"approver":{"command":{}}}"#).unwrap_err().to_string();
        assert!(err.contains("older version"), "{err}");
        let err = parse_request(r#"{"command":{"command":"x"},"operator_requires":null}"#)
            .unwrap_err()
            .to_string();
        assert!(err.contains("older version"), "{err}");
    }
}
