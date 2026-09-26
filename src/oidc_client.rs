//! OIDC authorization-code + PKCE plumbing shared by the local signer
//! (`remonce web`) and the CLI (`remonce cosign` / `remonce revoke`).
//!
//! Two kinds of login go through here:
//!
//! - **Viewer logins** (web only) use `viewer_client_id` and a random nonce.
//!   The token is a bearer credential for browsing files and logs.
//! - **Signing logins** use the signing `client_id`, a nonce bound to a fresh
//!   ephemeral key, and forced re-authentication (`max_age`, optionally
//!   `prompt=login`). One login signs exactly one thing.

use crate::config::OidcConfig;
use crate::web::OidcMetadata;
use rand::{RngCore, rngs::OsRng};
use sha2::{Digest, Sha256};

const SCOPES: &str = "openid groups user_profile";

/// Re-authentication parameters for a signing login.
#[derive(Clone, Copy, Debug)]
pub struct Reauth {
    pub max_age: std::time::Duration,
    pub prompt_login: bool,
}

impl Reauth {
    pub fn from_config(oidc: &OidcConfig) -> Self {
        Self {
            max_age: oidc.signing_max_age_or_default(),
            prompt_login: oidc.signing_prompt_login,
        }
    }
}

/// A PKCE `(challenge, verifier)` pair (S256).
pub fn pkce_pair() -> (String, String) {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    let verifier = URL_SAFE_NO_PAD.encode(bytes);
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    (challenge, verifier)
}

/// 32 random bytes, hex-encoded: OIDC `state` and viewer-login nonces.
pub fn random_token() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

pub struct AuthorizeParams<'a> {
    pub client_id: &'a str,
    pub redirect_uri: &'a str,
    pub state: &'a str,
    pub nonce: &'a str,
    pub pkce_challenge: &'a str,
    /// Set for signing logins; forces re-authentication.
    pub reauth: Option<Reauth>,
}

/// Build the IdP authorization URL.
pub fn authorize_url(meta: &OidcMetadata, p: &AuthorizeParams<'_>) -> Result<url::Url, String> {
    let mut url: url::Url = meta
        .authorization_endpoint
        .parse()
        .map_err(|_| "Invalid authorization_endpoint URL".to_string())?;
    {
        let mut q = url.query_pairs_mut();
        q.append_pair("response_type", "code")
            .append_pair("client_id", p.client_id)
            .append_pair("redirect_uri", p.redirect_uri)
            .append_pair("scope", SCOPES)
            .append_pair("state", p.state)
            .append_pair("nonce", p.nonce)
            .append_pair("code_challenge", p.pkce_challenge)
            .append_pair("code_challenge_method", "S256");
        if let Some(r) = p.reauth {
            q.append_pair("max_age", &r.max_age.as_secs().to_string());
            if r.prompt_login {
                q.append_pair("prompt", "login");
            }
        }
    }
    Ok(url)
}

/// Exchange an authorization code for the ID token.
pub async fn exchange_code(
    http: &reqwest::Client,
    meta: &OidcMetadata,
    client_id: &str,
    redirect_uri: &str,
    code: &str,
    pkce_verifier: &str,
) -> Result<String, String> {
    #[derive(serde::Deserialize)]
    struct TokenResponse {
        id_token: String,
    }
    let resp = http
        .post(&meta.token_endpoint)
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", redirect_uri),
            ("client_id", client_id),
            ("code_verifier", pkce_verifier),
        ])
        .send()
        .await
        .map_err(|e| format!("Token request failed: {}", e.without_url()))?
        .error_for_status()
        .map_err(|e| format!("Token endpoint rejected the code: {}", e.without_url()))?;
    let token: TokenResponse = resp
        .json()
        .await
        .map_err(|e| format!("Invalid token response: {}", e.without_url()))?;
    Ok(token.id_token)
}

/// Validate a freshly-obtained ID token: JWKS signature, issuer, `exp`,
/// strict audience, and the expected `nonce`. For signing logins pass
/// `fresh_auth_since` (the instant the login started): the token must then
/// carry `iat` and `auth_time` showing a real re-authentication after that
/// point — so an IdP that ignores `max_age` fails loudly here rather than
/// with a baffling rejection at the agent.
pub fn validate_id_token(
    token: &str,
    jwks: &jsonwebtoken::jwk::JwkSet,
    issuer: &str,
    client_id: &str,
    expected_nonce: &str,
    fresh_auth_since: Option<time::OffsetDateTime>,
) -> Result<serde_json::Value, String> {
    let claims = crate::security::verify_bearer_token(token, jwks, issuer, client_id)
        .map_err(|e| e.to_string())?;

    if claims.get("nonce").and_then(|v| v.as_str()) != Some(expected_nonce) {
        return Err("Nonce mismatch: the ID token is not bound to this login".into());
    }

    if let Some(since) = fresh_auth_since {
        let read = |name: &str| {
            claims
                .get(name)
                .and_then(|v| v.as_i64().or_else(|| v.as_f64().map(|f| f.floor() as i64)))
                .and_then(|s| time::OffsetDateTime::from_unix_timestamp(s).ok())
        };
        let hint = "check oidc.signing_max_age / oidc.signing_prompt_login and that the IdP \
                    honors max_age";
        let iat = read("iat").ok_or("The ID token has no `iat` claim")?;
        let auth_time = read("auth_time").ok_or_else(|| {
            format!("The IdP did not return `auth_time` for a re-authentication; {hint}")
        })?;
        if auth_time < since - crate::security::MAX_FUTURE_SKEW {
            return Err(format!(
                "The IdP did not re-authenticate you (auth_time predates this login); {hint}"
            ));
        }
        if iat - auth_time > crate::security::MAX_AUTH_AGE {
            return Err(format!("The IdP returned a stale authentication; {hint}"));
        }
    }

    Ok(claims)
}

/// Discover the IdP metadata and fetch its JWKS.
pub async fn discover(
    http: &reqwest::Client,
    issuer_url: &str,
) -> Result<(OidcMetadata, jsonwebtoken::jwk::JwkSet), String> {
    let discovery_url = format!("{issuer_url}/.well-known/openid-configuration");
    let meta: OidcMetadata = http
        .get(&discovery_url)
        .send()
        .await
        .map_err(|e| format!("OIDC discovery failed: {}", e.without_url()))?
        .json()
        .await
        .map_err(|e| format!("Invalid OIDC discovery document: {}", e.without_url()))?;
    let jwks = http
        .get(&meta.jwks_uri)
        .send()
        .await
        .map_err(|e| format!("JWKS fetch failed: {}", e.without_url()))?
        .json()
        .await
        .map_err(|e| format!("Invalid JWKS: {}", e.without_url()))?;
    Ok((meta, jwks))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta() -> OidcMetadata {
        OidcMetadata {
            authorization_endpoint: "https://idp.example/authorize".into(),
            token_endpoint: "https://idp.example/token".into(),
            jwks_uri: "https://idp.example/jwks".into(),
        }
    }

    fn params(reauth: Option<Reauth>) -> url::Url {
        authorize_url(
            &meta(),
            &AuthorizeParams {
                client_id: "signing",
                redirect_uri: "http://localhost:8080/oidc/callback",
                state: "s",
                nonce: "n",
                pkce_challenge: "c",
                reauth,
            },
        )
        .unwrap()
    }

    fn query(url: &url::Url, key: &str) -> Option<String> {
        url.query_pairs()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.into_owned())
    }

    #[test]
    fn signing_login_forces_reauth() {
        let url = params(Some(Reauth {
            max_age: std::time::Duration::ZERO,
            prompt_login: true,
        }));
        assert_eq!(query(&url, "max_age").as_deref(), Some("0"));
        assert_eq!(query(&url, "prompt").as_deref(), Some("login"));
        assert_eq!(query(&url, "client_id").as_deref(), Some("signing"));
    }

    #[test]
    fn viewer_login_has_no_reauth_params() {
        let url = params(None);
        assert_eq!(query(&url, "max_age"), None);
        assert_eq!(query(&url, "prompt"), None);
    }
}
