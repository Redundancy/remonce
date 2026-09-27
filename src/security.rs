//! Requests, approvals and their verification.
//!
//! See ARCHITECTURE.md for the full model. In short:
//!
//! - A **request** is a command: name, execution id, target machines,
//!   parameters and optional time bounds.
//! - An **approval** is one person's signature over the request's canonical
//!   payload. Every approval is independent — its own fresh login and
//!   one-time key — so approvals can be collected in any order, on any
//!   machine. A bundle is the request plus the approvals gathered so far.
//! - How many approvals, from whom, and who may execute is **policy**
//!   (OPA with published requirement documents), not something the request
//!   says. This module only establishes who approved, and that each
//!   approval is genuine and fresh; distinct people are enforced here.
//!
//! Every signature comes from its own OIDC login: a fresh ephemeral key whose
//! hash is the token's `nonce`, and a forced re-authentication. Freshness is
//! therefore measured from the IdP-attested `iat` (and `auth_time`), which a
//! re-timestamp cannot move — not from the token's `exp`, whose lifetime the
//! operator of Remonce usually doesn't control.
//!
//! Replay and revocation key on the **request id** — `hex(SHA256(payload))`
//! of the canonical request — which no signature malleability can change.
//! Signatures must still be low-S and canonical lowercase hex.

use crate::tsa;
use jsonwebtoken::{DecodingKey, Validation, decode, decode_header};
use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use p256::pkcs8::DecodePublicKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::Duration;

#[derive(Debug, thiserror::Error)]
pub enum ValidationError {
    #[error("Invalid public key: {0}")]
    InvalidPublicKey(String),
    #[error("Invalid signature format: {0}")]
    InvalidSignatureFormat(String),
    #[error("Approval signature verification failed")]
    ApprovalSignatureFailed,
    #[error("Invalid JWT header: {0}")]
    InvalidJwtHeader(String),
    #[error("JWT validation failed: {0}")]
    JwtValidationFailed(String),
    #[error("JWT audience rejected: {0}")]
    AudienceMismatch(String),
    #[error("JWT is missing the `{0}` claim")]
    MissingClaim(&'static str),
    #[error("JWT nonce not bound to signer's public key")]
    JwtNonceMismatch,
    #[error("Timestamp verification failed: {0}")]
    TimestampVerificationFailed(String),
    #[error("JWT expired relative to timestamp")]
    JwtExpired,
    #[error("Signature was timestamped before its ID token was issued")]
    TimestampBeforeIssue,
    #[error("Signature was timestamped {delay_secs}s after its ID token was issued (max {max_secs}s)")]
    SignedTooLongAfterIssue { delay_secs: u64, max_secs: u64 },
    #[error("ID token's auth_time is after its iat")]
    AuthTimeAfterIssue,
    #[error("Signer authenticated {age_secs}s before the ID token was issued (max {max_secs}s)")]
    AuthenticationTooOld { age_secs: u64, max_secs: u64 },
    #[error("Timestamp is too far in the future ({ahead_secs}s ahead)")]
    TimestampInFuture { ahead_secs: u64 },
    #[error("The request has no approvals")]
    NoApprovals,
    #[error("The request has {count} approvals (at most {max})")]
    TooManyApprovals { count: usize, max: usize },
    #[error("Approval #{index}: {source}")]
    InApproval {
        index: usize,
        #[source]
        source: Box<ValidationError>,
    },
    #[error("Approval #{index} by {username} has expired ({age_secs}s old, valid for {max_secs}s)")]
    ApprovalStale {
        index: usize,
        username: String,
        age_secs: u64,
        max_secs: u64,
    },
    #[error("{username} approved more than once; approvals must come from different people")]
    DuplicateApprover { username: String },
    #[error("Revoker signature verification failed")]
    RevokerSignatureFailed,
    #[error("Revocation signature is stale ({age_secs}s > {max_secs}s)")]
    RevokerStale { age_secs: u64, max_secs: u64 },
}

impl ValidationError {
    /// The underlying error, unwrapping the approval index.
    pub fn root(&self) -> &ValidationError {
        match self {
            ValidationError::InApproval { source, .. } => source.root(),
            other => other,
        }
    }
}

/// Tolerated clock skew between the TSA / IdP and this host, and between
/// the TSA and the IdP.
pub const MAX_FUTURE_SKEW: Duration = Duration::from_secs(5 * 60);
/// Longest allowed gap between an ID token's issue (`iat`) and the TSA
/// timestamp over the signature made with it. Signing happens right after
/// the login, so this is short; it is what stops a holder re-timestamping an
/// old signature to make it look fresh.
pub const MAX_SIGN_DELAY: Duration = Duration::from_secs(5 * 60);
/// Longest allowed gap between the signer's actual authentication
/// (`auth_time`) and the token's issue — proves the login was a real
/// re-authentication, not a silent SSO refresh of an old session.
pub const MAX_AUTH_AGE: Duration = Duration::from_secs(5 * 60);
/// `auth_time` and `iat` come from the same IdP clock; allow a little slop.
const AUTH_TIME_SLACK: Duration = Duration::from_secs(60);
/// Pad on cache retention to cover whole-second rounding in the checks.
pub const CACHE_SLACK: Duration = Duration::from_secs(60);
/// Most approvals a bundle may carry; bounds verification work.
pub const MAX_APPROVALS: usize = 16;
/// A revocation is an "act now" signature.
pub const MAX_REVOKER_AGE: Duration = Duration::from_secs(10 * 60);
/// Domain tag in every signed request payload.
pub const REQUEST_DOMAIN: &str = "request/v2";
/// Prefix of every revocation payload; never valid as a request payload.
const REVOKE_DOMAIN: &[u8] = b"REMONCE-REVOKE/v2:";

/// One person's signature over a request, with the evidence that binds it
/// to them (ID token) and to a time (TSA token).
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct Approval {
    pub signature: String,
    pub id_token: String,
    pub public_key: String,
    pub timestamp_token: String,
}

/// A request and the approvals collected for it. With no approvals it is
/// an unsigned request, ready for its first approver.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct RequestBundle {
    pub command: serde_json::Value,
    #[serde(default)]
    pub approvals: Vec<Approval>,
}

/// A request to revoke (cancel) a request before it runs. The revoker
/// presents the request with at least one genuine approval, plus their own
/// fresh attestation over a domain-separated payload.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct RevocationBundle {
    pub request: RequestBundle,
    pub revoker: Approval,
}

pub struct VerifierConfig {
    /// The *signing* OIDC client. Viewer-client tokens are rejected here.
    pub client_id: String,
    pub issuer_url: String,
    pub jwks: jsonwebtoken::jwk::JwkSet,
    pub trusted_roots: Vec<Vec<u8>>,
    /// How long each approval stays usable, from its login (`iat`).
    pub approval_validity: Duration,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SignerIdentity {
    pub username: String,
    pub claims: serde_json::Value,
    /// TSA time over the signature.
    pub signed_at: time::OffsetDateTime,
    /// The ID token's `iat`: IdP-attested, and within `MAX_SIGN_DELAY` of
    /// `signed_at`. Freshness windows are measured from here.
    pub issued_at: time::OffsetDateTime,
    /// The ID token's `auth_time`: when the signer actually authenticated.
    pub auth_time: time::OffsetDateTime,
    /// The ID token's `exp`. Kept for audit only — its lifetime is the IdP's
    /// choice and doesn't extend a signature's validity.
    pub token_exp: time::OffsetDateTime,
    /// `hex(SHA256(public_key_pem))`, as attested in the token's `nonce`.
    pub key_binding: String,
}

impl SignerIdentity {
    /// Latest instant a signature by this signer can still pass a freshness
    /// check of `window`. Re-timestamping can't extend this: the TSA time
    /// must stay within `MAX_SIGN_DELAY` of `iat`, and age is checked from both.
    pub fn usable_until(&self, window: Duration) -> time::OffsetDateTime {
        self.issued_at + window + CACHE_SLACK
    }

    /// The OIDC subject. Verified tokens always have one (checked when the
    /// identity is built).
    pub fn subject(&self) -> &str {
        self.claims.get("sub").and_then(|v| v.as_str()).unwrap_or("")
    }
}

/// A verified request: its id and the distinct people who approved it, in
/// bundle order.
#[derive(Debug, Clone)]
pub struct VerifiedRequest {
    pub request_id: String,
    pub approvers: Vec<SignerIdentity>,
}

/// The canonical bytes every approval signs: compact JSON with sorted keys,
/// `{"command":{…},"remonce":"request/v2"}`.
///
/// `serde_json::Value` keeps object keys in a BTreeMap unless the
/// `preserve_order` feature is on (it is not; a test guards this), so this
/// is the same string for the same command however its JSON was written.
pub fn canonical_request_payload(command: &serde_json::Value) -> String {
    serde_json::json!({ "command": command, "remonce": REQUEST_DOMAIN }).to_string()
}

/// The request id: `hex(SHA256(canonical payload))`. Names the request for
/// replay protection and revocation.
pub fn request_id(command: &serde_json::Value) -> String {
    hex::encode(Sha256::digest(canonical_request_payload(command).as_bytes()))
}

/// The bytes a revoker signs: the revoke domain tag, the request id, and
/// the revoker's public key.
pub fn revocation_payload(request_id: &str, revoker_public_key_pem: &str) -> Vec<u8> {
    let mut bytes = REVOKE_DOMAIN.to_vec();
    bytes.extend_from_slice(request_id.as_bytes());
    bytes.extend_from_slice(revoker_public_key_pem.as_bytes());
    bytes
}

/// The OIDC `nonce` a signer's token must carry: `hex(SHA256(pem))`.
pub fn key_binding(public_key_pem: &str) -> String {
    hex::encode(Sha256::digest(public_key_pem.as_bytes()))
}

/// Sign `msg`, normalized to low-S. The verifier rejects high-S signatures
/// (the `s → n−s` twin of every valid signature), and `p256` does not
/// normalize on its own, so every signer must go through this.
pub fn sign_low_s(key: &SigningKey, msg: &[u8]) -> Signature {
    let sig: Signature = key.sign(msg);
    sig.normalize_s().unwrap_or(sig)
}

/// The `sub` of a JWT, read *without* verifying it — only for early,
/// friendlier refusals in signers; the agent's checks are authoritative.
pub fn claimed_subject(id_token: &str) -> Option<String> {
    use base64::Engine;
    let payload = id_token.split('.').nth(1)?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload.trim_end_matches('='))
        .ok()?;
    let claims: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    claims.get("sub")?.as_str().map(str::to_string)
}

/// Decode a signature hex string, rejecting anything but canonical lowercase.
fn decode_canonical_hex(s: &str, what: &str) -> Result<Vec<u8>, ValidationError> {
    let bytes = hex::decode(s)
        .map_err(|_| ValidationError::InvalidSignatureFormat(format!("{what}: invalid hex")))?;
    if hex::encode(&bytes) != s {
        return Err(ValidationError::InvalidSignatureFormat(format!(
            "{what}: hex must be lowercase"
        )));
    }
    Ok(bytes)
}

/// Parse a raw `r || s` signature, rejecting the high-S form.
fn parse_low_s(bytes: &[u8], what: &str) -> Result<Signature, ValidationError> {
    let sig = Signature::from_slice(bytes)
        .map_err(|e| ValidationError::InvalidSignatureFormat(format!("{what}: {e}")))?;
    if sig.normalize_s().is_some() {
        return Err(ValidationError::InvalidSignatureFormat(format!(
            "{what}: high-S signature"
        )));
    }
    Ok(sig)
}

fn username_from_claims(claims: &serde_json::Value) -> String {
    claims
        .get("username")
        .and_then(|v| v.as_str())
        .or_else(|| claims.get("sub").and_then(|v| v.as_str()))
        .unwrap_or("unknown")
        .to_string()
}

/// Which kind of signature is being verified; selects error variants.
#[derive(Clone, Copy)]
enum Leg {
    Approval,
    Revoker,
}

impl Leg {
    fn name(self) -> &'static str {
        match self {
            Leg::Approval => "approval",
            Leg::Revoker => "revoker",
        }
    }

    fn signature_failed(self) -> ValidationError {
        match self {
            Leg::Approval => ValidationError::ApprovalSignatureFailed,
            Leg::Revoker => ValidationError::RevokerSignatureFailed,
        }
    }
}

/// Verify one signature: low-S over `payload`, TSA timestamp over
/// `(sig_bytes || id_token)`, and the nonce-bound, freshly-issued JWT with a
/// subject. Freshness against a validity window is left to the caller.
fn verify_leg(
    leg: Leg,
    a: &Approval,
    payload: &[u8],
    config: &VerifierConfig,
) -> Result<SignerIdentity, ValidationError> {
    let what = leg.name();

    // ---- 1. Signature over the payload ----
    let pubkey = VerifyingKey::from_public_key_pem(&a.public_key)
        .map_err(|e| ValidationError::InvalidPublicKey(e.to_string()))?;
    let sig_bytes = decode_canonical_hex(&a.signature, what)?;
    let sig = parse_low_s(&sig_bytes, what)?;
    pubkey
        .verify(payload, &sig)
        .map_err(|_| leg.signature_failed())?;

    // ---- 2. TSA over (sig_bytes || id_token) ----
    let tsa_bytes = hex::decode(&a.timestamp_token).map_err(|_| {
        ValidationError::TimestampVerificationFailed(format!("{what} TSA: invalid hex"))
    })?;
    let mut tsa_data = sig_bytes;
    tsa_data.extend_from_slice(a.id_token.as_bytes());
    let signed_at = tsa::verify_timestamp(&tsa_bytes, &tsa_data, &config.trusted_roots)
        .map_err(|e| ValidationError::TimestampVerificationFailed(e.to_string()))?;

    // ---- 3. JWT: issuer, strict audience, nonce, iat/auth_time vs signed_at ----
    let token = verify_oidc_jwt(&a.id_token, &a.public_key, signed_at, config)?;
    if token.claims.get("sub").and_then(|v| v.as_str()).is_none_or(str::is_empty) {
        return Err(ValidationError::MissingClaim("sub"));
    }

    Ok(SignerIdentity {
        username: username_from_claims(&token.claims),
        claims: token.claims,
        signed_at,
        issued_at: token.iat,
        auth_time: token.auth_time,
        token_exp: token.exp,
        key_binding: token.key_binding,
    })
}

/// Verify a bundle's approvals: each genuine, over this request, fresh
/// within `approval_validity`, and from a different person. Whether the
/// approvers are *enough* is policy's decision.
pub fn verify_request(
    bundle: &RequestBundle,
    config: &VerifierConfig,
    now: time::OffsetDateTime,
) -> Result<VerifiedRequest, ValidationError> {
    if bundle.approvals.is_empty() {
        return Err(ValidationError::NoApprovals);
    }
    if bundle.approvals.len() > MAX_APPROVALS {
        return Err(ValidationError::TooManyApprovals {
            count: bundle.approvals.len(),
            max: MAX_APPROVALS,
        });
    }
    let payload = canonical_request_payload(&bundle.command);

    let mut approvers = Vec::with_capacity(bundle.approvals.len());
    for (index, a) in bundle.approvals.iter().enumerate() {
        let id = verify_leg(Leg::Approval, a, payload.as_bytes(), config).map_err(|e| {
            ValidationError::InApproval {
                index,
                source: Box::new(e),
            }
        })?;
        check_fresh(now, &id, config.approval_validity, |age_secs, max_secs| {
            ValidationError::ApprovalStale {
                index,
                username: id.username.clone(),
                age_secs,
                max_secs,
            }
        })
        .map_err(|e| match e {
            e @ ValidationError::ApprovalStale { .. } => e,
            other => ValidationError::InApproval {
                index,
                source: Box::new(other),
            },
        })?;
        approvers.push(id);
    }

    // Distinct people, compared only after every token is verified (an
    // unverified `sub` is attacker-controlled). Rejecting rather than
    // ignoring duplicates means policy always sees one entry per person.
    for (i, a) in approvers.iter().enumerate() {
        if approvers[..i].iter().any(|b| b.subject() == a.subject()) {
            return Err(ValidationError::DuplicateApprover {
                username: a.username.clone(),
            });
        }
    }

    Ok(VerifiedRequest {
        request_id: request_id(&bundle.command),
        approvers,
    })
}

#[derive(Debug, Clone)]
pub struct AuthorizedRevocation {
    pub request_id: String,
    pub approvers: Vec<SignerIdentity>,
    pub revoker: SignerIdentity,
    /// Whether the revoker is one of the request's approvers (same `sub`).
    /// If false, the caller must consult policy before honoring it.
    pub self_revoked: bool,
}

/// Verify a revocation: the request must carry at least one genuine
/// approval (so nobody can fill the revocation list with invented
/// requests), and the revoker's attestation must be genuine and fresh.
/// Approvals need not be fresh — an expired approval can still be revoked.
pub fn verify_revocation(
    req: &RevocationBundle,
    config: &VerifierConfig,
    now: time::OffsetDateTime,
) -> Result<AuthorizedRevocation, ValidationError> {
    let request = &req.request;
    if request.approvals.is_empty() {
        return Err(ValidationError::NoApprovals);
    }
    if request.approvals.len() > MAX_APPROVALS {
        return Err(ValidationError::TooManyApprovals {
            count: request.approvals.len(),
            max: MAX_APPROVALS,
        });
    }
    let payload = canonical_request_payload(&request.command);
    let approvers = request
        .approvals
        .iter()
        .enumerate()
        .map(|(index, a)| {
            verify_leg(Leg::Approval, a, payload.as_bytes(), config).map_err(|e| {
                ValidationError::InApproval {
                    index,
                    source: Box::new(e),
                }
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    let request_id = request_id(&request.command);
    let revoker = verify_leg(
        Leg::Revoker,
        &req.revoker,
        &revocation_payload(&request_id, &req.revoker.public_key),
        config,
    )?;
    check_fresh(now, &revoker, MAX_REVOKER_AGE, |age_secs, max_secs| {
        ValidationError::RevokerStale { age_secs, max_secs }
    })?;

    let self_revoked = approvers.iter().any(|a| a.subject() == revoker.subject());
    Ok(AuthorizedRevocation {
        request_id,
        approvers,
        revoker,
        self_revoked,
    })
}

/// How long the replay cache must remember an executed request. Covers
/// every approval in the bundle, and any other approval that could have
/// existed when it ran (each is dead `validity` after its login, and none
/// can have logged in later than now plus skew). Only approvals made after
/// the run can ever run the same request again once this lapses.
pub fn replay_ttl(
    now: time::OffsetDateTime,
    approvers: &[SignerIdentity],
    validity: Duration,
) -> Duration {
    let latest = approvers
        .iter()
        .map(|a| a.usable_until(validity))
        .chain(std::iter::once(now + MAX_FUTURE_SKEW + validity + CACHE_SLACK))
        .max()
        .unwrap_or(now);
    (latest - now).try_into().unwrap_or(validity)
}

/// Until when a revocation must be kept: at least `retention`, and past any
/// approval of the request that could still be valid.
pub fn revocation_keep_until(
    now: time::OffsetDateTime,
    approvers: &[SignerIdentity],
    validity: Duration,
    retention: Duration,
) -> time::OffsetDateTime {
    let from = approvers
        .iter()
        .map(|a| a.issued_at)
        .chain(std::iter::once(now))
        .max()
        .unwrap_or(now);
    from + validity.max(retention) + MAX_FUTURE_SKEW + CACHE_SLACK
}

/// Claims and times from a verified, nonce-bound ID token.
struct VerifiedToken {
    claims: serde_json::Value,
    iat: time::OffsetDateTime,
    auth_time: time::OffsetDateTime,
    exp: time::OffsetDateTime,
    key_binding: String,
}

/// Strict audience rule shared by every token check: `aud` must be exactly
/// `expected` (a string, or a one-element array), and `azp`, if present,
/// must equal it too. `jsonwebtoken` alone accepts any overlapping array,
/// which would let one token pass as both a signing and a viewer token.
pub fn check_audience(claims: &serde_json::Value, expected: &str) -> Result<(), ValidationError> {
    let ok = match claims.get("aud") {
        Some(serde_json::Value::String(a)) => a == expected,
        Some(serde_json::Value::Array(arr)) => {
            arr.len() == 1 && arr[0].as_str() == Some(expected)
        }
        _ => false,
    };
    if !ok {
        return Err(ValidationError::AudienceMismatch(format!(
            "aud must be exactly \"{expected}\""
        )));
    }
    if let Some(azp) = claims.get("azp")
        && azp.as_str() != Some(expected)
    {
        return Err(ValidationError::AudienceMismatch(format!(
            "azp must be \"{expected}\""
        )));
    }
    Ok(())
}

/// Read a NumericDate claim (integer or fractional seconds).
fn numeric_date(
    claims: &serde_json::Value,
    name: &'static str,
) -> Result<time::OffsetDateTime, ValidationError> {
    let v = claims.get(name).ok_or(ValidationError::MissingClaim(name))?;
    let secs = v
        .as_i64()
        .or_else(|| v.as_f64().map(|f| f.floor() as i64))
        .ok_or_else(|| ValidationError::JwtValidationFailed(format!("{name} is not a number")))?;
    time::OffsetDateTime::from_unix_timestamp(secs)
        .map_err(|_| ValidationError::JwtValidationFailed(format!("{name} out of range")))
}

fn whole_secs(d: time::Duration) -> u64 {
    d.whole_seconds().max(0) as u64
}

/// Decode and verify a JWT's signature and issuer against the pinned JWKS,
/// plus the strict audience rule. `validate_exp` controls whether `exp` is
/// checked against the wall clock.
fn decode_verified(
    token: &str,
    jwks: &jsonwebtoken::jwk::JwkSet,
    issuer: &str,
    audience: &str,
    validate_exp: bool,
) -> Result<serde_json::Value, ValidationError> {
    let header =
        decode_header(token).map_err(|e| ValidationError::InvalidJwtHeader(e.to_string()))?;
    let kid = header
        .kid
        .ok_or_else(|| ValidationError::InvalidJwtHeader("Missing kid".into()))?;
    let jwk = jwks
        .find(&kid)
        .ok_or_else(|| ValidationError::JwtValidationFailed("Unknown signing key".into()))?;
    let decoding_key = DecodingKey::from_jwk(jwk)
        .map_err(|e| ValidationError::JwtValidationFailed(e.to_string()))?;

    let mut validation = Validation::new(header.alg);
    validation.set_audience(&[audience]);
    validation.set_issuer(&[issuer]);
    validation.set_required_spec_claims(&["exp", "iss", "aud"]);
    validation.validate_exp = validate_exp;

    let claims = decode::<serde_json::Value>(token, &decoding_key, &validation)
        .map_err(|e| ValidationError::JwtValidationFailed(e.to_string()))?
        .claims;
    check_audience(&claims, audience)?;
    Ok(claims)
}

/// Verify a signing token: JWKS signature, issuer, strict audience (the
/// signing client), nonce bound to the signer's ephemeral key, and the
/// issue/auth times relative to the TSA time `signed_at`:
///
/// - `signed_at <= exp` (the only remaining use of `exp`);
/// - `iat - skew <= signed_at <= iat + MAX_SIGN_DELAY` — a signature can't be
///   re-timestamped long after the login that produced it;
/// - `auth_time <= iat + slack` and `iat - auth_time <= MAX_AUTH_AGE` — the
///   login was a real re-authentication.
fn verify_oidc_jwt(
    id_token: &str,
    signer_public_key_pem: &str,
    signed_at: time::OffsetDateTime,
    config: &VerifierConfig,
) -> Result<VerifiedToken, ValidationError> {
    let claims = decode_verified(
        id_token,
        &config.jwks,
        &config.issuer_url,
        &config.client_id,
        false,
    )?;

    let expected_nonce = key_binding(signer_public_key_pem);
    let nonce = claims
        .get("nonce")
        .and_then(|v| v.as_str())
        .ok_or(ValidationError::MissingClaim("nonce"))?;
    if nonce != expected_nonce {
        return Err(ValidationError::JwtNonceMismatch);
    }

    let exp = numeric_date(&claims, "exp")?;
    let iat = numeric_date(&claims, "iat")?;
    let auth_time = numeric_date(&claims, "auth_time")?;

    if signed_at > exp {
        return Err(ValidationError::JwtExpired);
    }
    if signed_at < iat - MAX_FUTURE_SKEW {
        return Err(ValidationError::TimestampBeforeIssue);
    }
    if signed_at - iat > MAX_SIGN_DELAY {
        return Err(ValidationError::SignedTooLongAfterIssue {
            delay_secs: whole_secs(signed_at - iat),
            max_secs: MAX_SIGN_DELAY.as_secs(),
        });
    }
    if auth_time > iat + AUTH_TIME_SLACK {
        return Err(ValidationError::AuthTimeAfterIssue);
    }
    if iat - auth_time > MAX_AUTH_AGE {
        return Err(ValidationError::AuthenticationTooOld {
            age_secs: whole_secs(iat - auth_time),
            max_secs: MAX_AUTH_AGE.as_secs(),
        });
    }

    Ok(VerifiedToken {
        claims,
        iat,
        auth_time,
        exp,
        key_binding: expected_nonce,
    })
}

/// Verify a bearer token for the read-only viewer endpoints: JWKS
/// signature, issuer, `exp` against the wall clock, and the strict audience
/// rule for the *viewer* client. No nonce binding — this is plain bearer
/// auth, which is why it must never share an audience with signing tokens.
pub fn verify_bearer_token(
    token: &str,
    jwks: &jsonwebtoken::jwk::JwkSet,
    issuer: &str,
    viewer_audience: &str,
) -> Result<serde_json::Value, ValidationError> {
    decode_verified(token, jwks, issuer, viewer_audience, true)
}

/// Check a signer is fresh against both its IdP issue time and its TSA
/// time. `iat` is the binding bound (a re-timestamp can't move it); the TSA
/// time is kept as a backstop. `stale` builds the error for an expired one.
fn check_fresh(
    now: time::OffsetDateTime,
    who: &SignerIdentity,
    max: Duration,
    stale: impl Fn(u64, u64) -> ValidationError,
) -> Result<(), ValidationError> {
    check_age(now, who.issued_at, max, &stale)?;
    check_age(now, who.signed_at, max, &stale)
}

fn check_age(
    now: time::OffsetDateTime,
    at: time::OffsetDateTime,
    max: Duration,
    stale: &impl Fn(u64, u64) -> ValidationError,
) -> Result<(), ValidationError> {
    if at > now {
        // Small clock skew is treated as zero age; anything larger would let
        // a skewed TSA or IdP extend a signature's life past the cache TTL.
        let ahead_secs = whole_secs(at - now);
        if ahead_secs > MAX_FUTURE_SKEW.as_secs() {
            return Err(ValidationError::TimestampInFuture { ahead_secs });
        }
        return Ok(());
    }
    let age_secs = whole_secs(now - at);
    if age_secs > max.as_secs() {
        return Err(stale(age_secs, max.as_secs()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_is_domain_tagged_and_key_order_independent() {
        // Written in different key orders, the same command is the same
        // request. Guards against serde_json's `preserve_order` sneaking in.
        let a: serde_json::Value =
            serde_json::from_str(r#"{"id":"1","command":"test","target_machines":["h"]}"#).unwrap();
        let b: serde_json::Value =
            serde_json::from_str(r#"{"target_machines":["h"],"command":"test","id":"1"}"#).unwrap();
        let payload = canonical_request_payload(&a);
        assert_eq!(payload, canonical_request_payload(&b));
        assert_eq!(
            payload,
            r#"{"command":{"command":"test","id":"1","target_machines":["h"]},"remonce":"request/v2"}"#
        );
        assert_eq!(request_id(&a), request_id(&b));
        assert_eq!(request_id(&a).len(), 64);
    }

    #[test]
    fn revocation_payload_is_not_a_request_payload() {
        let cmd = serde_json::json!({ "command": "test" });
        let rev = revocation_payload(&request_id(&cmd), "pem");
        assert!(rev.starts_with(b"REMONCE-REVOKE/v2:"));
        assert_ne!(rev, canonical_request_payload(&cmd).into_bytes());
    }
}
