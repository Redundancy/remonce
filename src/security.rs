//! Approver + (optional) Operator signature verification.
//!
//! See ARCHITECTURE.md for the full delegation model. In short:
//!
//! - **Approver** signs `canonical(command + operator_requires)` and embeds
//!   constraints on who may execute. Long validity (days).
//! - **Operator** (if present) signs `approver_signature_hex || operator_pubkey_pem`.
//!   Short validity (minutes). Provides attribution + at-execution-time freshness.
//! - **Self-execute shortcut**: if no operator is present, the approver's own
//!   signature must be within the short window — they're acting as both roles.
//!
//! The signed `operator_requires` field doubles as the delegation mode:
//! `None` = self-execute only (a cosign is rejected); `Some(_)` = delegated
//! (self-execute is rejected), with an empty `any_of` meaning "any operator".
//!
//! Every signature comes from its own OIDC login: a fresh ephemeral key whose
//! hash is the token's `nonce`, and a forced re-authentication. Freshness is
//! therefore measured from the IdP-attested `iat` (and `auth_time`), which a
//! re-timestamp cannot move — not from the token's `exp`, whose lifetime the
//! operator of Remonce usually doesn't control.
//!
//! Replay and revocation caches key on the **key binding** — the verified
//! `nonce`, i.e. `hex(SHA256(public_key_pem))` — which sits inside the
//! IdP-signed payload and so cannot be mauled the way ECDSA signature bytes
//! can. Signatures must still be low-S and canonical lowercase hex: the
//! operator payload signs the approver's hex string, so it must be unique.

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
    #[error("Approver signature verification failed")]
    ApproverSignatureFailed,
    #[error("Operator signature verification failed")]
    OperatorSignatureFailed,
    #[error("Operator cosign does not bind to approver signature")]
    OperatorStapling,
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
    #[error("Approver signature is stale ({age_secs}s > {max_secs}s)")]
    ApproverStale { age_secs: u64, max_secs: u64 },
    #[error("Executor signature is stale ({age_secs}s > {max_secs}s)")]
    ExecutorStale { age_secs: u64, max_secs: u64 },
    #[error("Operator does not satisfy operator_requires")]
    OperatorConstraintUnsatisfied,
    #[error("Revoker signature verification failed")]
    RevokerSignatureFailed,
    #[error("Revoker is not authorized to revoke this approval")]
    RevokerNotAuthorized,
    #[error("Timestamp is too far in the future ({ahead_secs}s ahead)")]
    TimestampInFuture { ahead_secs: u64 },
    #[error("Bundle is delegated (operator_requires set) and needs an operator cosign")]
    CosignRequired,
    #[error("Bundle is self-execute only (no operator_requires) and cannot be cosigned")]
    CosignNotAllowed,
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

#[derive(Deserialize, Debug, Clone)]
pub struct Claims {
    pub sub: String,
    pub username: Option<String>,
    pub nonce: String,
    pub exp: u64,
    #[serde(default)]
    pub iat: Option<f64>,
    #[serde(default)]
    pub auth_time: Option<f64>,
}

/// A predicate over OIDC claims. Minimal by design: if you need more
/// expressive logic, put it in OPA rather than growing this language.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum ClaimPredicate {
    /// Claim value equals the given JSON value.
    Equals {
        claim: String,
        value: serde_json::Value,
    },
    /// Claim is an array and contains the given JSON value.
    Contains {
        claim: String,
        value: serde_json::Value,
    },
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct OperatorConstraint {
    /// At least one predicate must match. Empty = no restriction.
    #[serde(default)]
    pub any_of: Vec<ClaimPredicate>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ApproverBundle {
    pub command: serde_json::Value,
    #[serde(default)]
    pub operator_requires: Option<OperatorConstraint>,
    pub signature: String,
    pub id_token: String,
    pub public_key: String,
    pub timestamp_token: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct OperatorCosign {
    /// Must equal `approver.signature`. Submitted for explicitness; the verifier
    /// also re-derives it from the approver bundle to catch tampering.
    pub approver_sig: String,
    pub signature: String,
    pub id_token: String,
    pub public_key: String,
    pub timestamp_token: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ExecutionBundle {
    pub approver: ApproverBundle,
    #[serde(default)]
    pub operator: Option<OperatorCosign>,
}

/// A request to revoke a previously-issued approver bundle before its
/// natural expiry. The revoker presents the full bundle being revoked plus
/// their own fresh attestation (same shape as an operator cosign, but over
/// a domain-separated payload so the two can never be confused).
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RevocationBundle {
    /// The approver bundle being revoked.
    pub approver: ApproverBundle,
    pub revoker: RevokerAttestation,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RevokerAttestation {
    /// Signature over `revocation_payload(approver_sig, revoker_pubkey)`.
    pub signature: String,
    pub id_token: String,
    pub public_key: String,
    pub timestamp_token: String,
}

pub struct VerifierConfig {
    /// The *signing* OIDC client. Viewer-client tokens are rejected here.
    pub client_id: String,
    pub issuer_url: String,
    pub jwks: jsonwebtoken::jwk::JwkSet,
    pub trusted_roots: Vec<Vec<u8>>,
    pub approver_max_validity: Duration,
    pub operator_max_validity: Duration,
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
    /// choice and no longer extends a signature's validity.
    pub token_exp: time::OffsetDateTime,
    /// `hex(SHA256(public_key_pem))`, as attested in the token's `nonce`.
    /// Unique per signature and immune to signature malleability; the replay
    /// and revocation cache key.
    pub key_binding: String,
}

impl SignerIdentity {
    /// Latest instant a signature by this signer can still pass a freshness
    /// check of `window`. Re-timestamping can't extend this: the TSA time
    /// must stay within `MAX_SIGN_DELAY` of `iat`, and age is checked from both.
    pub fn usable_until(&self, window: Duration) -> time::OffsetDateTime {
        self.issued_at + window + CACHE_SLACK
    }
}

#[derive(Debug, Clone)]
pub struct AuthorizedExecution {
    pub approver: SignerIdentity,
    /// Equals `approver` when self-executing.
    pub operator: SignerIdentity,
    pub self_executed: bool,
    /// Key binding of the signer whose freshness bounds execution (operator
    /// if delegated, else approver). Used as the replay cache key.
    pub executor_key_binding: String,
}

/// Build the canonical bytes an approver signs over.
///
/// Using `serde_json::to_vec` on a Value with sorted keys is not guaranteed
/// by serde_json — but in practice serde_json::Value uses BTreeMap when the
/// `preserve_order` feature is *off*, which is the default. We document the
/// canonicalization contract here and rely on it across signer + verifier.
pub fn canonical_approver_payload(
    command: &serde_json::Value,
    operator_requires: &Option<OperatorConstraint>,
) -> String {
    let wrapper = serde_json::json!({
        "command": command,
        "operator_requires": operator_requires,
    });
    wrapper.to_string()
}

/// Build the bytes an operator signs over: approver signature hex followed
/// by the operator's public-key PEM. Binds the cosign to *this* approver's sig.
pub fn operator_payload(approver_sig_hex: &str, operator_public_key_pem: &str) -> Vec<u8> {
    let mut bytes = approver_sig_hex.as_bytes().to_vec();
    bytes.extend_from_slice(operator_public_key_pem.as_bytes());
    bytes
}

/// Build the bytes a revoker signs over. The `REMONCE-REVOKE:` prefix
/// domain-separates this from `operator_payload`, so a revocation signature
/// can never be replayed as a cosign or vice versa.
pub fn revocation_payload(approver_sig_hex: &str, revoker_public_key_pem: &str) -> Vec<u8> {
    let mut bytes = b"REMONCE-REVOKE:".to_vec();
    bytes.extend_from_slice(approver_sig_hex.as_bytes());
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

fn same_subject(a: &serde_json::Value, b: &serde_json::Value) -> bool {
    match (
        a.get("sub").and_then(|v| v.as_str()),
        b.get("sub").and_then(|v| v.as_str()),
    ) {
        (Some(a), Some(b)) => a == b,
        _ => false,
    }
}

fn username_from_claims(claims: &serde_json::Value) -> String {
    claims
        .get("username")
        .and_then(|v| v.as_str())
        .or_else(|| claims.get("sub").and_then(|v| v.as_str()))
        .unwrap_or("unknown")
        .to_string()
}

/// Which leg of a bundle is being verified; selects error variants.
#[derive(Clone, Copy)]
enum Leg {
    Approver,
    Operator,
    Revoker,
}

impl Leg {
    fn name(self) -> &'static str {
        match self {
            Leg::Approver => "approver",
            Leg::Operator => "operator",
            Leg::Revoker => "revoker",
        }
    }

    fn signature_failed(self) -> ValidationError {
        match self {
            Leg::Approver => ValidationError::ApproverSignatureFailed,
            Leg::Operator => ValidationError::OperatorSignatureFailed,
            Leg::Revoker => ValidationError::RevokerSignatureFailed,
        }
    }
}

/// Verify one signing leg: low-S signature over `payload`, TSA timestamp
/// over `(sig_bytes || id_token)`, and the nonce-bound, freshly-issued JWT.
/// Role-specific freshness is left to the caller.
fn verify_leg(
    leg: Leg,
    signature_hex: &str,
    payload: &[u8],
    public_key_pem: &str,
    id_token: &str,
    timestamp_token_hex: &str,
    config: &VerifierConfig,
) -> Result<SignerIdentity, ValidationError> {
    let what = leg.name();

    // ---- 1. Signature over the payload ----
    let pubkey = VerifyingKey::from_public_key_pem(public_key_pem)
        .map_err(|e| ValidationError::InvalidPublicKey(e.to_string()))?;
    let sig_bytes = decode_canonical_hex(signature_hex, what)?;
    let sig = parse_low_s(&sig_bytes, what)?;
    pubkey
        .verify(payload, &sig)
        .map_err(|_| leg.signature_failed())?;

    // ---- 2. TSA over (sig_bytes || id_token) ----
    let tsa_bytes = hex::decode(timestamp_token_hex).map_err(|_| {
        ValidationError::TimestampVerificationFailed(format!("{what} TSA: invalid hex"))
    })?;
    let mut tsa_data = sig_bytes;
    tsa_data.extend_from_slice(id_token.as_bytes());
    let signed_at = tsa::verify_timestamp(&tsa_bytes, &tsa_data, &config.trusted_roots)
        .map_err(|e| ValidationError::TimestampVerificationFailed(e.to_string()))?;

    // ---- 3. JWT: issuer, strict audience, nonce, iat/auth_time vs signed_at ----
    let token = verify_oidc_jwt(id_token, public_key_pem, signed_at, config)?;

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

/// Verify the approver leg of a bundle.
fn verify_approver(
    approver: &ApproverBundle,
    config: &VerifierConfig,
) -> Result<SignerIdentity, ValidationError> {
    let payload = canonical_approver_payload(&approver.command, &approver.operator_requires);
    verify_leg(
        Leg::Approver,
        &approver.signature,
        payload.as_bytes(),
        &approver.public_key,
        &approver.id_token,
        &approver.timestamp_token,
        config,
    )
}

pub fn verify_execution(
    bundle: &ExecutionBundle,
    config: &VerifierConfig,
) -> Result<AuthorizedExecution, ValidationError> {
    let approver = verify_approver(&bundle.approver, config)?;

    // ---- Delegated vs self-execute branch ----
    let now = time::OffsetDateTime::now_utc();

    match &bundle.operator {
        Some(_) if bundle.approver.operator_requires.is_none() => {
            Err(ValidationError::CosignNotAllowed)
        }
        None if bundle.approver.operator_requires.is_some() => {
            Err(ValidationError::CosignRequired)
        }
        Some(op) => {
            // Re-check the stated approver_sig matches the bundle.
            if op.approver_sig != bundle.approver.signature {
                return Err(ValidationError::OperatorStapling);
            }

            // Operator signs (approver_sig_hex || operator_pubkey_pem).
            let op_payload = operator_payload(&bundle.approver.signature, &op.public_key);
            let operator = verify_leg(
                Leg::Operator,
                &op.signature,
                &op_payload,
                &op.public_key,
                &op.id_token,
                &op.timestamp_token,
                config,
            )?;

            // Freshness — operator (short) + approver (long).
            check_fresh(now, &operator, config.operator_max_validity, true)?;
            check_fresh(now, &approver, config.approver_max_validity, false)?;

            // Evaluate operator_requires against operator claims.
            if let Some(req) = &bundle.approver.operator_requires
                && !req.any_of.is_empty()
                && !any_of_matches(&req.any_of, &operator.claims)
            {
                return Err(ValidationError::OperatorConstraintUnsatisfied);
            }

            // An approver cosigning their own delegated bundle is still one
            // person — report it as self-executed so four-eyes policies hold.
            let self_executed = same_subject(&approver.claims, &operator.claims);

            Ok(AuthorizedExecution {
                approver,
                executor_key_binding: operator.key_binding.clone(),
                operator,
                self_executed,
            })
        }
        None => {
            // Self-execute: approver's own sig must be within the short window.
            check_fresh(now, &approver, config.operator_max_validity, true)?;

            Ok(AuthorizedExecution {
                operator: approver.clone(),
                self_executed: true,
                executor_key_binding: approver.key_binding.clone(),
                approver,
            })
        }
    }
}

#[derive(Debug, Clone)]
pub struct AuthorizedRevocation {
    pub approver: SignerIdentity,
    pub revoker: SignerIdentity,
    /// Whether the revoker is the approver themselves (same `sub`). If false,
    /// the caller must consult policy (OPA) before honoring the revocation.
    pub self_revoked: bool,
    /// Key binding of the approval being revoked — the revocation cache key.
    pub approver_key_binding: String,
}

/// Verify a revocation request: the approver bundle must be genuine and the
/// revoker's attestation fresh (within `operator_max_validity`), signed with
/// a nonce-bound ephemeral key. Authorization (who may revoke) is split:
/// same-`sub` is decided here via `self_revoked`; anything else is the
/// caller's policy decision.
pub fn verify_revocation(
    req: &RevocationBundle,
    config: &VerifierConfig,
) -> Result<AuthorizedRevocation, ValidationError> {
    // 1. The bundle being revoked must itself be genuine — otherwise anyone
    //    could poison the revocation cache with signatures they invented.
    let approver = verify_approver(&req.approver, config)?;

    // 2. Revoker attestation over the domain-separated payload.
    let payload = revocation_payload(&req.approver.signature, &req.revoker.public_key);
    let revoker = verify_leg(
        Leg::Revoker,
        &req.revoker.signature,
        &payload,
        &req.revoker.public_key,
        &req.revoker.id_token,
        &req.revoker.timestamp_token,
        config,
    )?;

    // 3. Revocation is an "act now" signature — hold it to the short window.
    check_fresh(
        time::OffsetDateTime::now_utc(),
        &revoker,
        config.operator_max_validity,
        true,
    )?;

    let self_revoked = same_subject(&approver.claims, &revoker.claims);

    Ok(AuthorizedRevocation {
        revoker,
        self_revoked,
        approver_key_binding: approver.key_binding.clone(),
        approver,
    })
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
/// time is kept as a backstop.
fn check_fresh(
    now: time::OffsetDateTime,
    who: &SignerIdentity,
    max: Duration,
    is_executor: bool,
) -> Result<(), ValidationError> {
    check_age(now, who.issued_at, max, is_executor)?;
    check_age(now, who.signed_at, max, is_executor)
}

fn check_age(
    now: time::OffsetDateTime,
    at: time::OffsetDateTime,
    max: Duration,
    is_executor: bool,
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
    let max_secs = max.as_secs();
    if age_secs > max_secs {
        return Err(if is_executor {
            ValidationError::ExecutorStale { age_secs, max_secs }
        } else {
            ValidationError::ApproverStale { age_secs, max_secs }
        });
    }
    Ok(())
}

fn any_of_matches(preds: &[ClaimPredicate], claims: &serde_json::Value) -> bool {
    preds.iter().any(|p| match p {
        ClaimPredicate::Equals { claim, value } => {
            claims.get(claim).map(|c| c == value).unwrap_or(false)
        }
        ClaimPredicate::Contains { claim, value } => claims
            .get(claim)
            .and_then(|c| c.as_array())
            .map(|arr| arr.iter().any(|v| v == value))
            .unwrap_or(false),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contains_predicate_against_groups_claim() {
        let claims = serde_json::json!({
            "groups": ["noc-l1", "noc-l2"],
            "sub": "alice",
        });
        let preds = vec![ClaimPredicate::Contains {
            claim: "groups".into(),
            value: serde_json::json!("noc-l2"),
        }];
        assert!(any_of_matches(&preds, &claims));

        let preds2 = vec![ClaimPredicate::Contains {
            claim: "groups".into(),
            value: serde_json::json!("admins"),
        }];
        assert!(!any_of_matches(&preds2, &claims));
    }

    #[test]
    fn equals_predicate_against_scalar_claim() {
        let claims = serde_json::json!({ "team": "webapp" });
        let preds = vec![ClaimPredicate::Equals {
            claim: "team".into(),
            value: serde_json::json!("webapp"),
        }];
        assert!(any_of_matches(&preds, &claims));
    }

    #[test]
    fn canonical_payload_is_stable() {
        let cmd = serde_json::json!({ "command": "test", "target_machines": ["host-a"] });
        let req = Some(OperatorConstraint {
            any_of: vec![ClaimPredicate::Contains {
                claim: "groups".into(),
                value: serde_json::json!("noc-l2"),
            }],
        });
        let a = canonical_approver_payload(&cmd, &req);
        let b = canonical_approver_payload(&cmd, &req);
        assert_eq!(a, b);
    }
}
