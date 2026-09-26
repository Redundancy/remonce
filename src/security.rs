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
//! Signature hex must be canonical lowercase: caches key on the hex string,
//! and `hex::decode` would otherwise accept case variants of the same bytes.

use crate::tsa;
use jsonwebtoken::{DecodingKey, Validation, decode, decode_header};
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
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
    #[error("JWT nonce not bound to signer's public key")]
    JwtNonceMismatch,
    #[error("Timestamp verification failed: {0}")]
    TimestampVerificationFailed(String),
    #[error("JWT expired relative to timestamp")]
    JwtExpired,
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

/// Tolerated clock skew between the TSA and this host.
const MAX_FUTURE_SKEW: Duration = Duration::from_secs(5 * 60);

#[derive(Deserialize, Debug, Clone)]
pub struct Claims {
    pub sub: String,
    pub username: Option<String>,
    pub nonce: String,
    pub exp: u64,
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
    pub signed_at: time::OffsetDateTime,
    /// The ID token's `exp`. Anyone holding a bundle can obtain a fresh TSA
    /// timestamp over the same signature + token until this instant, so it
    /// bounds how late `signed_at` can be pushed. Size cache TTLs from it.
    pub token_exp: time::OffsetDateTime,
}

impl SignerIdentity {
    /// Latest instant a signature by this signer can still pass a freshness
    /// check of `window`, allowing for re-timestamping up to `token_exp`.
    pub fn usable_until(&self, window: Duration) -> time::OffsetDateTime {
        self.token_exp.max(self.signed_at) + window
    }
}

#[derive(Debug, Clone)]
pub struct AuthorizedExecution {
    pub approver: SignerIdentity,
    /// Equals `approver` when self-executing.
    pub operator: SignerIdentity,
    pub self_executed: bool,
    /// The signature whose freshness bounds execution (operator sig if
    /// delegated, else approver sig). Used as the replay cache key.
    pub executor_signature_hex: String,
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
fn operator_payload(approver_sig_hex: &str, operator_public_key_pem: &str) -> Vec<u8> {
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

/// Verify the approver leg of a bundle: signature over the canonical payload,
/// TSA timestamp, and nonce-bound JWT. Returns the approver's identity.
fn verify_approver(
    approver: &ApproverBundle,
    config: &VerifierConfig,
) -> Result<SignerIdentity, ValidationError> {
    // ---- 1. Verify approver signature over canonical(command + operator_requires) ----
    let approver_payload =
        canonical_approver_payload(&approver.command, &approver.operator_requires);

    let approver_pubkey = VerifyingKey::from_public_key_pem(&approver.public_key)
        .map_err(|e| ValidationError::InvalidPublicKey(e.to_string()))?;

    let approver_sig_bytes = decode_canonical_hex(&approver.signature, "approver")?;

    let approver_sig = Signature::from_slice(&approver_sig_bytes)
        .map_err(|e| ValidationError::InvalidSignatureFormat(e.to_string()))?;

    use p256::ecdsa::signature::Verifier;
    approver_pubkey
        .verify(approver_payload.as_bytes(), &approver_sig)
        .map_err(|_| ValidationError::ApproverSignatureFailed)?;

    // ---- 2. Verify approver TSA over (sig_bytes || id_token) ----
    let approver_tsa_bytes = hex::decode(&approver.timestamp_token).map_err(|_| {
        ValidationError::TimestampVerificationFailed("approver TSA: invalid hex".into())
    })?;
    let mut approver_tsa_data = approver_sig_bytes.clone();
    approver_tsa_data.extend_from_slice(approver.id_token.as_bytes());
    let approver_signed_at =
        tsa::verify_timestamp(&approver_tsa_bytes, &approver_tsa_data, &config.trusted_roots)
            .map_err(|e| ValidationError::TimestampVerificationFailed(e.to_string()))?;

    // ---- 3. Verify approver JWT ----
    let (approver_claims_obj, token_exp) = verify_oidc_jwt(
        &approver.id_token,
        &approver.public_key,
        approver_signed_at,
        config,
    )?;

    Ok(SignerIdentity {
        username: username_from_claims(&approver_claims_obj),
        claims: approver_claims_obj,
        signed_at: approver_signed_at,
        token_exp,
    })
}

pub fn verify_execution(
    bundle: &ExecutionBundle,
    config: &VerifierConfig,
) -> Result<AuthorizedExecution, ValidationError> {
    let approver = verify_approver(&bundle.approver, config)?;
    let approver_signed_at = approver.signed_at;

    // ---- 4. Delegated vs self-execute branch ----
    let now = time::OffsetDateTime::now_utc();

    match &bundle.operator {
        Some(_) if bundle.approver.operator_requires.is_none() => {
            Err(ValidationError::CosignNotAllowed)
        }
        None if bundle.approver.operator_requires.is_some() => {
            Err(ValidationError::CosignRequired)
        }
        Some(op) => {
            // 4a. Re-check the stated approver_sig matches the bundle.
            if op.approver_sig != bundle.approver.signature {
                return Err(ValidationError::OperatorStapling);
            }

            // 4b. Verify operator signature over (approver_sig_hex || operator_pubkey_pem).
            let operator_pubkey = VerifyingKey::from_public_key_pem(&op.public_key)
                .map_err(|e| ValidationError::InvalidPublicKey(e.to_string()))?;

            let op_sig_bytes = decode_canonical_hex(&op.signature, "operator")?;
            let op_sig = Signature::from_slice(&op_sig_bytes)
                .map_err(|e| ValidationError::InvalidSignatureFormat(e.to_string()))?;

            let op_payload = operator_payload(&bundle.approver.signature, &op.public_key);
            operator_pubkey
                .verify(&op_payload, &op_sig)
                .map_err(|_| ValidationError::OperatorSignatureFailed)?;

            // 4c. Operator TSA.
            let op_tsa_bytes = hex::decode(&op.timestamp_token).map_err(|_| {
                ValidationError::TimestampVerificationFailed("operator TSA: invalid hex".into())
            })?;
            let mut op_tsa_data = op_sig_bytes.clone();
            op_tsa_data.extend_from_slice(op.id_token.as_bytes());
            let operator_signed_at =
                tsa::verify_timestamp(&op_tsa_bytes, &op_tsa_data, &config.trusted_roots)
                    .map_err(|e| ValidationError::TimestampVerificationFailed(e.to_string()))?;

            // 4d. Operator JWT + nonce bound to operator pubkey.
            let (operator_claims_obj, operator_token_exp) = verify_oidc_jwt(
                &op.id_token,
                &op.public_key,
                operator_signed_at,
                config,
            )?;
            let operator_username = username_from_claims(&operator_claims_obj);

            // 4e. Freshness — operator (short) + approver (long).
            check_age(now, operator_signed_at, config.operator_max_validity, true)?;
            check_age(now, approver_signed_at, config.approver_max_validity, false)?;

            // 4f. Evaluate operator_requires against operator claims.
            if let Some(req) = &bundle.approver.operator_requires {
                if !req.any_of.is_empty() && !any_of_matches(&req.any_of, &operator_claims_obj) {
                    return Err(ValidationError::OperatorConstraintUnsatisfied);
                }
            }

            // An approver cosigning their own delegated bundle is still one
            // person — report it as self-executed so four-eyes policies hold.
            let self_executed = same_subject(&approver.claims, &operator_claims_obj);

            Ok(AuthorizedExecution {
                approver,
                operator: SignerIdentity {
                    username: operator_username,
                    claims: operator_claims_obj,
                    signed_at: operator_signed_at,
                    token_exp: operator_token_exp,
                },
                self_executed,
                executor_signature_hex: op.signature.clone(),
            })
        }
        None => {
            // Self-execute: approver's own sig must be within the short window.
            check_age(now, approver_signed_at, config.operator_max_validity, true)?;

            Ok(AuthorizedExecution {
                operator: approver.clone(),
                self_executed: true,
                executor_signature_hex: bundle.approver.signature.clone(),
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
    /// Hex signature of the approver bundle being revoked — the revocation
    /// cache key.
    pub approver_signature_hex: String,
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

    // 2. Verify revoker signature over the domain-separated payload.
    let revoker_pubkey = VerifyingKey::from_public_key_pem(&req.revoker.public_key)
        .map_err(|e| ValidationError::InvalidPublicKey(e.to_string()))?;

    let revoker_sig_bytes = decode_canonical_hex(&req.revoker.signature, "revoker")?;
    let revoker_sig = Signature::from_slice(&revoker_sig_bytes)
        .map_err(|e| ValidationError::InvalidSignatureFormat(e.to_string()))?;

    let payload = revocation_payload(&req.approver.signature, &req.revoker.public_key);
    use p256::ecdsa::signature::Verifier;
    revoker_pubkey
        .verify(&payload, &revoker_sig)
        .map_err(|_| ValidationError::RevokerSignatureFailed)?;

    // 3. Revoker TSA + JWT (nonce bound to revoker's ephemeral key).
    let revoker_tsa_bytes = hex::decode(&req.revoker.timestamp_token).map_err(|_| {
        ValidationError::TimestampVerificationFailed("revoker TSA: invalid hex".into())
    })?;
    let mut revoker_tsa_data = revoker_sig_bytes.clone();
    revoker_tsa_data.extend_from_slice(req.revoker.id_token.as_bytes());
    let revoker_signed_at =
        tsa::verify_timestamp(&revoker_tsa_bytes, &revoker_tsa_data, &config.trusted_roots)
            .map_err(|e| ValidationError::TimestampVerificationFailed(e.to_string()))?;

    let (revoker_claims, revoker_token_exp) = verify_oidc_jwt(
        &req.revoker.id_token,
        &req.revoker.public_key,
        revoker_signed_at,
        config,
    )?;

    // 4. Revocation is an "act now" signature — hold it to the short window.
    check_age(
        time::OffsetDateTime::now_utc(),
        revoker_signed_at,
        config.operator_max_validity,
        true,
    )?;

    let same_sub = same_subject(&approver.claims, &revoker_claims);

    Ok(AuthorizedRevocation {
        revoker: SignerIdentity {
            username: username_from_claims(&revoker_claims),
            claims: revoker_claims,
            signed_at: revoker_signed_at,
            token_exp: revoker_token_exp,
        },
        self_revoked: same_sub,
        approver_signature_hex: req.approver.signature.clone(),
        approver,
    })
}

/// Shared JWT verification: signature against JWKS, issuer, audience, and
/// nonce bound to the caller's ephemeral public key. Also checks the JWT's
/// own `exp` against the TSA timestamp (not wall clock). Returns the claims
/// and the token's expiry.
fn verify_oidc_jwt(
    id_token: &str,
    signer_public_key_pem: &str,
    signed_at: time::OffsetDateTime,
    config: &VerifierConfig,
) -> Result<(serde_json::Value, time::OffsetDateTime), ValidationError> {
    let header =
        decode_header(id_token).map_err(|e| ValidationError::InvalidJwtHeader(e.to_string()))?;
    let kid = header
        .kid
        .ok_or_else(|| ValidationError::InvalidJwtHeader("Missing kid".into()))?;
    let jwk = config
        .jwks
        .find(&kid)
        .ok_or_else(|| ValidationError::JwtValidationFailed("Unknown signing key".into()))?;
    let decoding_key = DecodingKey::from_jwk(jwk)
        .map_err(|e| ValidationError::JwtValidationFailed(e.to_string()))?;

    let mut validation = Validation::new(header.alg);
    validation.set_audience(&[&config.client_id]);
    validation.set_issuer(&[&config.issuer_url]);
    validation.validate_exp = false;

    let token_data = decode::<serde_json::Value>(id_token, &decoding_key, &validation)
        .map_err(|e| ValidationError::JwtValidationFailed(e.to_string()))?;
    let claims = token_data.claims;

    let expected_nonce = hex::encode(Sha256::digest(signer_public_key_pem.as_bytes()));
    let nonce = claims
        .get("nonce")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ValidationError::JwtValidationFailed("Missing nonce".into()))?;
    if nonce != expected_nonce {
        return Err(ValidationError::JwtNonceMismatch);
    }

    let exp = claims
        .get("exp")
        .and_then(|v| v.as_i64())
        .ok_or_else(|| ValidationError::JwtValidationFailed("Missing exp".into()))?;
    let exp_time = time::OffsetDateTime::from_unix_timestamp(exp)
        .map_err(|_| ValidationError::JwtValidationFailed("Invalid exp claim".into()))?;
    if signed_at > exp_time {
        return Err(ValidationError::JwtExpired);
    }

    Ok((claims, exp_time))
}

fn check_age(
    now: time::OffsetDateTime,
    signed_at: time::OffsetDateTime,
    max: Duration,
    is_executor: bool,
) -> Result<(), ValidationError> {
    if signed_at > now {
        // Small clock skew is treated as zero age; anything larger would let
        // a skewed TSA extend a signature's life past the replay-cache TTL.
        let ahead_secs = (signed_at - now).whole_seconds().max(0) as u64;
        if ahead_secs > MAX_FUTURE_SKEW.as_secs() {
            return Err(ValidationError::TimestampInFuture { ahead_secs });
        }
        return Ok(());
    }
    let age = now - signed_at;
    let age_secs = age.whole_seconds().max(0) as u64;
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
