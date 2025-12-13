use crate::tsa;
use jsonwebtoken::{DecodingKey, Validation, decode, decode_header};
use p256::ecdsa::{Signature, VerifyingKey};
use p256::pkcs8::DecodePublicKey;
use serde::Deserialize;
use sha2::{Digest, Sha256};

#[derive(Debug, thiserror::Error)]
pub enum ValidationError {
    #[error("Invalid public key: {0}")]
    InvalidPublicKey(String),
    #[error("Invalid signature format: {0}")]
    InvalidSignatureFormat(String),
    #[error("Signature verification failed")]
    SignatureVerificationFailed,
    #[error("Invalid JWT header: {0}")]
    InvalidJwtHeader(String),
    #[error("JWT validation failed: {0}")]
    JwtValidationFailed(String),
    #[error("JWT Nonce mismatch")]
    JwtNonceMismatch,
    #[error("Timestamp verification failed: {0}")]
    TimestampVerificationFailed(String),
    #[error("Command verification failed: {0}")]
    CommandVerificationFailed(String),
    #[error("JWT expired relative to timestamp")]
    JwtExpired,
}

#[derive(Deserialize, Debug, Clone)] // Added Debug/Clone/Deserialize.
pub struct Claims {
    pub sub: String,
    pub username: Option<String>,
    pub nonce: String,
    pub exp: u64,
    // nbf: Option<u64>,
}

#[derive(Deserialize, Debug, Clone)] // Added Serialize/Deserialize/Debug/Clone
pub struct ExecutionRequest {
    pub command: serde_json::Value,
    #[serde(rename = "signature")]
    pub signature_hex: String,
    pub id_token: String,
    #[serde(rename = "public_key")]
    pub public_key_pem: String,
    #[serde(rename = "timestamp_token")]
    pub timestamp_token_hex: String,
}

pub struct VerifierConfig {
    pub client_id: String,
    pub issuer_url: String,
    pub jwks: jsonwebtoken::jwk::JwkSet,
    pub trusted_roots: Vec<Vec<u8>>,
}

#[derive(Debug, PartialEq)]
pub struct AuthorizedUser {
    pub username: String,
    pub timestamp: time::OffsetDateTime,
}

pub fn verify_execution(
    req: &ExecutionRequest,
    config: &VerifierConfig,
) -> Result<AuthorizedUser, ValidationError> {
    // 1. Verify Command Signature
    let command_str_verification = req.command.to_string();

    let public_key = VerifyingKey::from_public_key_pem(&req.public_key_pem)
        .map_err(|e| ValidationError::InvalidPublicKey(e.to_string()))?;

    let signature_bytes = hex::decode(&req.signature_hex)
        .map_err(|_| ValidationError::InvalidSignatureFormat("Invalid hex".into()))?;

    let signature = Signature::from_slice(&signature_bytes)
        .map_err(|e| ValidationError::InvalidSignatureFormat(e.to_string()))?;

    use p256::ecdsa::signature::Verifier;
    if public_key
        .verify(command_str_verification.as_bytes(), &signature)
        .is_err()
    {
        return Err(ValidationError::SignatureVerificationFailed);
    }

    // 2. Verify Timestamp
    // We do this BEFORE JWT full validation because we need the timestamp to check JWT expiry correctly.
    let timestamp_token_bytes = hex::decode(&req.timestamp_token_hex)
        .map_err(|_| ValidationError::TimestampVerificationFailed("Invalid hex".into()))?;

    let mut data_to_verify = signature_bytes.to_vec();
    data_to_verify.extend_from_slice(req.id_token.as_bytes());

    let timestamp = tsa::verify_timestamp(
        &timestamp_token_bytes,
        &data_to_verify,
        &config.trusted_roots,
    )
    .map_err(|e| ValidationError::TimestampVerificationFailed(e.to_string()))?;

    // 3. Verify JWT
    let header = decode_header(&req.id_token)
        .map_err(|e| ValidationError::InvalidJwtHeader(e.to_string()))?;

    let kid = header
        .kid
        .ok_or_else(|| ValidationError::InvalidJwtHeader("Missing kid".into()))?;
    let jwk = config
        .jwks
        .find(&kid)
        .ok_or_else(|| ValidationError::JwtValidationFailed("Unknown signing key".into()))?;

    let mut validation = Validation::new(header.alg);
    validation.set_audience(&[&config.client_id]);
    validation.set_issuer(&[&config.issuer_url]);

    // CRITICAL: We validate expiry manually against the timestamp, NOT against "now".
    // If the fast moving train of time has passed, but the timestamp was valid AT THAT TIME, we are good.
    validation.validate_exp = false;

    let token_data = decode::<Claims>(
        &req.id_token,
        &DecodingKey::from_jwk(jwk)
            .map_err(|e| ValidationError::JwtValidationFailed(e.to_string()))?,
        &validation,
    )
    .map_err(|e| ValidationError::JwtValidationFailed(e.to_string()))?;

    // 4. Validate JWT Nonce
    let expected_nonce = hex::encode(Sha256::digest(req.public_key_pem.as_bytes()));
    if token_data.claims.nonce != expected_nonce {
        return Err(ValidationError::JwtNonceMismatch);
    }

    // 5. Validate JWT Expiry against Timestamp
    // exp is seconds since epoch
    let exp_time = time::OffsetDateTime::from_unix_timestamp(token_data.claims.exp as i64)
        .map_err(|_| ValidationError::JwtValidationFailed("Invalid exp claim".into()))?;

    if timestamp > exp_time {
        return Err(ValidationError::JwtExpired);
    }

    let username = token_data.claims.username.unwrap_or(token_data.claims.sub);

    Ok(AuthorizedUser {
        username,
        timestamp,
    })
}
