//! Signer-side helpers shared by the local signer and the CLI: a fresh
//! ephemeral key per signature, and the low-S sign + TSA timestamp step.

use p256::ecdsa::SigningKey;
use p256::elliptic_curve::generic_array::GenericArray;
use p256::pkcs8::EncodePublicKey;
use rand::rngs::OsRng;

/// A one-signature ephemeral key and the OIDC nonce that binds a login to it.
pub struct Ephemeral {
    pub key: SigningKey,
    pub public_key_pem: String,
    /// `hex(SHA256(public_key_pem))` — sent as the OIDC `nonce`.
    pub nonce: String,
}

pub fn new_ephemeral() -> Result<Ephemeral, String> {
    let key = SigningKey::random(&mut OsRng);
    let public_key_pem = key
        .verifying_key()
        .to_public_key_pem(spki::der::pem::LineEnding::LF)
        .map_err(|e| format!("Failed to encode public key: {e}"))?;
    let nonce = crate::security::key_binding(&public_key_pem);
    Ok(Ephemeral {
        key,
        public_key_pem,
        nonce,
    })
}

/// Hex of the raw private scalar, for holding a key across an OIDC redirect
/// in the local signer's in-memory session.
pub fn key_to_hex(key: &SigningKey) -> String {
    hex::encode(key.to_bytes())
}

pub fn key_from_hex(hex_str: &str) -> Result<SigningKey, String> {
    let bytes = hex::decode(hex_str).map_err(|_| "Invalid signing key hex".to_string())?;
    if bytes.len() != 32 {
        return Err("Invalid signing key length".into());
    }
    SigningKey::from_bytes(GenericArray::from_slice(&bytes))
        .map_err(|_| "Invalid signing key bytes".to_string())
}

/// One signed, timestamped leg: the fields shared by `ApproverBundle`,
/// `OperatorCosign` and `RevokerAttestation`.
pub struct Attestation {
    pub signature: String,
    pub id_token: String,
    pub public_key: String,
    pub timestamp_token: String,
}

/// Sign `payload` (low-S) and obtain an RFC 3161 timestamp over
/// `(sig_bytes || id_token)`.
pub async fn attest(
    http: &reqwest::Client,
    tsa_url: &str,
    key: &SigningKey,
    public_key_pem: &str,
    id_token: String,
    payload: &[u8],
) -> Result<Attestation, String> {
    let signature = crate::security::sign_low_s(key, payload);
    let signature_bytes = signature.to_bytes();

    let mut data_to_timestamp = signature_bytes.to_vec();
    data_to_timestamp.extend_from_slice(id_token.as_bytes());
    let timestamp_token = crate::tsa::request_timestamp(http, tsa_url, &data_to_timestamp)
        .await
        .map_err(|e| format!("TSA error: {e}"))?;

    Ok(Attestation {
        signature: hex::encode(signature_bytes),
        id_token,
        public_key: public_key_pem.to_string(),
        timestamp_token: hex::encode(timestamp_token),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_hex_round_trip() {
        let e = new_ephemeral().unwrap();
        let back = key_from_hex(&key_to_hex(&e.key)).unwrap();
        assert_eq!(back.to_bytes(), e.key.to_bytes());
        assert_eq!(e.nonce, crate::security::key_binding(&e.public_key_pem));
    }
}
