// Fix imports and rasn attributes
use num_traits::cast::ToPrimitive;
use rasn::prelude::*;
use rasn_cms::{ContentInfo, SignedData, SignerIdentifier};
use rasn_pkix::AlgorithmIdentifier;
use reqwest::Client;
use sha2::{Digest, Sha256}; // Needed for Integer -> i64

use p256::ecdsa::{Signature, VerifyingKey};
use x509_parser::prelude::*;

/// Bundled DigiCert Trusted Root G4 (expires 2038-01-15). Forms the default
/// trust anchor for TSA signature verification; matches the default TSA URL
/// (`http://timestamp.digicert.com`) and the free DigiCert public TSA that
/// most deployments will use out of the box.
pub const DIGICERT_ROOT_G4_DER: &[u8] =
    include_bytes!("../trust_anchors/DigiCertTrustedRootG4.crt");

/// DER-encoded OID content for id-kp-timeStamping (1.3.6.1.5.5.7.3.8),
/// per RFC 3161 §2.3.
const TIMESTAMPING_EKU_OID: &[u8] = &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x08];

// OID Constants
const OID_SIGNED_DATA: &[u32] = &[1, 2, 840, 113549, 1, 7, 2];
const OID_TST_INFO_CONTENT_TYPE: &[u32] = &[1, 2, 840, 113549, 1, 9, 16, 1, 4];
const OID_SHA256: &[u32] = &[2, 16, 840, 1, 101, 3, 4, 2, 1];
const OID_CONTENT_TYPE: &[u32] = &[1, 2, 840, 113549, 1, 9, 3];
const OID_MESSAGE_DIGEST: &[u32] = &[1, 2, 840, 113549, 1, 9, 4];

// Digest OIDs (used when signer_info.signature_algorithm is plain rsaEncryption
// and we need to dispatch on signer_info.digest_algorithm instead).
const OID_SHA256_STR: &str = "2.16.840.1.101.3.4.2.1";
const OID_SHA384_STR: &str = "2.16.840.1.101.3.4.2.2";
const OID_SHA512_STR: &str = "2.16.840.1.101.3.4.2.3";

// Signature algorithm OIDs for the SignerInfo `signature_algorithm` field.
// Full list here: RFC 4055 (RSA), RFC 5758 (ECDSA), RFC 8017 (PSS).
const OID_RSA_ENCRYPTION_STR: &str = "1.2.840.113549.1.1.1";
const OID_RSA_SHA256_STR: &str = "1.2.840.113549.1.1.11";
const OID_RSA_SHA384_STR: &str = "1.2.840.113549.1.1.12";
const OID_RSA_SHA512_STR: &str = "1.2.840.113549.1.1.13";
const OID_ECDSA_SHA256_STR: &str = "1.2.840.10045.4.3.2";
const OID_ECDSA_SHA384_STR: &str = "1.2.840.10045.4.3.3";
const OID_ECDSA_SHA512_STR: &str = "1.2.840.10045.4.3.4";

/// Supported hash algorithms for signature verification, derived either from
/// a combined RSA signature-algorithm OID or from the SignerInfo's
/// `digest_algorithm` field.
#[derive(Debug, Clone, Copy)]
enum SigHash {
    Sha256,
    Sha384,
    Sha512,
}

impl SigHash {
    fn digest(&self, msg: &[u8]) -> Vec<u8> {
        use sha2::{Sha384, Sha512};
        match self {
            SigHash::Sha256 => Sha256::digest(msg).to_vec(),
            SigHash::Sha384 => Sha384::digest(msg).to_vec(),
            SigHash::Sha512 => Sha512::digest(msg).to_vec(),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum TsaError {
    #[error("Network error: {0}")]
    Network(#[from] reqwest::Error),
    #[error("ASN.1 Decode error: {0}")]
    Asn1Decode(#[from] rasn::error::DecodeError),
    #[error("ASN.1 Encode error: {0}")]
    Asn1Encode(#[from] rasn::error::EncodeError),
    #[error("TSA refused request: {0}")]
    Refused(String),
    #[error("Verification error: {0}")]
    Verification(String),
    #[error("Internal error: {0}")]
    Internal(String),
    #[error("Certificate validation error: {0}")]
    CertValidation(String),
}

// RFC 3161 Structure Definitions

#[derive(AsnType, Encode, Decode, Debug, Clone, PartialEq, Eq)]
pub struct MessageImprint {
    pub hash_algorithm: AlgorithmIdentifier,
    pub hashed_message: OctetString,
}

#[derive(AsnType, Encode, Decode, Debug, Clone, PartialEq, Eq)]
pub struct TimeStampReq {
    pub version: Integer,
    pub message_imprint: MessageImprint,
    pub req_policy: Option<ObjectIdentifier>,
    pub nonce: Option<Integer>,
    #[rasn(default)]
    pub cert_req: bool,
    #[rasn(tag(0))]
    pub extensions: Option<rasn_pkix::Extensions>,
}

#[derive(AsnType, Encode, Decode, Debug, Clone, PartialEq, Eq)]
pub struct PKIStatusInfo {
    pub status: Integer,
    pub status_string: Option<SequenceOf<Utf8String>>,
    pub fail_info: Option<BitString>,
}

#[derive(AsnType, Encode, Decode, Debug, Clone, PartialEq, Eq)]
pub struct TimeStampResp {
    pub status: PKIStatusInfo,
    pub time_stamp_token: Option<ContentInfo>,
}

#[derive(AsnType, Encode, Decode, Debug, Clone, PartialEq, Eq)]
pub struct TSTInfo {
    pub version: Integer,
    pub policy: ObjectIdentifier,
    pub message_imprint: MessageImprint,
    pub serial_number: Integer,
    pub gen_time: GeneralizedTime,
    pub accuracy: Option<Accuracy>,
    #[rasn(default)]
    pub ordering: bool,
    pub nonce: Option<Integer>,
    #[rasn(tag(0))]
    pub tsa: Option<rasn_pkix::GeneralName>,
    #[rasn(tag(1))]
    pub extensions: Option<rasn_pkix::Extensions>,
}

#[derive(AsnType, Encode, Decode, Debug, Clone, PartialEq, Eq)]
// #[rasn(tag(sequence))]
pub struct Accuracy {
    #[rasn(tag(0))]
    pub seconds: Option<Integer>,
    #[rasn(tag(1))]
    pub millis: Option<Integer>,
    #[rasn(tag(2))]
    pub micros: Option<Integer>,
}

pub async fn request_timestamp(
    client: &Client,
    tsa_url: &str,
    data: &[u8],
) -> Result<Vec<u8>, TsaError> {
    // 1. Hash the data
    let hash = Sha256::digest(data);

    // 2. Build MessageImprint
    // SHA-256 OID: 2.16.840.1.101.3.4.2.1
    let sha256_oid = ObjectIdentifier::new_unchecked(std::borrow::Cow::Borrowed(OID_SHA256));
    let alg_id = AlgorithmIdentifier {
        algorithm: sha256_oid,
        parameters: None,
    };

    let msg_imprint = MessageImprint {
        hash_algorithm: alg_id,
        hashed_message: OctetString::from(hash.as_slice().to_vec()),
    };

    // 3. Build TimeStampReq
    let req = TimeStampReq {
        version: Integer::from(1),
        message_imprint: msg_imprint,
        req_policy: None,
        nonce: Some(Integer::from(rand::random::<u64>())), // Simple nonce
        cert_req: true,                                    // We want the cert to verify
        extensions: None,
    };

    let req_bytes = rasn::der::encode(&req).map_err(TsaError::Asn1Encode)?;

    // 4. Send Request
    let resp = client
        .post(tsa_url)
        .header("Content-Type", "application/timestamp-query")
        .body(req_bytes)
        .send()
        .await?;

    if !resp.status().is_success() {
        return Err(TsaError::Network(resp.error_for_status().unwrap_err()));
    }

    let resp_bytes = resp.bytes().await?;

    // 5. Check Response Status
    let ts_resp: TimeStampResp = rasn::der::decode(&resp_bytes).map_err(TsaError::Asn1Decode)?;

    // Status 0 and 1 are "granted" or "grantedWithMods"
    let status_val = ts_resp.status.status.to_i64().unwrap_or(-1);
    if status_val != 0 && status_val != 1 {
        let expl = ts_resp
            .status
            .status_string
            .map(|s| format!("{:?}", s))
            .unwrap_or_default();
        return Err(TsaError::Refused(format!(
            "Status: {} {}",
            status_val, expl
        )));
    }

    let token = ts_resp
        .time_stamp_token
        .ok_or(TsaError::Internal("Missing time_stamp_token".into()))?;

    // Return the raw encoded Token (CMS ContentInfo) for storage/verification
    let token_bytes = rasn::der::encode(&token).map_err(TsaError::Asn1Encode)?;
    Ok(token_bytes)
}

/// Verifies a timestamp token against the original data.
/// `trusted_roots` is a list of DER-encoded CA certificates.
/// This function creates a best-effort attempt to handle both raw ContentInfo and TimeStampResp.
pub fn verify_timestamp(
    token_bytes: &[u8],
    data: &[u8],
    trusted_roots: &[Vec<u8>],
) -> Result<::time::OffsetDateTime, TsaError> {
    tracing::debug!(
        "TSA Verification: verify_timestamp called. Input bytes len: {}",
        token_bytes.len()
    );

    // 1. RFC 3161 Section 2.4.2: Parse Response/Token
    let (signed_data, tst_info_bytes) = parse_timestamp_token(token_bytes)?;

    // 2. Decode TSTInfo
    tracing::debug!("TSA Verification: Decoding TSTInfo...");
    let tst_info: TSTInfo = match rasn::ber::decode(tst_info_bytes.as_ref()) {
        Ok(info) => info,
        Err(e) => {
            tracing::warn!(
                "TSA Verification: Failed to decode TSTInfo: {}. Trying OctetString unwrap...",
                e
            );
            let os: OctetString =
                rasn::ber::decode(tst_info_bytes.as_ref()).map_err(TsaError::Asn1Decode)?;
            rasn::ber::decode(os.as_ref()).map_err(TsaError::Asn1Decode)?
        }
    };

    // 3. Verify MessageImprint (RFC 3161 Section 2.4.1)
    verify_message_imprint(&tst_info.message_imprint, data)?;

    // 4. Extract gen_time from TSTInfo — used for historical chain validation.
    let chrono_time: chrono::DateTime<chrono::FixedOffset> = tst_info.gen_time.into();
    let timestamp = chrono_time.timestamp();
    let nanos = chrono_time.timestamp_subsec_nanos();
    let gen_time = ::time::OffsetDateTime::from_unix_timestamp(timestamp)
        .map_err(|_| TsaError::Verification("Invalid timestamp range".into()))?
        + ::time::Duration::nanoseconds(nanos as i64);

    // 5. Verify CMS Signature + chain (RFC 5652). Chain check uses gen_time.
    verify_cms_signature(&signed_data, &tst_info_bytes, trusted_roots, gen_time)?;

    Ok(gen_time)
}

/// Parses the RFC 3161 TimeStampToken (ContentInfo) and extracts SignedData and TSTInfo.
fn parse_timestamp_token(token_bytes: &[u8]) -> Result<(SignedData, Vec<u8>), TsaError> {
    // Try to decode as ContentInfo (Token only)
    let content_info = match rasn::ber::decode::<ContentInfo>(token_bytes) {
        Ok(ci) => {
            tracing::debug!("TSA Verification: Successfully decoded ContentInfo directly.");
            ci
        }
        Err(e_ci) => {
            tracing::warn!(
                "TSA Verification: Failed to decode as ContentInfo: {}",
                e_ci
            );
            // Fallback: Try to decode as TimeStampResp (Wrapper)
            let resp = rasn::ber::decode::<TimeStampResp>(token_bytes).map_err(|e_resp| {
                tracing::error!(
                    "TSA Verification: Failed to decode as TimeStampResp: {}",
                    e_resp
                );
                TsaError::Asn1Decode(e_resp)
            })?;

            tracing::debug!(
                "TSA Verification: Successfully decoded TimeStampResp. Status: {:?}",
                resp.status
            );

            // Check status (0 = granted, 1 = grantedWithMods)
            let granted = Integer::from(0);
            let granted_mods = Integer::from(1);
            if resp.status.status != granted && resp.status.status != granted_mods {
                return Err(TsaError::Verification(format!(
                    "TSA server returned error status: {:?}",
                    resp.status
                )));
            }
            resp.time_stamp_token.ok_or(TsaError::Verification(
                "TimeStampResp contains no token".into(),
            ))?
        }
    };

    // Verify ContentInfo type is id-signedData (RFC 3161 Section 2.4.2)
    if content_info.content_type
        != ObjectIdentifier::new_unchecked(std::borrow::Cow::Borrowed(OID_SIGNED_DATA))
    {
        return Err(TsaError::Verification(
            "ContentInfo is not SignedData".into(),
        ));
    }

    tracing::debug!("TSA Verification: Decoding SignedData...");
    let signed_data: SignedData =
        rasn::ber::decode(content_info.content.as_bytes()).map_err(|e| {
            tracing::error!("TSA Verification: Failed to decode SignedData: {}", e);
            TsaError::Asn1Decode(e)
        })?;

    // Verify EncapsulatedContentInfo type is id-ct-TSTInfo
    if signed_data.encap_content_info.content_type
        != ObjectIdentifier::new_unchecked(std::borrow::Cow::Borrowed(OID_TST_INFO_CONTENT_TYPE))
    {
        return Err(TsaError::Verification(
            "SignedData does not contain TSTInfo".into(),
        ));
    }

    let tst_info_bytes = signed_data
        .encap_content_info
        .content
        .as_ref()
        .ok_or(TsaError::Verification("Missing TSTInfo content".into()))?
        .clone();

    // Convert Bytes/OctetString to Vec<u8> if needed, assuming content is bytes-like.
    // rasn content is usually `Bytes` or `OctetString`. `to_vec()` works on Bytes.
    // `clone()` created a `Bytes` or `Vec<u8>` depending on `rasn` version.
    // Let's assume `Bytes` -> `to_vec()` works or it's `Vec<u8>`.
    // Wait, earlier it was `content.as_ref()`.
    // Let's just return `tst_info_bytes.to_vec()` to be safe.
    Ok((signed_data, tst_info_bytes.to_vec()))
}

/// Verifies that the MessageImprint matches the SHA-256 hash of the data.
fn verify_message_imprint(imprint: &MessageImprint, data: &[u8]) -> Result<(), TsaError> {
    let hash = Sha256::digest(data);
    let expected_alg = ObjectIdentifier::new_unchecked(std::borrow::Cow::Borrowed(OID_SHA256)); // SHA-256

    if imprint.hash_algorithm.algorithm != expected_alg {
        return Err(TsaError::Verification("Unsupported hash algorithm".into()));
    }

    if imprint.hashed_message.as_ref() != hash.as_slice() {
        return Err(TsaError::Verification(
            "Message imprint mismatch. Token was not issued for this data.".into(),
        ));
    }
    Ok(())
}

/// Verifies the CMS Signature and Trust Chain.
fn verify_cms_signature(
    signed_data: &SignedData,
    tst_info_bytes: &[u8],
    trusted_roots: &[Vec<u8>],
    gen_time: ::time::OffsetDateTime,
) -> Result<(), TsaError> {
    if signed_data.signer_infos.len() != 1 {
        let msg = format!(
            "Expected exactly one SignerInfo, found {}",
            signed_data.signer_infos.len()
        );
        tracing::error!("TSA Verification: {}", msg);
        return Err(TsaError::Verification(msg));
    }

    // SetOf: try to_vec()
    let signer_infos_vec = signed_data.signer_infos.to_vec();
    let signer_info = signer_infos_vec.first().unwrap();

    // Find Signer Cert
    let mut certs_der = Vec::new();
    if let Some(certs) = &signed_data.certificates {
        let cert_vec = certs.to_vec();
        tracing::debug!(
            "TSA Verification: Found {} certificates in SignedData",
            cert_vec.len()
        );
        for cert_choice in cert_vec {
            if let rasn_cms::CertificateChoices::Certificate(cert) = cert_choice {
                // cert is Box<Certificate>.
                let der = rasn::der::encode(cert.as_ref()).map_err(TsaError::Asn1Encode)?;
                certs_der.push(der);
            }
        }
    } else {
        tracing::warn!("TSA Verification: No certificates field in SignedData");
    }

    let signer_cert_der = find_signer_cert(&certs_der, &signer_info.sid)
        .or_else(|| {
            tracing::debug!("TSA Verification: Cert not in token, checking trusted roots...");
            find_signer_cert(trusted_roots, &signer_info.sid)
        })
        .ok_or_else(|| {
            tracing::error!(
                "TSA Verification: Signer certificate not found. Candidates count: {}",
                certs_der.len()
            );
            TsaError::Verification("Signing certificate not found inside token".into())
        })?;

    // Parse Signer Cert to get Public Key
    let (_, signer_cert) = x509_parser::parse_x509_certificate(signer_cert_der)
        .map_err(|_| TsaError::Verification("Failed to parse signing certificate".into()))?;

    let spki = signer_cert
        .tbs_certificate
        .subject_pki
        .subject_public_key
        .as_ref();

    // Verify SignerInfo Signature matches Content (SignedAttributes or Content)
    let data_to_verify_sig = if let Some(attrs) = &signer_info.signed_attrs {
        // Strict RFC 3161/5652 Verification for SignedAttributes
        let mut has_content_type = false;
        let mut has_message_digest = false;

        for attr in attrs.to_vec() {
            if attr.r#type
                == ObjectIdentifier::new_unchecked(std::borrow::Cow::Borrowed(OID_CONTENT_TYPE))
            {
                if let Some(val) = attr.values.to_vec().iter().next() {
                    let ct_oid: ObjectIdentifier =
                        rasn::ber::decode(val.as_bytes()).map_err(TsaError::Asn1Decode)?;
                    if ct_oid
                        != ObjectIdentifier::new_unchecked(std::borrow::Cow::Borrowed(
                            OID_TST_INFO_CONTENT_TYPE,
                        ))
                    {
                        return Err(TsaError::Verification(
                            "SignedAttributes contentType mismatch".into(),
                        ));
                    }
                    has_content_type = true;
                }
            } else if attr.r#type
                == ObjectIdentifier::new_unchecked(std::borrow::Cow::Borrowed(OID_MESSAGE_DIGEST))
            {
                if let Some(val) = attr.values.to_vec().iter().next() {
                    let digest: OctetString =
                        rasn::ber::decode(val.as_bytes()).map_err(TsaError::Asn1Decode)?;
                    let content_hash = Sha256::digest(tst_info_bytes);
                    if digest.as_ref() != content_hash.as_slice() {
                        return Err(TsaError::Verification(
                            "SignedAttributes messageDigest mismatch".into(),
                        ));
                    }
                    has_message_digest = true;
                }
            }
        }

        if !has_content_type {
            return Err(TsaError::Verification(
                "Missing contentType in SignedAttributes".into(),
            ));
        }
        if !has_message_digest {
            return Err(TsaError::Verification(
                "Missing messageDigest in SignedAttributes".into(),
            ));
        }

        rasn::der::encode(attrs).map_err(TsaError::Asn1Encode)?
    } else {
        // Sign the content
        // tst_info_bytes is already checked above to be correct content.
        // And we ensure it's a vector for signing.
        tst_info_bytes.to_vec()
    };

    // Dispatch on SignerInfo.signature_algorithm (authoritative — tells us
    // both which key type AND which hash). Fall back to digest_algorithm only
    // when the signature algorithm is the "plain" rsaEncryption OID.
    let sig_alg_oid = signer_info.signature_algorithm.algorithm.to_string();
    let digest_alg_oid = signer_info.digest_algorithm.algorithm.to_string();

    match sig_alg_oid.as_str() {
        OID_RSA_SHA256_STR => {
            verify_signature_rsa(spki, &data_to_verify_sig, signer_info.signature.as_ref(), SigHash::Sha256)
        }
        OID_RSA_SHA384_STR => {
            verify_signature_rsa(spki, &data_to_verify_sig, signer_info.signature.as_ref(), SigHash::Sha384)
        }
        OID_RSA_SHA512_STR => {
            verify_signature_rsa(spki, &data_to_verify_sig, signer_info.signature.as_ref(), SigHash::Sha512)
        }
        OID_RSA_ENCRYPTION_STR => {
            // Plain rsaEncryption — hash is whatever digest_algorithm says.
            let hash = parse_digest_oid(&digest_alg_oid)?;
            verify_signature_rsa(spki, &data_to_verify_sig, signer_info.signature.as_ref(), hash)
        }
        OID_ECDSA_SHA256_STR | OID_ECDSA_SHA384_STR | OID_ECDSA_SHA512_STR => {
            // p256::ecdsa::Verifier binds P-256 to SHA-256; non-256 hashes on
            // a P-256 key are ill-formed and will fail the verify call.
            verify_signature_p256(spki, &data_to_verify_sig, signer_info.signature.as_ref())
        }
        _ => Err(TsaError::Verification(format!(
            "Unsupported SignerInfo signature algorithm OID: {}",
            sig_alg_oid
        ))),
    }?;

    // Verify Trust Chain (EKU, validity window, signature, path) via rustls-webpki.
    verify_trust_chain(signer_cert_der, &certs_der, trusted_roots, gen_time)?;
    Ok(())
}

fn parse_digest_oid(oid: &str) -> Result<SigHash, TsaError> {
    match oid {
        OID_SHA256_STR => Ok(SigHash::Sha256),
        OID_SHA384_STR => Ok(SigHash::Sha384),
        OID_SHA512_STR => Ok(SigHash::Sha512),
        other => Err(TsaError::Verification(format!(
            "Unsupported SignerInfo digest algorithm OID: {}",
            other
        ))),
    }
}

fn verify_signature_p256(spki: &[u8], msg: &[u8], signature_bytes: &[u8]) -> Result<(), TsaError> {
    let verifying_key = VerifyingKey::from_sec1_bytes(spki)
        .map_err(|e| TsaError::Verification(format!("Invalid P-256 SPKI (SEC1): {}", e)))?;

    use p256::ecdsa::signature::Verifier;
    let signature = Signature::from_der(signature_bytes)
        .map_err(|e| TsaError::Verification(format!("Invalid DER signature: {}", e)))?;

    verifying_key
        .verify(msg, &signature)
        .map_err(|_| TsaError::Verification("P-256 signature verification failed".into()))
}

fn verify_signature_rsa(
    spki: &[u8],
    msg: &[u8],
    signature_bytes: &[u8],
    hash_alg: SigHash,
) -> Result<(), TsaError> {
    use rsa::pkcs1::DecodeRsaPublicKey;
    use rsa::{Pkcs1v15Sign, RsaPublicKey};
    use sha2::{Sha384, Sha512};

    let public_key = RsaPublicKey::from_pkcs1_der(spki)
        .map_err(|e| TsaError::Verification(format!("Invalid RSA SPKI: {}", e)))?;

    let hash = hash_alg.digest(msg);

    let scheme = match hash_alg {
        SigHash::Sha256 => Pkcs1v15Sign::new::<Sha256>(),
        SigHash::Sha384 => Pkcs1v15Sign::new::<Sha384>(),
        SigHash::Sha512 => Pkcs1v15Sign::new::<Sha512>(),
    };

    public_key
        .verify(scheme, &hash, signature_bytes)
        .map_err(|e| TsaError::Verification(format!("RSA verification failed: {}", e)))
}

/// Verify the end-entity TSA signer cert chains to a trusted root, was valid
/// at `gen_time`, and carries the `id-kp-timeStamping` EKU (RFC 3161 §2.3).
/// Delegates to `rustls-webpki`.
fn verify_trust_chain(
    cert_der: &[u8],
    intermediates: &[Vec<u8>],
    roots: &[Vec<u8>],
    gen_time: ::time::OffsetDateTime,
) -> Result<(), TsaError> {
    use rustls::pki_types::{CertificateDer, UnixTime};
    use webpki::{EndEntityCert, KeyUsage};

    let ee_der = CertificateDer::from(cert_der);
    let ee = EndEntityCert::try_from(&ee_der).map_err(|e| {
        TsaError::CertValidation(format!("invalid TSA end-entity cert: {:?}", e))
    })?;

    let anchors: Vec<rustls::pki_types::TrustAnchor> = roots
        .iter()
        .filter_map(|der| {
            let cd = CertificateDer::from(der.as_slice());
            match webpki::anchor_from_trusted_cert(&cd) {
                Ok(ta) => Some(ta.to_owned()),
                Err(e) => {
                    tracing::warn!("Skipping unparseable trust anchor: {:?}", e);
                    None
                }
            }
        })
        .collect();

    if anchors.is_empty() {
        return Err(TsaError::CertValidation(
            "no usable TSA trust anchors configured".into(),
        ));
    }

    let intermediate_ders: Vec<CertificateDer> = intermediates
        .iter()
        .map(|v| CertificateDer::from(v.as_slice()))
        .collect();

    // Use the gen_time from the TSTInfo, not wall-clock now(). A TSA cert that
    // was valid when it signed should still produce a verifiable historical
    // timestamp even if the cert later expired.
    let time = UnixTime::since_unix_epoch(std::time::Duration::from_secs(
        gen_time.unix_timestamp().max(0) as u64,
    ));

    let usage = KeyUsage::required(TIMESTAMPING_EKU_OID);

    ee.verify_for_usage(
        webpki::ALL_VERIFICATION_ALGS,
        &anchors,
        &intermediate_ders,
        time,
        usage,
        None,
        None,
    )
    .map_err(|e| TsaError::CertValidation(format!("TSA chain verification failed: {:?}", e)))?;

    tracing::debug!("TSA Verification: chain validated via rustls-webpki");
    Ok(())
}

/// Find the signer cert referenced by `sid` in the candidate set. Per RFC 5652
/// §5.1, `IssuerAndSerialNumber` identifies a cert by the **pair** of issuer DN
/// and serial; serial alone is not unique across CAs.
fn find_signer_cert<'a>(certs: &'a [Vec<u8>], sid: &SignerIdentifier) -> Option<&'a Vec<u8>> {
    use num_bigint::{BigInt, Sign};
    for (i, cert_der) in certs.iter().enumerate() {
        let parsed = match x509_parser::parse_x509_certificate(cert_der) {
            Ok((_, p)) => p,
            Err(_) => {
                tracing::warn!(
                    "TSA Verification: Candidate Cert [{}] failed to parse X.509",
                    i
                );
                continue;
            }
        };
        match sid {
            SignerIdentifier::IssuerAndSerialNumber(ias) => {
                let x509_serial_bytes = parsed.tbs_certificate.serial.to_bytes_be();
                let x509_as_int = BigInt::from_bytes_be(Sign::Plus, &x509_serial_bytes);
                if x509_as_int != ias.serial_number.clone().into() {
                    continue;
                }
                // Serial matches — verify issuer DN too. Compare the raw DER of
                // the cert's Issuer field against the `sid.issuer` re-encoded.
                let cert_issuer_der = parsed.tbs_certificate.issuer.as_raw();
                let sid_issuer_der = match rasn::der::encode(&ias.issuer) {
                    Ok(d) => d,
                    Err(e) => {
                        tracing::warn!(
                            "TSA Verification: Failed to encode sid.issuer for comparison: {}",
                            e
                        );
                        continue;
                    }
                };
                if cert_issuer_der == sid_issuer_der.as_slice() {
                    tracing::debug!(
                        "TSA Verification: Signer cert matched on issuer+serial (candidate {})",
                        i
                    );
                    return Some(cert_der);
                } else {
                    tracing::debug!(
                        "TSA Verification: Candidate {} has matching serial but issuer DN mismatch",
                        i
                    );
                }
            }
            SignerIdentifier::SubjectKeyIdentifier(ski) => {
                if let Ok(Some(ext)) = parsed.get_extension_unique(
                    &x509_parser::oid_registry::OID_X509_EXT_SUBJECT_KEY_IDENTIFIER,
                ) {
                    if let x509_parser::extensions::ParsedExtension::SubjectKeyIdentifier(
                        cert_ski,
                    ) = ext.parsed_extension()
                    {
                        if cert_ski.0 == ski.as_ref() {
                            tracing::debug!(
                                "TSA Verification: Signer cert matched on SKI (candidate {})",
                                i
                            );
                            return Some(cert_der);
                        }
                    }
                }
            }
        }
    }
    if !certs.is_empty() {
        tracing::warn!("TSA Verification: No match found for signer in candidate list.");
    }
    None
}

/// Load the TSA trust anchor set.
///
/// Always includes the bundled DigiCert Trusted Root G4. Adds certs from
/// `extra_path` (PEM) if provided. If `trust_system_store` is true, the OS
/// native trust store is *also* included — this is guarded by `--insecure`
/// because it widens the TSA trust surface to every CA the OS trusts.
pub fn load_trust_anchors(extra_path: Option<&str>, trust_system_store: bool) -> Vec<Vec<u8>> {
    let mut roots = Vec::new();

    // Always: bundled DigiCert Root G4.
    roots.push(DIGICERT_ROOT_G4_DER.to_vec());
    tracing::info!("TSA trust: bundled DigiCert Trusted Root G4 (always-on default)");

    // Optional: operator-supplied extra CAs.
    if let Some(path) = extra_path {
        match std::fs::read(path) {
            Ok(bytes) => {
                let mut count = 0;
                for pem in x509_parser::pem::Pem::iter_from_buffer(&bytes).flatten() {
                    roots.push(pem.contents);
                    count += 1;
                }
                tracing::info!(
                    "TSA trust: loaded {} additional anchor(s) from {}",
                    count,
                    path
                );
            }
            Err(e) => {
                tracing::error!("Failed to read TSA CA file {}: {}", path, e);
            }
        }
    }

    // Opt-in: OS native trust store. Gated by `--insecure`.
    if trust_system_store {
        let cert_res = rustls_native_certs::load_native_certs();
        let count = cert_res.certs.len();
        for c in cert_res.certs {
            roots.push(c.as_ref().to_vec());
        }
        if !cert_res.errors.is_empty() {
            tracing::warn!("Errors loading native certs: {:?}", cert_res.errors);
        }
        tracing::warn!(
            "TSA trust: system store enabled (INSECURE) — trusting {} additional OS CA(s)",
            count
        );
    }

    roots
}
