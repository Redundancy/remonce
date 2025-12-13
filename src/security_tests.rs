#[cfg(test)]
mod tests {
    use crate::security::{ExecutionRequest, ValidationError, VerifierConfig, verify_execution};
    use crate::tsa::{MessageImprint, TSTInfo};
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use chrono;
    use jsonwebtoken::jwk::{Jwk, JwkSet};
    use p256::ecdsa::{Signature, SigningKey, VerifyingKey, signature::Signer};
    use p256::pkcs8::{EncodePrivateKey, EncodePublicKey};
    use rand::rngs::OsRng;
    use rasn::prelude::*;
    use rasn_cms::{
        ContentInfo, EncapsulatedContentInfo, IssuerAndSerialNumber, SignedData, SignerIdentifier,
        SignerInfo,
    };
    use rasn_pkix::{
        AlgorithmIdentifier, Certificate, SubjectPublicKeyInfo, TbsCertificate, Validity,
    };
    use serde_json::json;
    use sha2::{Digest, Sha256};
    use time::{Duration, OffsetDateTime};

    // --- Helpers ---

    struct TestKeys {
        signing_key: SigningKey,
        kid: String,
        jwk_set: JwkSet,
        public_key_pem: String,
    }

    struct TsaKeys {
        cert_der: Vec<u8>,
        signing_key: SigningKey,
    }

    fn setup_keys() -> TestKeys {
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let kid = "test-key-1".to_string();

        let public_key_pem = verifying_key
            .to_public_key_pem(p256::pkcs8::LineEnding::LF)
            .unwrap();

        let public_key_jwk = serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": URL_SAFE_NO_PAD.encode(verifying_key.to_encoded_point(false).x().unwrap()),
            "y": URL_SAFE_NO_PAD.encode(verifying_key.to_encoded_point(false).y().unwrap()),
            "kid": kid,
            "use": "sig",
            "alg": "ES256"
        });

        let jwk: Jwk = serde_json::from_value(public_key_jwk).expect("Failed to create JWK");
        let jwk_set = JwkSet { keys: vec![jwk] };

        TestKeys {
            signing_key,
            kid,
            jwk_set,
            public_key_pem,
        }
    }

    fn create_valid_jwt(
        keys: &TestKeys,
        issuer: &str,
        audience: &str,
        subject: &str,
        nonce: &str,
        expiry: OffsetDateTime,
    ) -> String {
        let header = jsonwebtoken::Header {
            alg: jsonwebtoken::Algorithm::ES256,
            kid: Some(keys.kid.clone()),
            ..Default::default()
        };

        #[derive(serde::Serialize)]
        struct TestClaims {
            sub: String,
            iss: String,
            aud: String,
            exp: i64,
            nonce: String,
        }

        let claims = TestClaims {
            sub: subject.to_string(),
            iss: issuer.to_string(),
            aud: audience.to_string(),
            exp: expiry.unix_timestamp(),
            nonce: nonce.to_string(),
        };

        let private_key_pem = keys
            .signing_key
            .to_pkcs8_pem(p256::pkcs8::LineEnding::LF)
            .unwrap();
        let encoding_key =
            jsonwebtoken::EncodingKey::from_ec_pem(private_key_pem.as_bytes()).unwrap();

        jsonwebtoken::encode(&header, &claims, &encoding_key).unwrap()
    }

    // Generates a minimal Self-Signed X.509 Certificate for testing
    fn generate_tsa_keys() -> TsaKeys {
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let spki_der = verifying_key.to_public_key_der().unwrap();

        let mut spki_info: SubjectPublicKeyInfo =
            rasn::der::decode(spki_der.as_bytes()).expect("Failed to decode generated SPKI");

        let sig_alg_oid = ObjectIdentifier::new_unchecked(std::borrow::Cow::Borrowed(&[
            1, 2, 840, 10045, 4, 3, 2,
        ])); // ecdsa-with-SHA256
        let sig_alg = AlgorithmIdentifier {
            algorithm: sig_alg_oid.clone(),
            parameters: None,
        };

        // Construct Name (RDNSequence) manually
        // CN=Test TSA
        let common_name_oid =
            ObjectIdentifier::new_unchecked(std::borrow::Cow::Borrowed(&[2, 5, 4, 3]));
        let cn_value = rasn::der::encode(&Utf8String::from("Test TSA")).unwrap();

        let mut rdn_set = rasn::types::SetOf::new();
        rdn_set.insert(rasn_pkix::AttributeTypeAndValue {
            r#type: common_name_oid.clone(),
            value: Any::new(cn_value),
        });

        // Wrap in Vec (RDNSequence) -> rasn_cms::Name::RdnSequence
        let rdn_sequence = vec![rdn_set.into()];
        let issuer_name = rasn_cms::Name::RdnSequence(rdn_sequence.clone());
        let subject_name = rasn_cms::Name::RdnSequence(rdn_sequence);

        let tbs = TbsCertificate {
            version: rasn_pkix::Version::V3,
            serial_number: Integer::from(1001),
            signature: sig_alg.clone(),
            issuer: issuer_name,
            validity: Validity {
                not_before: rasn_pkix::Time::Utc(rasn::types::UtcTime::from(chrono::Utc::now())),
                not_after: rasn_pkix::Time::Utc(rasn::types::UtcTime::from(
                    chrono::Utc::now() + chrono::Duration::days(365),
                )),
            },
            subject: subject_name,
            subject_public_key_info: spki_info,
            issuer_unique_id: None,
            subject_unique_id: None,
            extensions: None,
        };

        let tbs_bytes = rasn::der::encode(&tbs).expect("Failed to encode TBS");

        // Sign TBS
        let signature: Signature = signing_key.sign(&tbs_bytes);

        let cert = Certificate {
            tbs_certificate: tbs,
            signature_algorithm: sig_alg,
            signature_value: BitString::from_slice(&signature.to_bytes()),
        };

        let cert_der = rasn::der::encode(&cert).expect("Failed to encode Cert");

        TsaKeys {
            cert_der,
            signing_key,
        }
    }

    // Constructs a valid signed RFC 3161 Timestamp Token
    fn create_mock_timestamp(data: &[u8], gen_time: OffsetDateTime, tsa_keys: &TsaKeys) -> String {
        // 1. Message Imprint
        let hash = Sha256::digest(data);
        let sha256_oid = ObjectIdentifier::new_unchecked(std::borrow::Cow::Borrowed(&[
            2, 16, 840, 1, 101, 3, 4, 2, 1,
        ]));
        let alg_id = AlgorithmIdentifier {
            algorithm: sha256_oid.clone(),
            parameters: None,
        };

        let msg_imprint = MessageImprint {
            hash_algorithm: alg_id,
            hashed_message: OctetString::from(hash.as_slice().to_vec()),
        };

        // 2. TSTInfo
        let unix_timestamp = gen_time.unix_timestamp();
        let nanos = gen_time.nanosecond();
        let chrono_time = chrono::DateTime::from_timestamp(unix_timestamp, nanos)
            .unwrap()
            .with_timezone(&chrono::FixedOffset::east_opt(0).unwrap());

        let rasn_time = rasn::types::GeneralizedTime::from(chrono_time);

        let tst_info = TSTInfo {
            version: Integer::from(1),
            policy: ObjectIdentifier::new_unchecked(std::borrow::Cow::Borrowed(&[1, 2, 3, 4])),
            message_imprint: msg_imprint,
            serial_number: Integer::from(12345),
            gen_time: rasn_time,
            accuracy: None,
            ordering: false,
            nonce: None,
            tsa: None,
            extensions: None,
        };

        let tst_info_bytes = rasn::der::encode(&tst_info).unwrap();

        // 3. EncapsulatedContentInfo
        let tst_info_oid = ObjectIdentifier::new_unchecked(std::borrow::Cow::Borrowed(&[
            1, 2, 840, 113549, 1, 9, 16, 1, 4,
        ]));
        let encap = EncapsulatedContentInfo {
            content_type: tst_info_oid,
            content: Some(OctetString::from(tst_info_bytes.clone())),
        };

        // 4. SignerInfo & Valid Signature
        // Digest Alg
        let digest_alg = AlgorithmIdentifier {
            algorithm: sha256_oid,
            parameters: None,
        };

        // Signature
        let signature: Signature = tsa_keys.signing_key.sign(&tst_info_bytes);

        // Sid: IssuerAndSerialNumber
        let common_name_oid =
            ObjectIdentifier::new_unchecked(std::borrow::Cow::Borrowed(&[2, 5, 4, 3]));
        let cn_value = rasn::der::encode(&Utf8String::from("Test TSA")).unwrap();
        let mut rdn_set = rasn::types::SetOf::new();
        rdn_set.insert(rasn_pkix::AttributeTypeAndValue {
            r#type: common_name_oid.clone(),
            value: Any::new(cn_value),
        });
        let issuer_name = rasn_cms::Name::RdnSequence(vec![rdn_set.into()]);

        let sid = SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
            issuer: issuer_name,
            serial_number: Integer::from(1001),
        });

        let sig_alg_oid = ObjectIdentifier::new_unchecked(std::borrow::Cow::Borrowed(&[
            1, 2, 840, 10045, 4, 3, 2,
        ])); // ecdsa-with-SHA256
        let sig_alg = AlgorithmIdentifier {
            algorithm: sig_alg_oid,
            parameters: None,
        };

        let signer_info = SignerInfo {
            version: Integer::from(1),
            sid: sid,
            digest_algorithm: digest_alg,
            signed_attrs: None,
            signature_algorithm: sig_alg,
            signature: OctetString::from(signature.to_der().as_bytes().to_vec()),
            unsigned_attrs: None,
        };

        // 5. SignedData
        let cert_decoded: Certificate = rasn::der::decode(&tsa_keys.cert_der).unwrap();
        // Box it for the enum variant
        let certs = SetOf::from_vec(vec![rasn_cms::CertificateChoices::Certificate(Box::new(
            cert_decoded,
        ))]);

        let signed_data = SignedData {
            version: Integer::from(3),
            digest_algorithms: SetOf::new(),
            encap_content_info: encap,
            certificates: Some(certs),
            crls: None,
            signer_infos: SetOf::from_vec(vec![signer_info]),
        };

        let signed_data_bytes = rasn::der::encode(&signed_data).unwrap();

        // 6. ContentInfo
        let signed_data_oid = ObjectIdentifier::new_unchecked(std::borrow::Cow::Borrowed(&[
            1, 2, 840, 113549, 1, 7, 2,
        ]));
        let content_info = ContentInfo {
            content_type: signed_data_oid,
            content: Any::new(signed_data_bytes),
        };

        hex::encode(rasn::der::encode(&content_info).unwrap())
    }

    // --- Tests ---

    #[test]
    fn test_verify_execution_happy_path() {
        let keys = setup_keys();
        let tsa_keys = generate_tsa_keys();

        let command = json!({"command": "test-cmd", "args": []});
        let command_str = command.to_string();

        // Sign Command
        let signature: p256::ecdsa::Signature = keys.signing_key.sign(command_str.as_bytes());
        let signature_hex = hex::encode(signature.to_bytes());

        // Generate Keys/Nonce
        let public_key_hash = hex::encode(Sha256::digest(keys.public_key_pem.as_bytes()));

        // Valid Time
        let now = OffsetDateTime::now_utc();
        let exp = now + Duration::minutes(5);

        let id_token = create_valid_jwt(
            &keys,
            "https://issuer.com",
            "my-client",
            "user123",
            &public_key_hash,
            exp,
        );

        // Timestamp Data
        let mut data_to_timestamp = signature.to_bytes().to_vec();
        data_to_timestamp.extend_from_slice(id_token.as_bytes());

        let timestamp_token_hex = create_mock_timestamp(&data_to_timestamp, now, &tsa_keys);

        let config = VerifierConfig {
            client_id: "my-client".to_string(),
            issuer_url: "https://issuer.com".to_string(),
            jwks: keys.jwk_set.clone(),
            trusted_roots: vec![tsa_keys.cert_der.clone()], // Trust the TSA cert
        };

        let req = ExecutionRequest {
            command: command,
            signature_hex,
            id_token,
            public_key_pem: keys.public_key_pem.clone(),
            timestamp_token_hex,
        };

        let result = verify_execution(&req, &config);
        assert!(result.is_ok(), "Verification failed: {:?}", result.err());
        let user = result.unwrap();
        assert_eq!(user.username, "user123");
        assert!((user.timestamp - now).abs() < Duration::seconds(1));
    }

    #[test]
    fn test_reject_invalid_command_signature() {
        let keys = setup_keys();
        let tsa_keys = generate_tsa_keys();
        let command = json!({"command": "test-cmd"});
        let other_command = json!({"command": "other"});

        // Sign WRONG command
        let signature: p256::ecdsa::Signature =
            keys.signing_key.sign(other_command.to_string().as_bytes());
        let signature_hex = hex::encode(signature.to_bytes());

        let req = ExecutionRequest {
            command: command,
            signature_hex,
            id_token: "dummy".into(),
            public_key_pem: keys.public_key_pem.clone(),
            timestamp_token_hex: "dummy".into(),
        };

        let config = VerifierConfig {
            client_id: "id".into(),
            issuer_url: "url".into(),
            jwks: keys.jwk_set.clone(),
            trusted_roots: vec![],
        };

        let result = verify_execution(&req, &config);
        assert!(matches!(
            result,
            Err(ValidationError::SignatureVerificationFailed)
        ));
    }

    #[test]
    fn test_reject_timestamp_hash_mismatch() {
        let keys = setup_keys();
        let tsa_keys = generate_tsa_keys();
        let command = json!({"command": "test-cmd"});
        let signature: p256::ecdsa::Signature =
            keys.signing_key.sign(command.to_string().as_bytes());
        let signature_hex = hex::encode(signature.to_bytes());

        let public_key_hash = hex::encode(Sha256::digest(keys.public_key_pem.as_bytes()));
        let id_token = create_valid_jwt(
            &keys,
            "iss",
            "aud",
            "sub",
            &public_key_hash,
            OffsetDateTime::now_utc() + Duration::minutes(5),
        );

        // Timestamp some GARBAGE data
        let timestamp_token_hex =
            create_mock_timestamp(b"garbage", OffsetDateTime::now_utc(), &tsa_keys);

        let req = ExecutionRequest {
            command,
            signature_hex,
            id_token,
            public_key_pem: keys.public_key_pem.clone(),
            timestamp_token_hex,
        };
        let config = VerifierConfig {
            client_id: "aud".into(),
            issuer_url: "iss".into(),
            jwks: keys.jwk_set.clone(),
            trusted_roots: vec![tsa_keys.cert_der],
        };

        let result = verify_execution(&req, &config);
        assert!(matches!(
            result,
            Err(ValidationError::TimestampVerificationFailed(_))
        ));
    }

    #[test]
    fn test_jwt_expiry_logic_valid_if_timestamped_before_expiry() {
        let keys = setup_keys();
        let tsa_keys = generate_tsa_keys();
        let command = json!({"command": "test-cmd"});
        let signature: p256::ecdsa::Signature =
            keys.signing_key.sign(command.to_string().as_bytes());
        let signature_hex = hex::encode(signature.to_bytes());
        let public_key_hash = hex::encode(Sha256::digest(keys.public_key_pem.as_bytes()));

        // Token expired 1 year ago relative to NOW
        let valid_start = OffsetDateTime::now_utc() - Duration::days(400);
        let expiry = valid_start + Duration::minutes(30);

        let id_token = create_valid_jwt(&keys, "iss", "aud", "sub", &public_key_hash, expiry);

        // Timestamp was created WHILE token was valid
        let timestamp_time = valid_start + Duration::minutes(10);

        let mut data = signature.to_bytes().to_vec();
        data.extend_from_slice(id_token.as_bytes());
        let timestamp_token_hex = create_mock_timestamp(&data, timestamp_time, &tsa_keys);

        let req = ExecutionRequest {
            command,
            signature_hex,
            id_token,
            public_key_pem: keys.public_key_pem.clone(),
            timestamp_token_hex,
        };
        let config = VerifierConfig {
            client_id: "aud".into(),
            issuer_url: "iss".into(),
            jwks: keys.jwk_set.clone(),
            trusted_roots: vec![tsa_keys.cert_der],
        };

        let result = verify_execution(&req, &config);
        assert!(
            result.is_ok(),
            "Should accept token if timestamp is within validity period"
        );
    }

    #[test]
    fn test_jwt_expiry_logic_invalid_if_timestamped_after_expiry() {
        let keys = setup_keys();
        let tsa_keys = generate_tsa_keys();
        let command = json!({"command": "test-cmd"});
        let signature: p256::ecdsa::Signature =
            keys.signing_key.sign(command.to_string().as_bytes());
        let signature_hex = hex::encode(signature.to_bytes());
        let public_key_hash = hex::encode(Sha256::digest(keys.public_key_pem.as_bytes()));

        // Token valid window
        let valid_start = OffsetDateTime::now_utc();
        let expiry = valid_start + Duration::minutes(30);

        let id_token = create_valid_jwt(&keys, "iss", "aud", "sub", &public_key_hash, expiry);

        // Timestamp created AFTER token expired
        let timestamp_time = expiry + Duration::seconds(1);

        let mut data = signature.to_bytes().to_vec();
        data.extend_from_slice(id_token.as_bytes());
        let timestamp_token_hex = create_mock_timestamp(&data, timestamp_time, &tsa_keys);

        let req = ExecutionRequest {
            command,
            signature_hex,
            id_token,
            public_key_pem: keys.public_key_pem.clone(),
            timestamp_token_hex,
        };
        let config = VerifierConfig {
            client_id: "aud".into(),
            issuer_url: "iss".into(),
            jwks: keys.jwk_set.clone(),
            trusted_roots: vec![tsa_keys.cert_der],
        };

        let result = verify_execution(&req, &config);
        assert!(
            matches!(result, Err(ValidationError::JwtExpired)),
            "Should reject if timestamp > exp"
        );
    }

    #[test]
    fn test_reject_jwt_nonce_mismatch() {
        let keys = setup_keys();
        let tsa_keys = generate_tsa_keys();
        let command = json!({"command": "test-cmd"});
        let signature: p256::ecdsa::Signature =
            keys.signing_key.sign(command.to_string().as_bytes());
        let signature_hex = hex::encode(signature.to_bytes());

        // Nonce mismatch
        let id_token = create_valid_jwt(
            &keys,
            "iss",
            "aud",
            "sub",
            "wrong-nonce",
            OffsetDateTime::now_utc() + Duration::minutes(5),
        );

        let now = OffsetDateTime::now_utc();
        let mut data = signature.to_bytes().to_vec();
        data.extend_from_slice(id_token.as_bytes());
        let timestamp_token_hex = create_mock_timestamp(&data, now, &tsa_keys);

        let req = ExecutionRequest {
            command,
            signature_hex,
            id_token,
            public_key_pem: keys.public_key_pem.clone(),
            timestamp_token_hex,
        };
        let config = VerifierConfig {
            client_id: "aud".into(),
            issuer_url: "iss".into(),
            jwks: keys.jwk_set.clone(),
            trusted_roots: vec![tsa_keys.cert_der],
        };

        let result = verify_execution(&req, &config);
        assert!(matches!(result, Err(ValidationError::JwtNonceMismatch)));
    }

    #[test]
    fn test_reject_untrusted_tsa_cert() {
        let keys = setup_keys();
        let tsa_keys = generate_tsa_keys(); // "Real" TSA
        let attacker_keys = generate_tsa_keys(); // Attacker's self-signed TSA

        let command = json!({"command": "test-cmd"});
        let signature: p256::ecdsa::Signature =
            keys.signing_key.sign(command.to_string().as_bytes());
        let signature_hex = hex::encode(signature.to_bytes());
        let public_key_hash = hex::encode(Sha256::digest(keys.public_key_pem.as_bytes()));

        let id_token = create_valid_jwt(
            &keys,
            "iss",
            "aud",
            "sub",
            &public_key_hash,
            OffsetDateTime::now_utc() + Duration::minutes(5),
        );

        let mut data = signature.to_bytes().to_vec();
        data.extend_from_slice(id_token.as_bytes());

        // Token signed by Attacker
        let timestamp_token_hex =
            create_mock_timestamp(&data, OffsetDateTime::now_utc(), &attacker_keys);

        let req = ExecutionRequest {
            command,
            signature_hex,
            id_token,
            public_key_pem: keys.public_key_pem.clone(),
            timestamp_token_hex,
        };
        // Config ONLY trusts the Real TSA
        let config = VerifierConfig {
            client_id: "aud".into(),
            issuer_url: "iss".into(),
            jwks: keys.jwk_set.clone(),
            trusted_roots: vec![tsa_keys.cert_der],
        };

        let result = verify_execution(&req, &config);
        assert!(matches!(
            result,
            Err(ValidationError::TimestampVerificationFailed(_))
        )); // Should fail TSA verification
    }
}
