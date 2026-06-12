#[cfg(test)]
mod tests {
    use crate::security::{
        ApproverBundle, ClaimPredicate, ExecutionBundle, OperatorConstraint, OperatorCosign,
        RevocationBundle, RevokerAttestation, ValidationError, VerifierConfig,
        canonical_approver_payload, revocation_payload, verify_execution, verify_revocation,
    };
    use crate::tsa::{MessageImprint, TSTInfo};
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use chrono;
    use jsonwebtoken::jwk::{Jwk, JwkSet};
    use p256::ecdsa::{Signature, SigningKey, signature::Signer};
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
    use std::time::Duration as StdDuration;
    use time::{Duration, OffsetDateTime};

    // --- Key helpers ---

    struct TestKeys {
        signing_key: SigningKey,
        kid: String,
        public_key_pem: String,
    }

    struct TsaKeys {
        cert_der: Vec<u8>,
        signing_key: SigningKey,
    }

    fn setup_keys(kid: &str) -> TestKeys {
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        let public_key_pem = verifying_key
            .to_public_key_pem(p256::pkcs8::LineEnding::LF)
            .unwrap();

        TestKeys {
            signing_key,
            kid: kid.to_string(),
            public_key_pem,
        }
    }

    fn keys_to_jwk(keys: &TestKeys) -> Jwk {
        let verifying_key = keys.signing_key.verifying_key();
        let j = serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": URL_SAFE_NO_PAD.encode(verifying_key.to_encoded_point(false).x().unwrap()),
            "y": URL_SAFE_NO_PAD.encode(verifying_key.to_encoded_point(false).y().unwrap()),
            "kid": keys.kid,
            "use": "sig",
            "alg": "ES256"
        });
        serde_json::from_value(j).expect("Failed to create JWK")
    }

    fn create_valid_jwt(
        keys: &TestKeys,
        issuer: &str,
        audience: &str,
        subject: &str,
        nonce: &str,
        expiry: OffsetDateTime,
        extra_claims: serde_json::Value,
    ) -> String {
        let header = jsonwebtoken::Header {
            alg: jsonwebtoken::Algorithm::ES256,
            kid: Some(keys.kid.clone()),
            ..Default::default()
        };

        let mut claims = serde_json::json!({
            "sub": subject,
            "iss": issuer,
            "aud": audience,
            "exp": expiry.unix_timestamp(),
            "nonce": nonce,
            "username": subject,
        });
        if let Some(obj) = extra_claims.as_object() {
            for (k, v) in obj {
                claims[k] = v.clone();
            }
        }

        let private_key_pem = keys
            .signing_key
            .to_pkcs8_pem(p256::pkcs8::LineEnding::LF)
            .unwrap();
        let encoding_key =
            jsonwebtoken::EncodingKey::from_ec_pem(private_key_pem.as_bytes()).unwrap();

        jsonwebtoken::encode(&header, &claims, &encoding_key).unwrap()
    }

    fn generate_tsa_keys() -> TsaKeys {
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let spki_der = verifying_key.to_public_key_der().unwrap();

        let spki_info: SubjectPublicKeyInfo =
            rasn::der::decode(spki_der.as_bytes()).expect("Failed to decode generated SPKI");

        let sig_alg_oid = ObjectIdentifier::new_unchecked(std::borrow::Cow::Borrowed(&[
            1, 2, 840, 10045, 4, 3, 2,
        ]));
        let sig_alg = AlgorithmIdentifier {
            algorithm: sig_alg_oid.clone(),
            parameters: None,
        };

        let common_name_oid =
            ObjectIdentifier::new_unchecked(std::borrow::Cow::Borrowed(&[2, 5, 4, 3]));
        let cn_value = rasn::der::encode(&Utf8String::from("Test TSA")).unwrap();

        let mut rdn_set = rasn::types::SetOf::new();
        rdn_set.insert(rasn_pkix::AttributeTypeAndValue {
            r#type: common_name_oid.clone(),
            value: Any::new(cn_value),
        });

        let rdn_sequence = vec![rdn_set.into()];
        let issuer_name = rasn_cms::Name::RdnSequence(rdn_sequence.clone());
        let subject_name = rasn_cms::Name::RdnSequence(rdn_sequence);

        // Build ExtendedKeyUsage extension with id-kp-timeStamping so webpki
        // accepts this cert as a TSA signer.
        let timestamping_oid = ObjectIdentifier::new_unchecked(std::borrow::Cow::Borrowed(&[
            1, 3, 6, 1, 5, 5, 7, 3, 8,
        ]));
        let eku_inner: Vec<ObjectIdentifier> = vec![timestamping_oid];
        let eku_der = rasn::der::encode(&eku_inner).unwrap();
        let ext_ext_key_usage_oid =
            ObjectIdentifier::new_unchecked(std::borrow::Cow::Borrowed(&[2, 5, 29, 37]));
        let eku_extension = rasn_pkix::Extension {
            extn_id: ext_ext_key_usage_oid,
            critical: false,
            extn_value: OctetString::from(eku_der),
        };

        let tbs = TbsCertificate {
            version: rasn_pkix::Version::V3,
            serial_number: Integer::from(1001),
            signature: sig_alg.clone(),
            issuer: issuer_name,
            validity: Validity {
                // Backdate not_before so tests can reference "gen_time in the past"
                // without tripping webpki's NotValidYet check.
                not_before: rasn_pkix::Time::Utc(rasn::types::UtcTime::from(
                    chrono::Utc::now() - chrono::Duration::days(365),
                )),
                not_after: rasn_pkix::Time::Utc(rasn::types::UtcTime::from(
                    chrono::Utc::now() + chrono::Duration::days(365),
                )),
            },
            subject: subject_name,
            subject_public_key_info: spki_info,
            issuer_unique_id: None,
            subject_unique_id: None,
            extensions: Some(vec![eku_extension].into()),
        };

        let tbs_bytes = rasn::der::encode(&tbs).expect("Failed to encode TBS");
        let signature: Signature = signing_key.sign(&tbs_bytes);

        let cert = Certificate {
            tbs_certificate: tbs,
            signature_algorithm: sig_alg,
            // X.509 encodes ECDSA signatures as DER SEQUENCE { r, s }, not raw r||s.
            signature_value: BitString::from_slice(signature.to_der().as_bytes()),
        };

        let cert_der = rasn::der::encode(&cert).expect("Failed to encode Cert");

        TsaKeys {
            cert_der,
            signing_key,
        }
    }

    fn create_mock_timestamp(data: &[u8], gen_time: OffsetDateTime, tsa_keys: &TsaKeys) -> String {
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

        let tst_info_oid = ObjectIdentifier::new_unchecked(std::borrow::Cow::Borrowed(&[
            1, 2, 840, 113549, 1, 9, 16, 1, 4,
        ]));
        let encap = EncapsulatedContentInfo {
            content_type: tst_info_oid,
            content: Some(OctetString::from(tst_info_bytes.clone())),
        };

        let digest_alg = AlgorithmIdentifier {
            algorithm: sha256_oid,
            parameters: None,
        };
        let signature: Signature = tsa_keys.signing_key.sign(&tst_info_bytes);

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
        ]));
        let sig_alg = AlgorithmIdentifier {
            algorithm: sig_alg_oid,
            parameters: None,
        };

        let signer_info = SignerInfo {
            version: Integer::from(1),
            sid,
            digest_algorithm: digest_alg,
            signed_attrs: None,
            signature_algorithm: sig_alg,
            signature: OctetString::from(signature.to_der().as_bytes().to_vec()),
            unsigned_attrs: None,
        };

        let cert_decoded: Certificate = rasn::der::decode(&tsa_keys.cert_der).unwrap();
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

        let signed_data_oid = ObjectIdentifier::new_unchecked(std::borrow::Cow::Borrowed(&[
            1, 2, 840, 113549, 1, 7, 2,
        ]));
        let content_info = ContentInfo {
            content_type: signed_data_oid,
            content: Any::new(signed_data_bytes),
        };

        hex::encode(rasn::der::encode(&content_info).unwrap())
    }

    // --- Bundle builders ---

    struct Env {
        tsa_keys: TsaKeys,
        approver: TestKeys,
        operator: TestKeys,
        jwks: JwkSet,
    }

    fn new_env() -> Env {
        let approver = setup_keys("approver-kid");
        let operator = setup_keys("operator-kid");
        let jwks = JwkSet {
            keys: vec![keys_to_jwk(&approver), keys_to_jwk(&operator)],
        };
        Env {
            tsa_keys: generate_tsa_keys(),
            approver,
            operator,
            jwks,
        }
    }

    fn build_approver_bundle(
        env: &Env,
        command: serde_json::Value,
        operator_requires: Option<OperatorConstraint>,
        approver_signed_at: OffsetDateTime,
        approver_groups: Vec<&str>,
    ) -> ApproverBundle {
        let canonical = canonical_approver_payload(&command, &operator_requires);
        let sig: p256::ecdsa::Signature = env.approver.signing_key.sign(canonical.as_bytes());
        let sig_bytes = sig.to_bytes();
        let sig_hex = hex::encode(sig_bytes);

        let nonce = hex::encode(Sha256::digest(env.approver.public_key_pem.as_bytes()));
        let id_token = create_valid_jwt(
            &env.approver,
            "https://issuer.example",
            "remonce",
            "alice",
            &nonce,
            approver_signed_at + Duration::minutes(30),
            serde_json::json!({ "groups": approver_groups }),
        );

        let mut data = sig_bytes.to_vec();
        data.extend_from_slice(id_token.as_bytes());
        let timestamp_token = create_mock_timestamp(&data, approver_signed_at, &env.tsa_keys);

        ApproverBundle {
            command,
            operator_requires,
            signature: sig_hex,
            id_token,
            public_key: env.approver.public_key_pem.clone(),
            timestamp_token,
        }
    }

    fn build_operator_cosign(
        env: &Env,
        approver_sig_hex: &str,
        operator_signed_at: OffsetDateTime,
        operator_groups: Vec<&str>,
    ) -> OperatorCosign {
        let mut payload = approver_sig_hex.as_bytes().to_vec();
        payload.extend_from_slice(env.operator.public_key_pem.as_bytes());
        let sig: p256::ecdsa::Signature = env.operator.signing_key.sign(&payload);
        let sig_bytes = sig.to_bytes();

        let nonce = hex::encode(Sha256::digest(env.operator.public_key_pem.as_bytes()));
        let id_token = create_valid_jwt(
            &env.operator,
            "https://issuer.example",
            "remonce",
            "bob",
            &nonce,
            operator_signed_at + Duration::minutes(30),
            serde_json::json!({ "groups": operator_groups }),
        );

        let mut tsa_data = sig_bytes.to_vec();
        tsa_data.extend_from_slice(id_token.as_bytes());
        let timestamp_token = create_mock_timestamp(&tsa_data, operator_signed_at, &env.tsa_keys);

        OperatorCosign {
            approver_sig: approver_sig_hex.to_string(),
            signature: hex::encode(sig_bytes),
            id_token,
            public_key: env.operator.public_key_pem.clone(),
            timestamp_token,
        }
    }

    fn build_revoker_attestation(
        env: &Env,
        revoker_keys: &TestKeys,
        subject: &str,
        approver_sig_hex: &str,
        revoker_signed_at: OffsetDateTime,
    ) -> RevokerAttestation {
        let payload = revocation_payload(approver_sig_hex, &revoker_keys.public_key_pem);
        let sig: p256::ecdsa::Signature = revoker_keys.signing_key.sign(&payload);
        let sig_bytes = sig.to_bytes();

        let nonce = hex::encode(Sha256::digest(revoker_keys.public_key_pem.as_bytes()));
        let id_token = create_valid_jwt(
            revoker_keys,
            "https://issuer.example",
            "remonce",
            subject,
            &nonce,
            revoker_signed_at + Duration::minutes(30),
            serde_json::json!({}),
        );

        let mut tsa_data = sig_bytes.to_vec();
        tsa_data.extend_from_slice(id_token.as_bytes());
        let timestamp_token = create_mock_timestamp(&tsa_data, revoker_signed_at, &env.tsa_keys);

        RevokerAttestation {
            signature: hex::encode(sig_bytes),
            id_token,
            public_key: revoker_keys.public_key_pem.clone(),
            timestamp_token,
        }
    }

    fn verifier_config(env: &Env) -> VerifierConfig {
        VerifierConfig {
            client_id: "remonce".into(),
            issuer_url: "https://issuer.example".into(),
            jwks: env.jwks.clone(),
            trusted_roots: vec![env.tsa_keys.cert_der.clone()],
            approver_max_validity: StdDuration::from_secs(3 * 24 * 60 * 60), // 3 days
            operator_max_validity: StdDuration::from_secs(10 * 60),          // 10 minutes
        }
    }

    // --- Self-execute tests ---

    #[test]
    fn self_execute_fresh_is_authorized() {
        let env = new_env();
        let now = OffsetDateTime::now_utc();
        let approver = build_approver_bundle(
            &env,
            json!({ "command": "ping-test" }),
            None,
            now,
            vec!["approvers"],
        );
        let bundle = ExecutionBundle {
            approver,
            operator: None,
        };
        let result = verify_execution(&bundle, &verifier_config(&env));
        assert!(result.is_ok(), "expected ok, got {:?}", result.err());
        let a = result.unwrap();
        assert!(a.self_executed);
        assert_eq!(a.approver.username, "alice");
        assert_eq!(a.operator.username, "alice");
    }

    #[test]
    fn self_execute_stale_is_rejected() {
        let env = new_env();
        // 30 minutes ago — way past operator_max_validity of 10m.
        let stale = OffsetDateTime::now_utc() - Duration::minutes(30);
        let approver = build_approver_bundle(
            &env,
            json!({ "command": "ping-test" }),
            None,
            stale,
            vec!["approvers"],
        );
        let bundle = ExecutionBundle {
            approver,
            operator: None,
        };
        let result = verify_execution(&bundle, &verifier_config(&env));
        assert!(
            matches!(result, Err(ValidationError::ExecutorStale { .. })),
            "expected ExecutorStale, got {:?}",
            result
        );
    }

    // --- Delegated tests ---

    #[test]
    fn delegated_fresh_operator_old_approver_authorized() {
        let env = new_env();
        let now = OffsetDateTime::now_utc();
        // Approver signed 2 days ago (within 3-day approver_max)
        let approver = build_approver_bundle(
            &env,
            json!({ "command": "ping-test" }),
            Some(OperatorConstraint {
                any_of: vec![ClaimPredicate::Contains {
                    claim: "groups".into(),
                    value: serde_json::json!("noc-l2"),
                }],
            }),
            now - Duration::days(2),
            vec!["approvers"],
        );
        let op = build_operator_cosign(&env, &approver.signature, now, vec!["noc-l2"]);

        let bundle = ExecutionBundle {
            approver,
            operator: Some(op),
        };
        let result = verify_execution(&bundle, &verifier_config(&env));
        assert!(result.is_ok(), "expected ok, got {:?}", result.err());
        let a = result.unwrap();
        assert!(!a.self_executed);
        assert_eq!(a.approver.username, "alice");
        assert_eq!(a.operator.username, "bob");
    }

    #[test]
    fn delegated_stale_operator_rejected() {
        let env = new_env();
        let now = OffsetDateTime::now_utc();
        let approver = build_approver_bundle(
            &env,
            json!({ "command": "ping-test" }),
            None,
            now - Duration::minutes(1),
            vec!["approvers"],
        );
        // Operator cosigned 30 minutes ago — beyond 10m operator_max.
        let op = build_operator_cosign(
            &env,
            &approver.signature,
            now - Duration::minutes(30),
            vec!["noc-l2"],
        );
        let bundle = ExecutionBundle {
            approver,
            operator: Some(op),
        };
        let result = verify_execution(&bundle, &verifier_config(&env));
        assert!(
            matches!(result, Err(ValidationError::ExecutorStale { .. })),
            "expected ExecutorStale, got {:?}",
            result
        );
    }

    #[test]
    fn delegated_approver_too_old_rejected() {
        let env = new_env();
        let now = OffsetDateTime::now_utc();
        // Approver signed 10 days ago — past 3-day approver_max.
        let approver = build_approver_bundle(
            &env,
            json!({ "command": "ping-test" }),
            None,
            now - Duration::days(10),
            vec!["approvers"],
        );
        let op = build_operator_cosign(&env, &approver.signature, now, vec!["noc-l2"]);
        let bundle = ExecutionBundle {
            approver,
            operator: Some(op),
        };
        let result = verify_execution(&bundle, &verifier_config(&env));
        assert!(
            matches!(result, Err(ValidationError::ApproverStale { .. })),
            "expected ApproverStale, got {:?}",
            result
        );
    }

    #[test]
    fn delegated_operator_missing_required_claim_rejected() {
        let env = new_env();
        let now = OffsetDateTime::now_utc();
        let approver = build_approver_bundle(
            &env,
            json!({ "command": "ping-test" }),
            Some(OperatorConstraint {
                any_of: vec![ClaimPredicate::Contains {
                    claim: "groups".into(),
                    value: serde_json::json!("noc-l2"),
                }],
            }),
            now - Duration::minutes(1),
            vec!["approvers"],
        );
        // Operator is in "noc-l1" only, not "noc-l2".
        let op = build_operator_cosign(&env, &approver.signature, now, vec!["noc-l1"]);
        let bundle = ExecutionBundle {
            approver,
            operator: Some(op),
        };
        let result = verify_execution(&bundle, &verifier_config(&env));
        assert!(
            matches!(result, Err(ValidationError::OperatorConstraintUnsatisfied)),
            "expected OperatorConstraintUnsatisfied, got {:?}",
            result
        );
    }

    #[test]
    fn stapling_attack_rejected_when_approver_sig_swapped() {
        let env = new_env();
        let now = OffsetDateTime::now_utc();

        // Build approver bundle A + operator cosign bound to it.
        let approver_a = build_approver_bundle(
            &env,
            json!({ "command": "ping-test" }),
            None,
            now - Duration::minutes(1),
            vec!["approvers"],
        );
        let op = build_operator_cosign(&env, &approver_a.signature, now, vec!["noc-l2"]);

        // Build a DIFFERENT approver bundle B (different command).
        let approver_b = build_approver_bundle(
            &env,
            json!({ "command": "dangerous-thing" }),
            None,
            now - Duration::minutes(1),
            vec!["approvers"],
        );

        // Attacker staples operator cosign (bound to A) onto approver B.
        // They set `approver_sig` to match approver_b (passing the equality check)
        // but the operator's signature was computed over approver_a's hex — so it
        // won't match approver_b's.
        let mut tampered_op = op.clone();
        tampered_op.approver_sig = approver_b.signature.clone();

        let bundle = ExecutionBundle {
            approver: approver_b,
            operator: Some(tampered_op),
        };

        let result = verify_execution(&bundle, &verifier_config(&env));
        assert!(
            matches!(result, Err(ValidationError::OperatorSignatureFailed)),
            "expected OperatorSignatureFailed, got {:?}",
            result
        );
    }

    // --- Revocation tests ---

    #[test]
    fn self_revocation_is_recognized() {
        let env = new_env();
        let now = OffsetDateTime::now_utc();
        let approver = build_approver_bundle(
            &env,
            json!({ "command": "ping-test" }),
            None,
            now - Duration::days(1),
            vec!["approvers"],
        );
        // Alice revokes her own approval with a fresh attestation. Her
        // original ephemeral key is gone, so the test uses a new key bound
        // to a fresh token — but the same `sub`.
        let fresh_keys = setup_keys("alice-fresh-kid");
        let mut jwks = env.jwks.clone();
        jwks.keys.push(keys_to_jwk(&fresh_keys));
        let revoker =
            build_revoker_attestation(&env, &fresh_keys, "alice", &approver.signature, now);
        let sig_hex = approver.signature.clone();
        let req = RevocationBundle { approver, revoker };

        let config = VerifierConfig {
            jwks,
            ..verifier_config(&env)
        };
        let result = verify_revocation(&req, &config);
        assert!(result.is_ok(), "expected ok, got {:?}", result.err());
        let r = result.unwrap();
        assert!(r.self_revoked);
        assert_eq!(r.approver.username, "alice");
        assert_eq!(r.revoker.username, "alice");
        assert_eq!(r.approver_signature_hex, sig_hex);
    }

    #[test]
    fn third_party_revocation_not_self() {
        let env = new_env();
        let now = OffsetDateTime::now_utc();
        let approver = build_approver_bundle(
            &env,
            json!({ "command": "ping-test" }),
            None,
            now - Duration::days(1),
            vec!["approvers"],
        );
        let revoker =
            build_revoker_attestation(&env, &env.operator, "bob", &approver.signature, now);
        let req = RevocationBundle { approver, revoker };

        let result = verify_revocation(&req, &verifier_config(&env));
        assert!(result.is_ok(), "expected ok, got {:?}", result.err());
        let r = result.unwrap();
        assert!(!r.self_revoked, "bob is not alice — must not be self_revoked");
        assert_eq!(r.revoker.username, "bob");
    }

    #[test]
    fn stale_revoker_attestation_rejected() {
        let env = new_env();
        let now = OffsetDateTime::now_utc();
        let approver = build_approver_bundle(
            &env,
            json!({ "command": "ping-test" }),
            None,
            now - Duration::days(1),
            vec!["approvers"],
        );
        // Revoker signed 30 minutes ago — past the 10m short window.
        let revoker = build_revoker_attestation(
            &env,
            &env.operator,
            "bob",
            &approver.signature,
            now - Duration::minutes(30),
        );
        let req = RevocationBundle { approver, revoker };

        let result = verify_revocation(&req, &verifier_config(&env));
        assert!(
            matches!(result, Err(ValidationError::ExecutorStale { .. })),
            "expected ExecutorStale, got {:?}",
            result
        );
    }

    #[test]
    fn tampered_approver_bundle_cannot_be_revoked() {
        // The bundle being revoked must itself verify — otherwise anyone
        // could poison the revocation cache with fabricated signatures.
        let env = new_env();
        let now = OffsetDateTime::now_utc();
        let mut approver = build_approver_bundle(
            &env,
            json!({ "command": "ping-test" }),
            None,
            now - Duration::days(1),
            vec!["approvers"],
        );
        approver.command = json!({ "command": "something-else" });
        let revoker =
            build_revoker_attestation(&env, &env.operator, "bob", &approver.signature, now);
        let req = RevocationBundle { approver, revoker };

        let result = verify_revocation(&req, &verifier_config(&env));
        assert!(
            matches!(result, Err(ValidationError::ApproverSignatureFailed)),
            "expected ApproverSignatureFailed, got {:?}",
            result
        );
    }

    #[test]
    fn operator_cosign_signature_cannot_be_replayed_as_revocation() {
        // Domain separation: an operator cosign signs (approver_sig || pubkey)
        // without the REMONCE-REVOKE: prefix, so it must not verify as a
        // revocation attestation.
        let env = new_env();
        let now = OffsetDateTime::now_utc();
        let approver = build_approver_bundle(
            &env,
            json!({ "command": "ping-test" }),
            None,
            now - Duration::days(1),
            vec!["approvers"],
        );
        let cosign = build_operator_cosign(&env, &approver.signature, now, vec!["noc-l2"]);
        let revoker = RevokerAttestation {
            signature: cosign.signature,
            id_token: cosign.id_token,
            public_key: cosign.public_key,
            timestamp_token: cosign.timestamp_token,
        };
        let req = RevocationBundle { approver, revoker };

        let result = verify_revocation(&req, &verifier_config(&env));
        assert!(
            matches!(result, Err(ValidationError::RevokerSignatureFailed)),
            "expected RevokerSignatureFailed, got {:?}",
            result
        );
    }

    #[test]
    fn stapling_attack_mismatched_approver_sig_rejected() {
        // If the attacker doesn't even bother updating `approver_sig` to match
        // the new approver, the explicit mismatch check fires first.
        let env = new_env();
        let now = OffsetDateTime::now_utc();
        let approver_a = build_approver_bundle(
            &env,
            json!({ "command": "ping-test" }),
            None,
            now - Duration::minutes(1),
            vec!["approvers"],
        );
        let op = build_operator_cosign(&env, &approver_a.signature, now, vec!["noc-l2"]);
        let approver_b = build_approver_bundle(
            &env,
            json!({ "command": "dangerous-thing" }),
            None,
            now - Duration::minutes(1),
            vec!["approvers"],
        );
        // Leave op.approver_sig pointing at approver_a even though bundle has approver_b.
        let bundle = ExecutionBundle {
            approver: approver_b,
            operator: Some(op),
        };
        let result = verify_execution(&bundle, &verifier_config(&env));
        assert!(
            matches!(result, Err(ValidationError::OperatorStapling)),
            "expected OperatorStapling, got {:?}",
            result
        );
    }
}
