#[cfg(test)]
mod tests {
    use crate::security::{
        Approval, AuthorizedRevocation, CACHE_SLACK, MAX_APPROVALS, MAX_FUTURE_SKEW, RequestBundle,
        RevocationBundle, ValidationError, VerifiedRequest, VerifierConfig, canonical_request_payload,
        key_binding, replay_ttl, request_id, revocation_keep_until, revocation_payload, sign_low_s,
        verify_bearer_token, verify_request, verify_revocation,
    };
    use crate::tsa::{MessageImprint, TSTInfo};
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
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

    /// A token as a fresh per-signature login would produce: issued 30s
    /// before `signed_at`, authenticated 10s before that, and — to prove the
    /// lifetime no longer matters — valid for a whole day. `extra_claims`
    /// overrides any claim; a `null` value removes it.
    fn create_valid_jwt(
        keys: &TestKeys,
        issuer: &str,
        audience: &str,
        subject: &str,
        nonce: &str,
        signed_at: OffsetDateTime,
        extra_claims: serde_json::Value,
    ) -> String {
        let header = jsonwebtoken::Header {
            alg: jsonwebtoken::Algorithm::ES256,
            kid: Some(keys.kid.clone()),
            ..Default::default()
        };

        let iat = signed_at - Duration::seconds(30);
        let mut claims = serde_json::json!({
            "sub": subject,
            "iss": issuer,
            "aud": audience,
            "iat": iat.unix_timestamp(),
            "auth_time": (iat - Duration::seconds(10)).unix_timestamp(),
            "exp": (iat + Duration::hours(24)).unix_timestamp(),
            "nonce": nonce,
            "username": subject,
        });
        if let Some(obj) = extra_claims.as_object() {
            for (k, v) in obj {
                if v.is_null() {
                    claims.as_object_mut().unwrap().remove(k);
                } else {
                    claims[k] = v.clone();
                }
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

    // --- Request builders ---

    const ISSUER: &str = "https://issuer.example";
    const CLIENT: &str = "remonce";
    const ALICE: usize = 0;
    const BOB: usize = 1;
    const CAROL: usize = 2;
    const PEOPLE: [&str; 3] = ["alice", "bob", "carol"];

    struct Env {
        tsa_keys: TsaKeys,
        /// The IdP's token-signing key.
        idp: TestKeys,
        jwks: JwkSet,
    }

    fn new_env() -> Env {
        let idp = setup_keys("idp-kid");
        let jwks = JwkSet {
            keys: vec![keys_to_jwk(&idp)],
        };
        Env {
            tsa_keys: generate_tsa_keys(),
            idp,
            jwks,
        }
    }

    fn cmd() -> serde_json::Value {
        json!({
            "command": "ping-test",
            "id": "1b4e28ba-2fa1-11d2-883f-0016d3cca427",
            "params": { "count": "4" },
        })
    }

    /// One signature as a fresh per-signature login makes it: a new
    /// ephemeral key, a token from `who`'s login bound to that key, and a
    /// TSA timestamp at `signed_at`.
    fn sign(
        env: &Env,
        who: usize,
        payload: impl Fn(&str) -> Vec<u8>,
        signed_at: OffsetDateTime,
        claims: serde_json::Value,
    ) -> Approval {
        let ephemeral = setup_keys("ephemeral");
        let sig = sign_low_s(&ephemeral.signing_key, &payload(&ephemeral.public_key_pem));
        let sig_bytes = sig.to_bytes();
        let id_token = create_valid_jwt(
            &env.idp,
            ISSUER,
            CLIENT,
            PEOPLE[who],
            &key_binding(&ephemeral.public_key_pem),
            signed_at,
            claims,
        );
        Approval {
            signature: hex::encode(sig_bytes),
            timestamp_token: retimestamp(env, &sig_bytes, &id_token, signed_at),
            id_token,
            public_key: ephemeral.public_key_pem,
        }
    }

    fn approve_with(
        env: &Env,
        who: usize,
        command: &serde_json::Value,
        signed_at: OffsetDateTime,
        claims: serde_json::Value,
    ) -> Approval {
        let payload = canonical_request_payload(command);
        sign(env, who, |_| payload.as_bytes().to_vec(), signed_at, claims)
    }

    fn approve(env: &Env, who: usize, command: &serde_json::Value, signed_at: OffsetDateTime) -> Approval {
        approve_with(env, who, command, signed_at, json!({ "groups": ["webapp-users"] }))
    }

    /// An approval whose login (`iat`) was `age` ago, signed right after it.
    fn approve_aged(env: &Env, who: usize, command: &serde_json::Value, age: Duration) -> Approval {
        let iat = OffsetDateTime::now_utc() - age;
        approve_with(
            env,
            who,
            command,
            iat + Duration::seconds(30),
            json!({
                "iat": iat.unix_timestamp(),
                "auth_time": (iat - Duration::seconds(10)).unix_timestamp(),
            }),
        )
    }

    fn revoke_sig(env: &Env, who: usize, request_id: &str, signed_at: OffsetDateTime) -> Approval {
        let id = request_id.to_string();
        sign(env, who, |pem| revocation_payload(&id, pem), signed_at, json!({}))
    }

    fn bundle(approvals: Vec<Approval>) -> RequestBundle {
        RequestBundle {
            command: cmd(),
            approvals,
        }
    }

    fn verifier_config(env: &Env) -> VerifierConfig {
        VerifierConfig {
            client_id: CLIENT.into(),
            issuer_url: ISSUER.into(),
            jwks: env.jwks.clone(),
            trusted_roots: vec![env.tsa_keys.cert_der.clone()],
            approval_validity: StdDuration::from_secs(60 * 60),
        }
    }

    fn verify(env: &Env, b: &RequestBundle) -> Result<VerifiedRequest, ValidationError> {
        verify_request(b, &verifier_config(env), OffsetDateTime::now_utc())
    }

    /// Verify a request whose single approval carries `claims`.
    fn verify_with_claims(env: &Env, claims: serde_json::Value) -> Result<(), ValidationError> {
        let a = approve_with(env, ALICE, &cmd(), OffsetDateTime::now_utc(), claims);
        verify(env, &bundle(vec![a])).map(|_| ())
    }

    // --- Payload ---

    #[test]
    fn request_payload_golden_vector() {
        // Pins the signed bytes: changing them silently invalidates every
        // approval in flight, and other implementations must match.
        let command = json!({ "params": { "b": 1, "a": 2 }, "id": "x", "command": "ping" });
        assert_eq!(
            canonical_request_payload(&command),
            r#"{"command":{"command":"ping","id":"x","params":{"a":2,"b":1}},"remonce":"request/v2"}"#
        );
        assert_eq!(
            request_id(&command),
            "f937cde02e56dd3d657c74622e952af015d382912387e63d1cbbfd1b86036f73"
        );
    }

    // --- Approvals ---

    #[test]
    fn single_approval_verifies() {
        let env = new_env();
        let now = OffsetDateTime::now_utc();
        let v = verify(&env, &bundle(vec![approve(&env, ALICE, &cmd(), now)])).expect("should verify");
        assert_eq!(v.request_id, request_id(&cmd()));
        assert_eq!(v.approvers.len(), 1);
        assert_eq!(v.approvers[0].username, "alice");
        assert_eq!(v.approvers[0].claims["groups"], json!(["webapp-users"]));
    }

    #[test]
    fn approvals_verify_in_any_order() {
        let env = new_env();
        let now = OffsetDateTime::now_utc();
        let a = approve(&env, ALICE, &cmd(), now - Duration::minutes(20));
        let b = approve(&env, BOB, &cmd(), now);
        let ab = verify(&env, &bundle(vec![a.clone(), b.clone()])).expect("a, b");
        let ba = verify(&env, &bundle(vec![b, a])).expect("b, a");
        assert_eq!(ab.request_id, ba.request_id);
        let names = |v: &VerifiedRequest| v.approvers.iter().map(|a| a.username.clone()).collect::<Vec<_>>();
        assert_eq!(names(&ab), ["alice", "bob"]);
        assert_eq!(names(&ba), ["bob", "alice"]);
    }

    #[test]
    fn same_person_twice_rejected() {
        // Two separate logins by one person are still one approver.
        let env = new_env();
        let now = OffsetDateTime::now_utc();
        let result = verify(
            &env,
            &bundle(vec![
                approve(&env, ALICE, &cmd(), now - Duration::minutes(1)),
                approve(&env, BOB, &cmd(), now),
                approve(&env, ALICE, &cmd(), now),
            ]),
        );
        assert!(
            matches!(&result, Err(ValidationError::DuplicateApprover { username }) if username == "alice"),
            "expected DuplicateApprover, got {result:?}"
        );
    }

    #[test]
    fn no_approvals_rejected() {
        let env = new_env();
        assert!(matches!(verify(&env, &bundle(vec![])), Err(ValidationError::NoApprovals)));
    }

    #[test]
    fn too_many_approvals_rejected_before_verifying() {
        let env = new_env();
        let a = approve(&env, ALICE, &cmd(), OffsetDateTime::now_utc());
        let result = verify(&env, &bundle(vec![a; MAX_APPROVALS + 1]));
        assert!(
            matches!(result, Err(ValidationError::TooManyApprovals { .. })),
            "expected TooManyApprovals, got {result:?}"
        );
    }

    #[test]
    fn transplanted_approval_rejected() {
        // An approval of one request is useless on any other: different
        // params, or the same command with a different id.
        let env = new_env();
        let now = OffsetDateTime::now_utc();
        let mut other_params = cmd();
        other_params["params"]["count"] = json!("1000");
        let mut other_id = cmd();
        other_id["id"] = json!("9a8b7c6d-0000-4000-8000-000000000000");
        for other in [other_params, other_id] {
            let result = verify(
                &env,
                &bundle(vec![approve(&env, ALICE, &cmd(), now), approve(&env, BOB, &other, now)]),
            );
            assert!(
                matches!(
                    &result,
                    Err(ValidationError::InApproval { index: 1, source })
                        if matches!(**source, ValidationError::ApprovalSignatureFailed)
                ),
                "expected approval #1 signature failure, got {result:?}"
            );
        }
    }

    #[test]
    fn approval_within_validity_accepted() {
        let env = new_env();
        let a = approve_aged(&env, ALICE, &cmd(), Duration::minutes(50));
        assert!(verify(&env, &bundle(vec![a])).is_ok());
    }

    #[test]
    fn expired_approval_rejected_with_its_index() {
        let env = new_env();
        let now = OffsetDateTime::now_utc();
        let result = verify(
            &env,
            &bundle(vec![
                approve(&env, ALICE, &cmd(), now),
                approve_aged(&env, BOB, &cmd(), Duration::minutes(61)),
            ]),
        );
        assert!(
            matches!(&result, Err(ValidationError::ApprovalStale { index: 1, username, .. }) if username == "bob"),
            "expected ApprovalStale for #1, got {result:?}"
        );
    }

    #[test]
    fn per_signature_checks_apply_at_every_index() {
        // A bad second approval is caught just like a bad first one.
        let env = new_env();
        let now = OffsetDateTime::now_utc();
        let good = approve(&env, ALICE, &cmd(), now);
        let mut high_s = approve(&env, BOB, &cmd(), now);
        let (mauled_hex, mauled_bytes) = maul(&high_s.signature);
        high_s.timestamp_token = retimestamp(&env, &mauled_bytes, &high_s.id_token, now);
        high_s.signature = mauled_hex;
        let result = verify(&env, &bundle(vec![good.clone(), high_s]));
        assert!(matches!(&result, Err(ValidationError::InApproval { index: 1, .. })), "{result:?}");
        assert_high_s_rejected(result.map_err(|e| match e {
            ValidationError::InApproval { source, .. } => *source,
            other => other,
        }));

        let mut upper = approve(&env, CAROL, &cmd(), now);
        upper.signature = upper.signature.to_uppercase();
        let result = verify(&env, &bundle(vec![good, upper]));
        assert!(
            matches!(
                &result,
                Err(ValidationError::InApproval { index: 1, source })
                    if matches!(**source, ValidationError::InvalidSignatureFormat(_))
            ),
            "expected uppercase rejection at #1, got {result:?}"
        );
    }

    #[test]
    fn approval_needs_a_subject() {
        let env = new_env();
        let result = verify_with_claims(&env, json!({ "sub": null }));
        assert!(
            matches!(result.as_ref().map_err(|e| e.root()), Err(ValidationError::MissingClaim("sub"))),
            "expected MissingClaim(sub), got {result:?}"
        );
    }

    #[test]
    fn far_future_timestamp_rejected() {
        let env = new_env();
        let a = approve(&env, ALICE, &cmd(), OffsetDateTime::now_utc() + Duration::hours(1));
        let result = verify(&env, &bundle(vec![a]));
        assert!(
            matches!(result.as_ref().map_err(|e| e.root()), Err(ValidationError::TimestampInFuture { .. })),
            "expected TimestampInFuture, got {result:?}"
        );
    }

    #[test]
    fn revocation_signature_is_not_an_approval() {
        // Domain separation: a revoker's signature over the same request
        // can never count as an approval of it.
        let env = new_env();
        let now = OffsetDateTime::now_utc();
        let rev = revoke_sig(&env, ALICE, &request_id(&cmd()), now);
        let result = verify(&env, &bundle(vec![rev]));
        assert!(
            matches!(result.as_ref().map_err(|e| e.root()), Err(ValidationError::ApprovalSignatureFailed)),
            "expected ApprovalSignatureFailed, got {result:?}"
        );
    }

    // --- Signature malleability (s -> n - s) ---

    /// The high-S twin of a valid low-S signature: equally valid under plain
    /// ECDSA, different bytes.
    fn maul(sig_hex: &str) -> (String, Vec<u8>) {
        use p256::elliptic_curve::ff::PrimeField;
        let sig = Signature::from_slice(&hex::decode(sig_hex).unwrap()).unwrap();
        let (r, s) = sig.split_scalars();
        let neg_s = -(*s.as_ref());
        let mauled = Signature::from_scalars(r.as_ref().to_repr(), neg_s.to_repr()).unwrap();
        let bytes = mauled.to_bytes().to_vec();
        (hex::encode(&bytes), bytes)
    }

    /// A fresh TSA timestamp over (sig_bytes || id_token), as any holder of
    /// a bundle can obtain.
    fn retimestamp(env: &Env, sig_bytes: &[u8], id_token: &str, at: OffsetDateTime) -> String {
        let mut data = sig_bytes.to_vec();
        data.extend_from_slice(id_token.as_bytes());
        create_mock_timestamp(&data, at, &env.tsa_keys)
    }

    fn assert_high_s_rejected(result: Result<impl std::fmt::Debug, ValidationError>) {
        match result {
            Err(ValidationError::InvalidSignatureFormat(msg)) => {
                assert!(msg.contains("high-S"), "unexpected message: {msg}")
            }
            other => panic!("expected high-S rejection, got {other:?}"),
        }
    }

    #[test]
    fn sign_low_s_always_low() {
        let key = SigningKey::random(&mut OsRng);
        for i in 0..64u32 {
            let sig = sign_low_s(&key, &i.to_be_bytes());
            assert!(sig.normalize_s().is_none(), "signature {i} is high-S");
        }
    }

    // --- Re-timestamping and IdP-attested times ---

    #[test]
    fn retimestamp_after_sign_delay_rejected() {
        // A holder re-timestamps an 8-minute-old signature: the TSA time
        // looks fresh, but it is too far from the token's `iat`.
        let env = new_env();
        let now = OffsetDateTime::now_utc();
        let iat = now - Duration::minutes(8);
        let a = approve_with(
            &env,
            ALICE,
            &cmd(),
            now,
            json!({
                "iat": iat.unix_timestamp(),
                "auth_time": (iat - Duration::seconds(10)).unix_timestamp(),
            }),
        );
        let result = verify(&env, &bundle(vec![a]));
        assert!(
            matches!(result.as_ref().map_err(|e| e.root()), Err(ValidationError::SignedTooLongAfterIssue { .. })),
            "expected SignedTooLongAfterIssue, got {result:?}"
        );
    }

    #[test]
    fn timestamp_before_iat_rejected() {
        let env = new_env();
        let now = OffsetDateTime::now_utc();
        let a = approve_with(
            &env,
            ALICE,
            &cmd(),
            now - Duration::minutes(10),
            json!({
                "iat": now.unix_timestamp(),
                "auth_time": (now - Duration::seconds(10)).unix_timestamp(),
            }),
        );
        let result = verify(&env, &bundle(vec![a]));
        assert!(
            matches!(result.as_ref().map_err(|e| e.root()), Err(ValidationError::TimestampBeforeIssue)),
            "expected TimestampBeforeIssue, got {result:?}"
        );
    }

    #[test]
    fn stale_by_iat_despite_fresh_timestamp() {
        // TSA time 57m ago is inside the 1h window, but the login (`iat`)
        // was 61m ago — validity is measured from the login.
        let env = new_env();
        let now = OffsetDateTime::now_utc();
        let iat = now - Duration::minutes(61);
        let a = approve_with(
            &env,
            ALICE,
            &cmd(),
            now - Duration::minutes(57),
            json!({
                "iat": iat.unix_timestamp(),
                "auth_time": (iat - Duration::seconds(10)).unix_timestamp(),
            }),
        );
        let result = verify(&env, &bundle(vec![a]));
        assert!(
            matches!(result, Err(ValidationError::ApprovalStale { index: 0, .. })),
            "expected ApprovalStale, got {result:?}"
        );
    }

    #[test]
    fn missing_iat_rejected() {
        let env = new_env();
        let result = verify_with_claims(&env, json!({ "iat": null }));
        assert!(
            matches!(result.as_ref().map_err(|e| e.root()), Err(ValidationError::MissingClaim("iat"))),
            "expected MissingClaim(iat), got {result:?}"
        );
    }

    #[test]
    fn missing_auth_time_rejected() {
        let env = new_env();
        let result = verify_with_claims(&env, json!({ "auth_time": null }));
        assert!(
            matches!(result.as_ref().map_err(|e| e.root()), Err(ValidationError::MissingClaim("auth_time"))),
            "expected MissingClaim(auth_time), got {result:?}"
        );
    }

    #[test]
    fn stale_auth_time_rejected() {
        // A silent SSO refresh of a 10-minute-old session is not a
        // re-authentication.
        let env = new_env();
        let iat = OffsetDateTime::now_utc() - Duration::seconds(30);
        let result = verify_with_claims(
            &env,
            json!({ "auth_time": (iat - Duration::minutes(10)).unix_timestamp() }),
        );
        assert!(
            matches!(result.as_ref().map_err(|e| e.root()), Err(ValidationError::AuthenticationTooOld { .. })),
            "expected AuthenticationTooOld, got {result:?}"
        );
    }

    #[test]
    fn auth_time_after_iat_rejected() {
        let env = new_env();
        let iat = OffsetDateTime::now_utc() - Duration::seconds(30);
        let result = verify_with_claims(
            &env,
            json!({ "auth_time": (iat + Duration::minutes(5)).unix_timestamp() }),
        );
        assert!(
            matches!(result.as_ref().map_err(|e| e.root()), Err(ValidationError::AuthTimeAfterIssue)),
            "expected AuthTimeAfterIssue, got {result:?}"
        );
    }

    #[test]
    fn token_nonce_must_bind_the_signing_key() {
        // Someone else's token stapled to my signature fails.
        let env = new_env();
        let now = OffsetDateTime::now_utc();
        let mut mine = approve(&env, ALICE, &cmd(), now);
        let theirs = approve(&env, BOB, &cmd(), now);
        mine.id_token = theirs.id_token;
        let sig = hex::decode(&mine.signature).unwrap();
        mine.timestamp_token = retimestamp(&env, &sig, &mine.id_token, now);
        let result = verify(&env, &bundle(vec![mine]));
        assert!(
            matches!(result.as_ref().map_err(|e| e.root()), Err(ValidationError::JwtNonceMismatch)),
            "expected JwtNonceMismatch, got {result:?}"
        );
    }

    // --- Audience separation (signing vs viewer client) ---

    #[test]
    fn viewer_aud_rejected_for_signing() {
        let env = new_env();
        let result = verify_with_claims(&env, json!({ "aud": "remonce-viewer" }));
        assert!(
            matches!(
                result.as_ref().map_err(|e| e.root()),
                Err(ValidationError::JwtValidationFailed(_) | ValidationError::AudienceMismatch(_))
            ),
            "expected audience rejection, got {result:?}"
        );
    }

    #[test]
    fn multi_aud_array_rejected() {
        // jsonwebtoken alone accepts any overlap; the strict rule must not.
        let env = new_env();
        let result = verify_with_claims(&env, json!({ "aud": ["remonce", "remonce-viewer"] }));
        assert!(
            matches!(result.as_ref().map_err(|e| e.root()), Err(ValidationError::AudienceMismatch(_))),
            "expected AudienceMismatch, got {result:?}"
        );
    }

    #[test]
    fn azp_mismatch_rejected() {
        let env = new_env();
        let result = verify_with_claims(&env, json!({ "azp": "remonce-viewer" }));
        assert!(
            matches!(result.as_ref().map_err(|e| e.root()), Err(ValidationError::AudienceMismatch(_))),
            "expected AudienceMismatch, got {result:?}"
        );
    }

    #[test]
    fn single_element_aud_array_accepted() {
        let env = new_env();
        let result = verify_with_claims(&env, json!({ "aud": ["remonce"], "azp": "remonce" }));
        assert!(result.is_ok(), "expected ok, got {result:?}");
    }

    fn bearer(env: &Env, aud: serde_json::Value) -> String {
        create_valid_jwt(
            &env.idp,
            ISSUER,
            "unused",
            "bob",
            "random-nonce",
            OffsetDateTime::now_utc(),
            json!({ "aud": aud }),
        )
    }

    #[test]
    fn verify_bearer_token_accepts_viewer() {
        let env = new_env();
        let token = bearer(&env, json!("remonce-viewer"));
        let claims = verify_bearer_token(&token, &env.jwks, ISSUER, "remonce-viewer")
            .expect("viewer token should verify");
        assert_eq!(claims["sub"], "bob");
    }

    #[test]
    fn verify_bearer_token_rejects_signing_aud() {
        // An approval's token carried in a request must not work as the
        // executor's credential or a file/log viewing credential.
        let env = new_env();
        let token = bearer(&env, json!("remonce"));
        assert!(verify_bearer_token(&token, &env.jwks, ISSUER, "remonce-viewer").is_err());
    }

    #[test]
    fn verify_bearer_token_rejects_multi_aud() {
        let env = new_env();
        let token = bearer(&env, json!(["remonce-viewer", "remonce"]));
        assert!(verify_bearer_token(&token, &env.jwks, ISSUER, "remonce-viewer").is_err());
    }

    #[test]
    fn verify_bearer_token_rejects_expired() {
        let env = new_env();
        let expired = OffsetDateTime::now_utc() - Duration::hours(1);
        let token = create_valid_jwt(
            &env.idp,
            ISSUER,
            "remonce-viewer",
            "bob",
            "random-nonce",
            OffsetDateTime::now_utc(),
            json!({ "exp": expired.unix_timestamp() }),
        );
        assert!(verify_bearer_token(&token, &env.jwks, ISSUER, "remonce-viewer").is_err());
    }

    // --- Revocation ---

    fn revocation(request: RequestBundle, revoker: Approval) -> RevocationBundle {
        RevocationBundle { request, revoker }
    }

    fn verify_rev(env: &Env, r: &RevocationBundle) -> Result<AuthorizedRevocation, ValidationError> {
        verify_revocation(r, &verifier_config(env), OffsetDateTime::now_utc())
    }

    #[test]
    fn approver_revoking_is_self_revocation() {
        let env = new_env();
        let now = OffsetDateTime::now_utc();
        let req = bundle(vec![approve(&env, ALICE, &cmd(), now), approve(&env, BOB, &cmd(), now)]);
        let rid = request_id(&cmd());
        let r = verify_rev(&env, &revocation(req, revoke_sig(&env, BOB, &rid, now))).expect("should verify");
        assert!(r.self_revoked);
        assert_eq!(r.request_id, rid);
        assert_eq!(r.revoker.username, "bob");
        assert_eq!(r.approvers.len(), 2);
    }

    #[test]
    fn non_approver_revoking_is_third_party() {
        let env = new_env();
        let now = OffsetDateTime::now_utc();
        let req = bundle(vec![approve(&env, ALICE, &cmd(), now)]);
        let rid = request_id(&cmd());
        let r = verify_rev(&env, &revocation(req, revoke_sig(&env, CAROL, &rid, now))).expect("should verify");
        assert!(!r.self_revoked);
    }

    #[test]
    fn expired_approvals_can_still_be_revoked() {
        let env = new_env();
        let now = OffsetDateTime::now_utc();
        let req = bundle(vec![approve_aged(&env, ALICE, &cmd(), Duration::days(2))]);
        let rid = request_id(&cmd());
        assert!(verify_rev(&env, &revocation(req, revoke_sig(&env, ALICE, &rid, now))).is_ok());
    }

    #[test]
    fn stale_revoker_rejected() {
        let env = new_env();
        let now = OffsetDateTime::now_utc();
        let req = bundle(vec![approve(&env, ALICE, &cmd(), now)]);
        let rid = request_id(&cmd());
        let rev = revoke_sig(&env, ALICE, &rid, now - Duration::minutes(11));
        let result = verify_rev(&env, &revocation(req, rev));
        assert!(
            matches!(result, Err(ValidationError::RevokerStale { .. })),
            "expected RevokerStale, got {result:?}"
        );
    }

    #[test]
    fn revocation_needs_a_genuine_approval() {
        // Nobody can fill the revocation list with invented requests.
        let env = new_env();
        let now = OffsetDateTime::now_utc();
        let mut other = cmd();
        other["params"]["count"] = json!("1");
        let req = RequestBundle {
            command: other.clone(),
            approvals: vec![approve(&env, ALICE, &cmd(), now)],
        };
        let rev = revoke_sig(&env, ALICE, &request_id(&other), now);
        let result = verify_rev(&env, &revocation(req, rev));
        assert!(
            matches!(result.as_ref().map_err(|e| e.root()), Err(ValidationError::ApprovalSignatureFailed)),
            "expected ApprovalSignatureFailed, got {result:?}"
        );
        let unapproved = revoke_sig(&env, ALICE, &request_id(&cmd()), now);
        assert!(matches!(
            verify_rev(&env, &revocation(bundle(vec![]), unapproved)),
            Err(ValidationError::NoApprovals)
        ));
    }

    #[test]
    fn revocation_names_one_request() {
        // A revocation signed for request A can't be attached to request B.
        let env = new_env();
        let now = OffsetDateTime::now_utc();
        let mut other = cmd();
        other["id"] = json!("9a8b7c6d-0000-4000-8000-000000000000");
        let req = bundle(vec![approve(&env, ALICE, &cmd(), now)]);
        let rev = revoke_sig(&env, ALICE, &request_id(&other), now);
        let result = verify_rev(&env, &revocation(req, rev));
        assert!(
            matches!(result, Err(ValidationError::RevokerSignatureFailed)),
            "expected RevokerSignatureFailed, got {result:?}"
        );
    }

    #[test]
    fn approval_is_not_a_revocation() {
        // Domain separation the other way: an approval can't cancel.
        let env = new_env();
        let now = OffsetDateTime::now_utc();
        let a = approve(&env, ALICE, &cmd(), now);
        let result = verify_rev(&env, &revocation(bundle(vec![a.clone()]), a));
        assert!(
            matches!(result, Err(ValidationError::RevokerSignatureFailed)),
            "expected RevokerSignatureFailed, got {result:?}"
        );
    }

    #[test]
    fn high_s_revoker_signature_rejected() {
        let env = new_env();
        let now = OffsetDateTime::now_utc();
        let req = bundle(vec![approve(&env, ALICE, &cmd(), now)]);
        let mut rev = revoke_sig(&env, ALICE, &request_id(&cmd()), now);
        let (mauled_hex, mauled_bytes) = maul(&rev.signature);
        rev.timestamp_token = retimestamp(&env, &mauled_bytes, &rev.id_token, now);
        rev.signature = mauled_hex;
        assert_high_s_rejected(verify_rev(&env, &revocation(req, rev)));
    }

    // --- Retention ---

    #[test]
    fn long_lived_token_does_not_extend_usable_until() {
        // The test tokens live 24h; usability is bounded from `iat`.
        let env = new_env();
        let a = approve(&env, ALICE, &cmd(), OffsetDateTime::now_utc());
        let v = verify(&env, &bundle(vec![a])).expect("should verify");
        let id = &v.approvers[0];
        assert_eq!(id.token_exp - id.issued_at, Duration::hours(24));
        let window = StdDuration::from_secs(60 * 60);
        assert_eq!(id.usable_until(window), id.issued_at + window + CACHE_SLACK);
    }

    #[test]
    fn replay_ttl_outlives_every_possible_approval() {
        let env = new_env();
        let now = OffsetDateTime::now_utc();
        let validity = StdDuration::from_secs(60 * 60);
        let v = verify(
            &env,
            &bundle(vec![
                approve_aged(&env, ALICE, &cmd(), Duration::minutes(40)),
                approve(&env, BOB, &cmd(), now),
            ]),
        )
        .unwrap();
        let ttl = replay_ttl(now, &v.approvers, validity);
        let lapses = now + ttl;
        for a in &v.approvers {
            assert!(lapses >= a.usable_until(validity));
        }
        // Also covers an approval not in the bundle whose login is as late
        // as clock skew allows.
        assert!(lapses >= now + MAX_FUTURE_SKEW + validity);
    }

    #[test]
    fn revocation_kept_past_every_approval() {
        let env = new_env();
        let now = OffsetDateTime::now_utc();
        let validity = StdDuration::from_secs(60 * 60);
        let v = verify(&env, &bundle(vec![approve(&env, ALICE, &cmd(), now)])).unwrap();
        let keep = revocation_keep_until(now, &v.approvers, validity, StdDuration::ZERO);
        assert!(keep >= v.approvers[0].usable_until(validity));
        assert!(keep >= now + validity);
        // Retention longer than validity (the central service's setting)
        // wins.
        let week = StdDuration::from_secs(7 * 24 * 60 * 60);
        assert!(revocation_keep_until(now, &v.approvers, validity, week) >= now + week);
    }

    #[test]
    fn approver_key_binding_matches_token_nonce() {
        let env = new_env();
        let a = approve(&env, ALICE, &cmd(), OffsetDateTime::now_utc());
        let expected = key_binding(&a.public_key);
        let v = verify(&env, &bundle(vec![a])).unwrap();
        assert_eq!(v.approvers[0].key_binding, expected);
        assert_eq!(v.approvers[0].claims["nonce"], expected);
    }
}
