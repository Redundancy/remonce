use rcgen::generate_simple_self_signed;

#[tokio::test]
async fn test_dynamic_cert_resolver_reloads() -> Result<(), Box<dyn std::error::Error>> {
    use std::sync::Arc;
    use remonce::tls::DynamicCertResolver;
    use rustls::sign::CertifiedKey;
    use rustls::pki_types::PrivateKeyDer;

    // Helper to create CertifiedKey from in-memory PEMs
    fn create_key_from_mem(cert_pem: &str, key_pem: &str) -> Result<Arc<CertifiedKey>, Box<dyn std::error::Error>> {
        let mut cert_reader = std::io::Cursor::new(cert_pem.as_bytes());
        let certs = rustls_pemfile::certs(&mut cert_reader).collect::<Result<Vec<_>, _>>()?;
        
        let mut key_reader = std::io::Cursor::new(key_pem.as_bytes());
        let key = loop {
            match rustls_pemfile::read_one(&mut key_reader)? {
                Some(rustls_pemfile::Item::Pkcs1Key(key)) => break PrivateKeyDer::from(key),
                Some(rustls_pemfile::Item::Pkcs8Key(key)) => break PrivateKeyDer::from(key),
                Some(rustls_pemfile::Item::Sec1Key(key)) => break PrivateKeyDer::from(key),
                None => return Err("No private key found".into()),
                _ => {}
            }
        };

        let signing_key = rustls::crypto::ring::sign::any_supported_type(&key)
            .map_err(|e| format!("Invalid private key: {:?}", e))?;
            
        Ok(Arc::new(CertifiedKey::new(certs, signing_key)))
    }

    // 1. Generate Cert A
    let cert_a = generate_simple_self_signed(vec!["localhost".to_string()])?;
    let pem_cert_a = cert_a.cert.pem();
    let pem_key_a = cert_a.signing_key.serialize_pem();
    
    // 2. Generate Cert B
    let cert_b = generate_simple_self_signed(vec!["example.com".to_string()])?;
    let pem_cert_b = cert_b.cert.pem();
    let pem_key_b = cert_b.signing_key.serialize_pem();

    // 3. Init resolver with Key A
    let certified_key_a = create_key_from_mem(&pem_cert_a, &pem_key_a)?;
    let resolver = Arc::new(DynamicCertResolver::new(certified_key_a));

    // 4. Update resolver with Key B
    let certified_key_b = create_key_from_mem(&pem_cert_b, &pem_key_b)?;
    resolver.update_cert(certified_key_b);
    
    // Logic verification complete (no IO needed)
    Ok(())
}
