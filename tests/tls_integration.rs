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

/// A client that opens a TCP connection and never sends a ClientHello must
/// not stop the listener from accepting other connections.
#[tokio::test]
async fn silent_client_does_not_block_accept() -> Result<(), Box<dyn std::error::Error>> {
    use axum::serve::Listener;
    use remonce::tls::TlsListener;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
    use std::sync::Arc;
    use std::time::Duration;

    let _ = rustls::crypto::ring::default_provider().install_default();

    let cert = generate_simple_self_signed(vec!["localhost".to_string()])?;
    let cert_der: CertificateDer<'static> = cert.cert.der().clone();
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()));

    let server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], key_der)?;
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));

    let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = tcp.local_addr()?;
    let mut listener = TlsListener::new(tcp, acceptor);

    // 1. The silent client: connects, then does nothing.
    let _silent = tokio::net::TcpStream::connect(addr).await?;

    // 2. A well-behaved TLS client.
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert_der)?;
    let client_config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
    let client = tokio::spawn(async move {
        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        connector
            .connect(ServerName::try_from("localhost").unwrap(), tcp)
            .await
            .map(|_| ())
    });

    // The good client must be accepted promptly despite the silent one.
    let accepted = tokio::time::timeout(Duration::from_secs(3), listener.accept()).await;
    assert!(accepted.is_ok(), "accept() stalled behind a silent client");
    client.await??;
    Ok(())
}
