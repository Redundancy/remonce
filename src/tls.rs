use crate::config::TlsConfig;
use axum::Router;
use notify::{Config, Event, RecommendedWatcher, RecursiveMode, Watcher};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use std::path::Path;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::sync::watch;

/// A `ResolvesServerCert` implementation that allows hot-reloading the certificate.
#[derive(Debug)]
pub struct DynamicCertResolver {
    cert_key: Arc<RwLock<Arc<CertifiedKey>>>,
}

impl DynamicCertResolver {
    pub fn new(cert_key: Arc<CertifiedKey>) -> Self {
        Self {
            cert_key: Arc::new(RwLock::new(cert_key)),
        }
    }

    pub fn update_cert(&self, new_key: Arc<CertifiedKey>) {
        if let Ok(mut guard) = self.cert_key.write() {
            *guard = new_key;
            tracing::info!("TLS certificate reloaded successfully.");
        } else {
            tracing::error!("Failed to acquire write lock for certificate update");
        }
    }
}

impl ResolvesServerCert for DynamicCertResolver {
    fn resolve(&self, _client_hello: ClientHello) -> Option<Arc<CertifiedKey>> {
        self.cert_key.read().ok().map(|guard| guard.clone())
    }
}

pub fn load_certs(path: &str) -> std::io::Result<Vec<CertificateDer<'static>>> {
    let file = std::fs::File::open(path)?;
    let mut reader = std::io::BufReader::new(file);
    rustls_pemfile::certs(&mut reader).collect()
}

pub fn load_private_key(path: &str) -> std::io::Result<PrivateKeyDer<'static>> {
    let file = std::fs::File::open(path)?;
    let mut reader = std::io::BufReader::new(file);
    
    // Try to read the first item
    loop {
        match rustls_pemfile::read_one(&mut reader)? {
            Some(rustls_pemfile::Item::Pkcs1Key(key)) => return Ok(key.into()),
            Some(rustls_pemfile::Item::Pkcs8Key(key)) => return Ok(key.into()),
            Some(rustls_pemfile::Item::Sec1Key(key)) => return Ok(key.into()),
            None => break,
            _ => {} // Ignore certs/exposed keys mixed in if any
        }
    }

    Err(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "No private key found in file",
    ))
}

pub fn create_certified_key(cert_path: &str, key_path: &str) -> std::io::Result<Arc<CertifiedKey>> {
    let certs = load_certs(cert_path)?;
    if certs.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("No certificates found in {}", cert_path),
        ));
    }
    let key = load_private_key(key_path)?;
    
    let signing_key = rustls::crypto::ring::sign::any_supported_type(&key)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("Invalid private key: {:?}", e)))?;
        
    Ok(Arc::new(CertifiedKey::new(certs, signing_key)))
}

/// Spawns a dedicated task to watch for file changes and reload the certificate.
pub fn start_cert_watcher(
    cert_path: String,
    key_path: String,
    resolver: Arc<DynamicCertResolver>,
) {
    tokio::spawn(async move {
        tracing::info!("Starting certificate watcher for {} and {}", cert_path, key_path);
        
        let (tx, mut rx) = watch::channel(());
        let tx = Arc::new(tx);
        
        // Setup Notify Watcher
        let watcher_tx = tx.clone();
        let mut watcher = match RecommendedWatcher::new(
            move |res: Result<Event, notify::Error>| {
                match res {
                    Ok(event) => {
                         if event.kind.is_modify() {
                             // Notify the async loop
                             let _ = watcher_tx.send(());
                         }
                    }
                    Err(e) => tracing::error!("Watch error: {:?}", e),
                }
            },
            Config::default(),
        ) {
            Ok(w) => w,
            Err(e) => {
                tracing::error!("Failed to create file watcher: {e}");
                return;
            }
        };

        if let Err(e) = watcher.watch(Path::new(&cert_path), RecursiveMode::NonRecursive) {
             tracing::error!("Failed to watch cert path: {e}");
        }
        if let Err(e) = watcher.watch(Path::new(&key_path), RecursiveMode::NonRecursive) {
             tracing::error!("Failed to watch key path: {e}");
        }

        // Debounce loop
        let mut change_detected = false;
        loop {
            // Wait for a change notification or timeout if we have a pending change
            let timeout_future = if change_detected {
                // If change detected, wait a bit to debounce
                Some(tokio::time::sleep(Duration::from_millis(500)))
            } else {
                None
            };
            
            tokio::select! {
                _ = rx.changed() => {
                    change_detected = true;
                    // Consume the change
                    rx.mark_unchanged();
                }
                _ = async { if let Some(f) = timeout_future { f.await } else { std::future::pending().await } } => {
                     // Debounce timeout expired, reload certs
                     change_detected = false;
                     tracing::info!("Reloading certificates...");
                     match create_certified_key(&cert_path, &key_path) {
                         Ok(key) => resolver.update_cert(key),
                         Err(e) => tracing::error!("Failed to reload certificate: {e}"),
                     }
                }
            }
        }
    });
}

use axum::serve::Listener;
use tokio::net::{TcpListener, TcpStream};
use std::future::Future;
use std::net::SocketAddr;
use std::io;

pub trait AcceptTls: Clone + Send + Sync + 'static {
    type Stream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static;
    type Future: Future<Output = io::Result<Self::Stream>> + Send;
    
    fn accept_tls(&self, tcp: TcpStream) -> Self::Future;
}

impl AcceptTls for tokio_rustls::TlsAcceptor {
    type Stream = tokio_rustls::server::TlsStream<TcpStream>;
    type Future = tokio_rustls::Accept<TcpStream>;
    
    fn accept_tls(&self, tcp: TcpStream) -> Self::Future {
        self.accept(tcp)
    }
}

/// Upper bound on a single TLS handshake. A client that connects and then
/// stalls is dropped after this.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Maximum number of handshakes in flight at once. Connections beyond this
/// are dropped immediately rather than queued, so a flood of idle sockets
/// cannot pile up unbounded tasks.
const MAX_CONCURRENT_HANDSHAKES: usize = 512;

/// A TLS listener for `axum::serve`. Handshakes run concurrently in their
/// own tasks (with a timeout), never inline in `accept()` — otherwise one
/// client that opens a TCP connection and sends nothing would block every
/// later connection.
pub struct TlsListener<A: AcceptTls> {
    ready: tokio::sync::mpsc::Receiver<(A::Stream, SocketAddr)>,
    local_addr: Result<SocketAddr, String>,
}

impl<A: AcceptTls> TlsListener<A> {
    pub fn new(listener: TcpListener, acceptor: A) -> Self {
        let local_addr = listener.local_addr().map_err(|e| e.to_string());
        let (tx, ready) = tokio::sync::mpsc::channel(64);
        let permits = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_HANDSHAKES));

        tokio::spawn(async move {
            loop {
                let (socket, addr) = match listener.accept().await {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::debug!("TCP accept error: {}", e);
                        // Back off briefly: accept errors (e.g. EMFILE) tend
                        // to repeat immediately.
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        continue;
                    }
                };
                let Ok(permit) = permits.clone().try_acquire_owned() else {
                    tracing::warn!("Too many concurrent TLS handshakes; dropping {}", addr);
                    continue;
                };
                if tx.is_closed() {
                    break;
                }
                let acceptor = acceptor.clone();
                let tx = tx.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    match tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept_tls(socket)).await {
                        Ok(Ok(stream)) => {
                            let _ = tx.send((stream, addr)).await;
                        }
                        Ok(Err(e)) => tracing::debug!("TLS handshake failed from {}: {}", addr, e),
                        Err(_) => tracing::debug!("TLS handshake timed out from {}", addr),
                    }
                });
            }
        });

        Self { ready, local_addr }
    }
}

impl<A> Listener for TlsListener<A>
where
    A: AcceptTls,
{
    type Io = A::Stream;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        match self.ready.recv().await {
            Some(conn) => conn,
            // The accept task only exits when this listener is dropped.
            None => std::future::pending().await,
        }
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        self.local_addr
            .clone()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
    }
}

/// Peer socket address for a TLS-served connection. Used with
/// `ConnectInfo<PeerAddr>` because orphan rules prevent us from implementing
/// `Connected` on `std::net::SocketAddr` for our custom listener.
#[derive(Copy, Clone, Debug)]
pub struct PeerAddr(pub SocketAddr);

impl PeerAddr {
    pub fn ip_string(&self) -> String {
        self.0.ip().to_string()
    }
}

impl<A> axum::extract::connect_info::Connected<axum::serve::IncomingStream<'_, TlsListener<A>>>
    for PeerAddr
where
    A: AcceptTls,
{
    fn connect_info(stream: axum::serve::IncomingStream<'_, TlsListener<A>>) -> Self {
        PeerAddr(*stream.remote_addr())
    }
}

/// The port an ACME CA connects to for TLS-ALPN-01 validation (RFC 8737 §3).
pub const ACME_VALIDATION_PORT: u16 = 443;

/// Serve an Axum `Router` over TLS using the given `TlsConfig`.
///
/// Supports both file-based certificates (with hot-reload via `notify`) and
/// ACME (Let's Encrypt and compatible). This is the single entry point used
/// by both the web tier and the agent so TLS-serving logic lives in one place.
pub async fn serve_with_tls(
    listener: TcpListener,
    app: Router,
    tls: &TlsConfig,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    match tls {
        TlsConfig::Files { chain, key } => {
            let certified_key = create_certified_key(chain, key)
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
                    format!("Failed to load certs: {e}").into()
                })?;

            let resolver = Arc::new(DynamicCertResolver::new(certified_key));
            start_cert_watcher(chain.clone(), key.clone(), resolver.clone());

            let mut rustls_config = rustls::server::ServerConfig::builder()
                .with_no_client_auth()
                .with_cert_resolver(resolver);
            rustls_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

            let tls_acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(rustls_config));
            let tls_listener = TlsListener::new(listener, tls_acceptor);

            axum::serve(
                tls_listener,
                app.into_make_service_with_connect_info::<PeerAddr>(),
            )
            .await
            .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
                format!("Server error: {e}").into()
            })?;
        }
        TlsConfig::Acme {
            domains,
            email,
            cache_dir,
            directory_url,
            challenge,
            http_challenge_address,
        } => {
            use crate::config::AcmeChallenge;
            use futures::StreamExt;
            use hyper_util::rt::{TokioExecutor, TokioIo};
            use hyper_util::server::conn::auto::Builder;
            use hyper_util::service::TowerToHyperService;
            use rustls_acme::{caches::DirCache, AcmeConfig};
            use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};

            if *challenge == AcmeChallenge::TlsAlpn01 && http_challenge_address.is_some() {
                return Err("http_challenge_address only applies with challenge = \"http-01\"".into());
            }
            // TLS-ALPN-01 is always checked on port 443 (RFC 8737 §3).
            // Another port works only if 443 is forwarded here, so say so
            // rather than fail silently at the CA. HTTP-01 has no such
            // constraint on this listener.
            if *challenge == AcmeChallenge::TlsAlpn01
                && let Ok(addr) = listener.local_addr()
                && addr.port() != ACME_VALIDATION_PORT
            {
                tracing::warn!(
                    port = addr.port(),
                    "ACME: the CA validates on port {ACME_VALIDATION_PORT} of {}. Listen on \
                     {ACME_VALIDATION_PORT}, forward {ACME_VALIDATION_PORT} to this port, or use \
                     challenge = \"http-01\"; otherwise no certificate will be issued",
                    domains.join(", ")
                );
            }

            let (signals, signal_rx) = crate::acme_http01::channel();
            let cache = crate::acme_http01::NotifyingCache::new(DirCache::new(cache_dir.clone()), signals.clone());

            let mut root_store = rustls::RootCertStore::empty();
            for cert in rustls_native_certs::load_native_certs()
                .expect("could not load platform certs")
            {
                root_store.add(cert).ok();
            }

            // The client the ACME library talks to the CA with. Its verifier
            // reports each connection, which is how HTTP-01 knows an order
            // has started; with resumption off, every connection verifies.
            let provider = Arc::new(rustls::crypto::ring::default_provider());
            let verifier = rustls::client::WebPkiServerVerifier::builder_with_provider(
                Arc::new(root_store),
                provider.clone(),
            )
            .build()
            .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { format!("ACME client: {e}").into() })?;
            let mut client_config = rustls::client::ClientConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .unwrap()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(crate::acme_http01::NotifyingVerifier::new(
                    verifier, signals,
                )))
                .with_no_client_auth();
            client_config.resumption = rustls::client::Resumption::disabled();

            let mut acme_config =
                AcmeConfig::new_with_client_config(domains.clone(), Arc::new(client_config))
                    .contact(email.iter().map(|e| format!("mailto:{}", e)))
                    .cache(cache);
            if *challenge == AcmeChallenge::Http01 {
                acme_config = acme_config.challenge_type(rustls_acme::UseChallenge::Http01);
            }

            if let Some(url) = directory_url {
                acme_config = acme_config.directory(url);
            } else {
                acme_config = acme_config.directory_lets_encrypt(true);
            }

            let listener_stream = tokio_stream::wrappers::TcpListenerStream::new(listener)
                .map(|res| res.map(|s| s.compat()));

            let state = acme_config.state();
            if *challenge == AcmeChallenge::Http01 {
                let address = http_challenge_address
                    .clone()
                    .unwrap_or_else(|| crate::acme_http01::DEFAULT_ADDRESS.to_string());
                if !address.ends_with(":80") {
                    tracing::warn!(
                        "ACME: the CA validates HTTP-01 on port 80 of {}; {address} works only \
                         if port 80 is forwarded to it",
                        domains.join(", ")
                    );
                }
                tokio::spawn(crate::acme_http01::run(address, state.resolver(), signal_rx));
            }
            let mut incoming = state.incoming(listener_stream, vec![b"h2".to_vec(), b"http/1.1".to_vec()]);

            while let Some(tls) = incoming.next().await {
                match tls {
                    Ok(tls_stream) => {
                        // This path drives hyper directly rather than
                        // `axum::serve`, so nothing inserts `ConnectInfo`.
                        // Recover the peer from the underlying TCP socket so
                        // audit records carry the real source address.
                        let peer_addr = tls_stream
                            .get_ref()
                            .0
                            .get_ref()
                            .peer_addr()
                            .unwrap_or_else(|e| {
                                tracing::debug!("Could not read peer address: {}", e);
                                SocketAddr::from(([0, 0, 0, 0], 0))
                            });

                        let compat_tls = tls_stream.compat();
                        let io = TokioIo::new(compat_tls);

                        let app = app.clone().layer(axum::Extension(
                            axum::extract::ConnectInfo(PeerAddr(peer_addr)),
                        ));
                        let service = TowerToHyperService::new(app);

                        tokio::spawn(async move {
                            let builder = Builder::new(TokioExecutor::new());
                            if let Err(err) = builder.serve_connection(io, service).await {
                                tracing::debug!("Error serving connection: {}", err);
                            }
                        });
                    }
                    Err(e) => {
                        tracing::debug!("ACME handshake error: {}", e);
                    }
                }
            }
        }
    }

    Ok(())
}
