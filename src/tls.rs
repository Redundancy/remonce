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

pub struct TlsListener<A> {
    pub listener: TcpListener,
    pub acceptor: A,
}

impl<A> TlsListener<A> {
    pub fn new(listener: TcpListener, acceptor: A) -> Self {
        Self { listener, acceptor }
    }
}

impl<A> Listener for TlsListener<A>
where
    A: AcceptTls,
{
    type Io = A::Stream;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            let (socket, addr) = match self.listener.accept().await {
                Ok(v) => v,
                Err(e) => {
                     tracing::debug!("TCP accept error: {}", e);
                     continue;
                }
            };
            
            match self.acceptor.accept_tls(socket).await {
                Ok(stream) => return (stream, addr),
                Err(e) => {
                    tracing::debug!("TLS handshake failed: {}", e);
                    continue;
                }
            }
        }
    }
    
    fn local_addr(&self) -> io::Result<Self::Addr> {
        self.listener.local_addr()
    }
}
