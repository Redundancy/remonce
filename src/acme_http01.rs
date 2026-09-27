//! HTTP-01 validation for ACME, with port 80 open only while a certificate
//! is being issued.
//!
//! The CA validates HTTP-01 by fetching
//! `http://<domain>/.well-known/acme-challenge/<token>` on port 80, so the
//! agent's own HTTPS listener can use any port. rustls-acme has no event
//! for "renewal starting", so two hooks stand in for one:
//!
//! - **Start**: every order begins by connecting to the CA with the TLS
//!   client config we supply. Its certificate verifier reports each
//!   handshake (session resumption is off, so every connection does one).
//! - **Done**: the new certificate is written to the cache.
//!
//! Port 80 is bound on the first CA contact and released when the new
//! certificate is stored, or after [`IDLE_CLOSE`] with no CA contact (a
//! failed attempt; the library's retry contacts the CA again and reopens
//! it). While open, it answers only challenge tokens, and 404 otherwise.

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use rustls_acme::{CertCache, AccountCache, ResolvesServerCertAcme};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

/// Where the challenge responder listens by default.
pub const DEFAULT_ADDRESS: &str = "0.0.0.0:80";
/// Close port 80 after this long without talking to the CA.
pub const IDLE_CLOSE: Duration = Duration::from_secs(5 * 60);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Signal {
    /// A TLS handshake with the CA: an order is in progress.
    CaContact,
    /// A new certificate was stored: the order is done.
    CertStored,
}

pub fn channel() -> (UnboundedSender<Signal>, UnboundedReceiver<Signal>) {
    tokio::sync::mpsc::unbounded_channel()
}

/// Wraps the ACME client's certificate verifier to report each CA contact.
#[derive(Debug)]
pub struct NotifyingVerifier {
    inner: Arc<dyn ServerCertVerifier>,
    signals: UnboundedSender<Signal>,
}

impl NotifyingVerifier {
    pub fn new(inner: Arc<dyn ServerCertVerifier>, signals: UnboundedSender<Signal>) -> Self {
        NotifyingVerifier { inner, signals }
    }
}

impl ServerCertVerifier for NotifyingVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let _ = self.signals.send(Signal::CaContact);
        self.inner
            .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// A cache that reports each newly stored certificate.
pub struct NotifyingCache<C> {
    inner: C,
    signals: UnboundedSender<Signal>,
}

impl<C> NotifyingCache<C> {
    pub fn new(inner: C, signals: UnboundedSender<Signal>) -> Self {
        NotifyingCache { inner, signals }
    }
}

#[async_trait::async_trait]
impl<C: CertCache> CertCache for NotifyingCache<C> {
    type EC = C::EC;
    async fn load_cert(&self, domains: &[String], directory_url: &str) -> Result<Option<Vec<u8>>, Self::EC> {
        self.inner.load_cert(domains, directory_url).await
    }
    async fn store_cert(&self, domains: &[String], directory_url: &str, cert: &[u8]) -> Result<(), Self::EC> {
        let result = self.inner.store_cert(domains, directory_url, cert).await;
        // The certificate is deployed before it is stored, so the order is
        // over either way.
        let _ = self.signals.send(Signal::CertStored);
        result
    }
}

#[async_trait::async_trait]
impl<C: AccountCache> AccountCache for NotifyingCache<C> {
    type EA = C::EA;
    async fn load_account(&self, contact: &[String], directory_url: &str) -> Result<Option<Vec<u8>>, Self::EA> {
        self.inner.load_account(contact, directory_url).await
    }
    async fn store_account(&self, contact: &[String], directory_url: &str, account: &[u8]) -> Result<(), Self::EA> {
        self.inner.store_account(contact, directory_url, account).await
    }
}

fn responder(resolver: Arc<ResolvesServerCertAcme>) -> axum::Router {
    use axum::extract::Path;
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    axum::Router::new()
        .route(
            "/.well-known/acme-challenge/{token}",
            axum::routing::get(move |Path(token): Path<String>| {
                let resolver = resolver.clone();
                async move {
                    match resolver.get_http_01_key_auth(&token) {
                        Some(key_auth) => {
                            tracing::info!("ACME: answered an HTTP-01 challenge");
                            (StatusCode::OK, key_auth).into_response()
                        }
                        None => StatusCode::NOT_FOUND.into_response(),
                    }
                }
            }),
        )
        .fallback(|| async { StatusCode::NOT_FOUND })
}

/// Open the challenge responder at `address` while the CA is being talked
/// to, and close it when the certificate is stored or the CA goes quiet.
/// Runs until the signal channel closes.
pub async fn run(address: String, resolver: Arc<ResolvesServerCertAcme>, signals: UnboundedReceiver<Signal>) {
    run_with_idle(address, resolver, signals, IDLE_CLOSE).await
}

async fn run_with_idle(
    address: String,
    resolver: Arc<ResolvesServerCertAcme>,
    mut signals: UnboundedReceiver<Signal>,
    idle: Duration,
) {
    loop {
        // Closed: wait for an order to start.
        match signals.recv().await {
            Some(Signal::CaContact) => {}
            Some(Signal::CertStored) => continue,
            None => return,
        }
        let listener = match tokio::net::TcpListener::bind(&address).await {
            Ok(l) => l,
            Err(e) => {
                tracing::error!(
                    "ACME: can't open {address} for HTTP-01 validation: {e}. No certificate will \
                     be issued until it can (binding port 80 may need privileges)"
                );
                continue;
            }
        };
        tracing::info!("ACME: opened {address} for HTTP-01 validation");
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let server = tokio::spawn(
            axum::serve(listener, responder(resolver.clone()))
                .with_graceful_shutdown(async {
                    let _ = stopped.await;
                })
                .into_future(),
        );

        // Open: stay open while the CA is being talked to.
        let reason = loop {
            match tokio::time::timeout(idle, signals.recv()).await {
                Ok(Some(Signal::CaContact)) => continue,
                Ok(Some(Signal::CertStored)) => break "certificate issued",
                Ok(None) => break "shutting down",
                Err(_) => break "no contact with the CA; it reopens on the next attempt",
            }
        };
        let _ = stop.send(());
        let _ = tokio::time::timeout(Duration::from_secs(5), server).await;
        tracing::info!("ACME: closed {address} ({reason})");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resolver() -> Arc<ResolvesServerCertAcme> {
        // Challenge data can't be set from outside the crate, so these tests
        // check the port's lifecycle and the 404 answers.
        let client = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();
        rustls_acme::AcmeConfig::new_with_client_config(["example.invalid"], Arc::new(client))
            .state()
            .resolver()
    }

    async fn get(addr: &str, path: &str) -> Option<u16> {
        let client = reqwest::Client::new();
        client
            .get(format!("http://{addr}{path}"))
            .timeout(Duration::from_secs(2))
            .send()
            .await
            .ok()
            .map(|r| r.status().as_u16())
    }

    fn free_address() -> String {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().to_string()
    }

    async fn settle() {
        tokio::time::sleep(Duration::from_millis(150)).await;
    }

    #[tokio::test]
    async fn port_opens_on_ca_contact_and_closes_when_stored() {
        let addr = free_address();
        let (tx, rx) = channel();
        tokio::spawn(run_with_idle(addr.clone(), resolver(), rx, Duration::from_secs(30)));

        settle().await;
        assert_eq!(get(&addr, "/.well-known/acme-challenge/x").await, None, "closed until an order starts");

        tx.send(Signal::CaContact).unwrap();
        settle().await;
        assert_eq!(get(&addr, "/.well-known/acme-challenge/unknown").await, Some(404));
        assert_eq!(get(&addr, "/anything-else").await, Some(404), "answers nothing but challenges");

        tx.send(Signal::CertStored).unwrap();
        settle().await;
        assert_eq!(get(&addr, "/.well-known/acme-challenge/x").await, None, "closed once issued");

        // The next renewal opens it again.
        tx.send(Signal::CaContact).unwrap();
        settle().await;
        assert_eq!(get(&addr, "/x").await, Some(404));
    }

    #[tokio::test]
    async fn port_closes_when_the_ca_goes_quiet() {
        let addr = free_address();
        let (tx, rx) = channel();
        tokio::spawn(run_with_idle(addr.clone(), resolver(), rx, Duration::from_millis(300)));
        tx.send(Signal::CaContact).unwrap();
        settle().await;
        assert_eq!(get(&addr, "/x").await, Some(404));
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(get(&addr, "/x").await, None, "a failed attempt doesn't leave it open");
    }
}
