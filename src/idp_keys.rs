//! The IdP's token-signing keys, kept current while the process runs.
//!
//! An IdP rotates its signing keys. A process that fetched them once at
//! startup rejects every token signed after a rotation until it restarts,
//! so the set is refetched: when a token names a key we don't hold (at most
//! once per `MIN_REFRESH_INTERVAL`, since anyone can send such a token),
//! and on a slow timer.
//!
//! The IdP is followed exactly: a refresh replaces the whole set, so a key
//! the IdP has withdrawn stops verifying here too — including for approvals
//! made while it was current. `approval_validity` therefore shouldn't exceed
//! how long the IdP keeps a rotated key published. If the IdP can't be
//! reached, the last set it gave us stays in use.

use jsonwebtoken::jwk::JwkSet;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

/// Least time between refreshes triggered by unknown key ids.
pub const MIN_REFRESH_INTERVAL: Duration = Duration::from_secs(60);
/// How often the set is refetched regardless, so withdrawn keys go even
/// when nothing unknown turns up.
pub const PERIODIC_REFRESH: Duration = Duration::from_secs(60 * 60);

type FetchFuture = Pin<Box<dyn Future<Output = Result<JwkSet, String>> + Send>>;
type Fetcher = Box<dyn Fn() -> FetchFuture + Send + Sync>;

#[derive(Clone)]
pub struct IdpKeys {
    inner: Arc<Inner>,
}

struct Inner {
    current: RwLock<Arc<JwkSet>>,
    /// Where a fresh set comes from; `None` for a fixed set.
    fetch: Option<Fetcher>,
    /// When the last refresh was attempted. Held across a fetch, so
    /// concurrent callers wait for one fetch instead of each starting one.
    last_attempt: tokio::sync::Mutex<Option<Instant>>,
    min_interval: Duration,
}

impl IdpKeys {
    /// A set that never changes.
    pub fn fixed(keys: JwkSet) -> Self {
        Self::new(keys, None, MIN_REFRESH_INTERVAL)
    }

    /// `initial`, replaced by whatever `fetch` returns on each refresh.
    pub fn refreshing<F, Fut>(initial: JwkSet, fetch: F, min_interval: Duration) -> Self
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<JwkSet, String>> + Send + 'static,
    {
        Self::new(initial, Some(Box::new(move || Box::pin(fetch()))), min_interval)
    }

    fn new(initial: JwkSet, fetch: Option<Fetcher>, min_interval: Duration) -> Self {
        IdpKeys {
            inner: Arc::new(Inner {
                current: RwLock::new(Arc::new(initial)),
                fetch,
                last_attempt: tokio::sync::Mutex::new(None),
                min_interval,
            }),
        }
    }

    /// Discover the IdP at `issuer_url` and keep its keys current from then
    /// on: on demand, and every `PERIODIC_REFRESH`. Each refresh repeats
    /// discovery, so a moved `jwks_uri` is followed too.
    pub async fn discover(
        http: &reqwest::Client,
        issuer_url: &str,
    ) -> Result<(crate::web::OidcMetadata, Self), String> {
        let (metadata, initial) = crate::oidc_client::discover(http, issuer_url).await?;
        let (http, issuer) = (http.clone(), issuer_url.to_string());
        let keys = Self::refreshing(
            initial,
            move || {
                let (http, issuer) = (http.clone(), issuer.clone());
                async move { crate::oidc_client::discover(&http, &issuer).await.map(|(_, keys)| keys) }
            },
            MIN_REFRESH_INTERVAL,
        );
        let periodic = keys.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(PERIODIC_REFRESH).await;
                periodic.refresh().await;
            }
        });
        Ok((metadata, keys))
    }

    /// The set as it is now.
    pub fn current(&self) -> Arc<JwkSet> {
        self.inner.current.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// The set to verify `tokens` against: refetched first if one of them
    /// names a key that isn't in it (and a refresh is due).
    pub async fn for_tokens<'a>(&self, tokens: impl IntoIterator<Item = &'a str>) -> Arc<JwkSet> {
        let current = self.current();
        let unknown = tokens.into_iter().any(|token| {
            jsonwebtoken::decode_header(token)
                .ok()
                .and_then(|h| h.kid)
                .is_some_and(|kid| current.find(&kid).is_none())
        });
        if !unknown {
            return current;
        }
        self.refresh_if_due().await;
        self.current()
    }

    /// Refetch unless a refresh was attempted within the minimum interval.
    async fn refresh_if_due(&self) {
        let mut last = self.inner.last_attempt.lock().await;
        if last.is_some_and(|at| at.elapsed() < self.inner.min_interval) {
            return;
        }
        self.fetch_into(&mut last).await;
    }

    /// Refetch now.
    pub async fn refresh(&self) {
        let mut last = self.inner.last_attempt.lock().await;
        self.fetch_into(&mut last).await;
    }

    async fn fetch_into(&self, last_attempt: &mut Option<Instant>) {
        let Some(fetch) = &self.inner.fetch else {
            return;
        };
        *last_attempt = Some(Instant::now());
        match fetch().await {
            Ok(keys) => {
                let ids = |set: &JwkSet| {
                    let mut ids: Vec<String> = set.keys.iter().filter_map(|k| k.common.key_id.clone()).collect();
                    ids.sort();
                    ids
                };
                let (before, after) = (ids(&self.current()), ids(&keys));
                if before != after {
                    tracing::info!(event = "idp_keys_changed", ?before, ?after, "IdP signing keys changed");
                }
                *self.inner.current.write().unwrap_or_else(|e| e.into_inner()) = Arc::new(keys);
            }
            Err(e) => {
                tracing::warn!(event = "idp_keys_refresh_failed", "Could not refresh IdP signing keys; keeping the last set: {e}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security_tests::tests::{create_valid_jwt, keys_to_jwk, setup_keys};
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A fake IdP: `publish` sets what the next fetch returns (`None`: the
    /// IdP is unreachable), and `fetches` counts them.
    struct FakeIdp {
        published: Arc<Mutex<Option<JwkSet>>>,
        fetches: Arc<AtomicUsize>,
    }

    impl FakeIdp {
        fn new() -> Self {
            FakeIdp {
                published: Arc::new(Mutex::new(None)),
                fetches: Arc::new(AtomicUsize::new(0)),
            }
        }

        fn publish(&self, keys: Option<JwkSet>) {
            *self.published.lock().unwrap() = keys;
        }

        fn keys(&self, initial: JwkSet, min_interval: Duration) -> IdpKeys {
            let (published, fetches) = (self.published.clone(), self.fetches.clone());
            IdpKeys::refreshing(
                initial,
                move || {
                    fetches.fetch_add(1, Ordering::SeqCst);
                    let result = published.lock().unwrap().clone().ok_or_else(|| "unreachable".to_string());
                    async move { result }
                },
                min_interval,
            )
        }

        fn fetches(&self) -> usize {
            self.fetches.load(Ordering::SeqCst)
        }
    }

    fn set(kids: &[&str]) -> JwkSet {
        JwkSet {
            keys: kids.iter().map(|kid| keys_to_jwk(&setup_keys(kid))).collect(),
        }
    }

    fn token(kid: &str) -> String {
        create_valid_jwt(
            &setup_keys(kid),
            "https://issuer.example",
            "aud",
            "alice",
            "nonce",
            time::OffsetDateTime::now_utc(),
            serde_json::json!({}),
        )
    }

    fn kids(keys: &Arc<JwkSet>) -> Vec<String> {
        keys.keys.iter().filter_map(|k| k.common.key_id.clone()).collect()
    }

    #[tokio::test]
    async fn known_key_does_not_refetch() {
        let idp = FakeIdp::new();
        let keys = idp.keys(set(&["k1"]), Duration::ZERO);
        let token = token("k1");
        assert_eq!(kids(&keys.for_tokens([token.as_str()]).await), ["k1"]);
        assert_eq!(idp.fetches(), 0);
    }

    #[tokio::test]
    async fn unknown_key_refetches_and_follows_the_idp() {
        let idp = FakeIdp::new();
        let keys = idp.keys(set(&["k1"]), Duration::ZERO);
        // The IdP rotated: k2 is current and k1 has been withdrawn.
        idp.publish(Some(set(&["k2"])));
        let token = token("k2");
        assert_eq!(kids(&keys.for_tokens([token.as_str()]).await), ["k2"]);
        assert_eq!(idp.fetches(), 1);
        // The withdrawn key is gone, not remembered.
        assert!(keys.current().find("k1").is_none());
    }

    #[tokio::test]
    async fn unknown_keys_refetch_at_most_once_per_interval() {
        let idp = FakeIdp::new();
        let keys = idp.keys(set(&["k1"]), Duration::from_secs(3600));
        idp.publish(Some(set(&["k1"])));
        let (a, b) = (token("nope"), token("nope-either"));
        keys.for_tokens([a.as_str()]).await;
        keys.for_tokens([b.as_str()]).await;
        keys.for_tokens([a.as_str(), b.as_str()]).await;
        assert_eq!(idp.fetches(), 1);
    }

    #[tokio::test]
    async fn unreachable_idp_keeps_the_last_set() {
        let idp = FakeIdp::new();
        let keys = idp.keys(set(&["k1"]), Duration::ZERO);
        idp.publish(None);
        let token = token("k2");
        assert_eq!(kids(&keys.for_tokens([token.as_str()]).await), ["k1"]);
        assert_eq!(idp.fetches(), 1);
    }

    #[tokio::test]
    async fn timed_refresh_drops_withdrawn_keys() {
        let idp = FakeIdp::new();
        let keys = idp.keys(set(&["k1", "k2"]), Duration::from_secs(3600));
        idp.publish(Some(set(&["k2"])));
        keys.refresh().await;
        assert_eq!(kids(&keys.current()), ["k2"]);
    }

    #[tokio::test]
    async fn fixed_set_never_fetches() {
        let keys = IdpKeys::fixed(set(&["k1"]));
        let token = token("k2");
        assert_eq!(kids(&keys.for_tokens([token.as_str()]).await), ["k1"]);
        keys.refresh().await;
        assert_eq!(kids(&keys.current()), ["k1"]);
    }

    #[tokio::test]
    async fn malformed_tokens_do_not_refetch() {
        let idp = FakeIdp::new();
        let keys = idp.keys(set(&["k1"]), Duration::ZERO);
        keys.for_tokens(["not a jwt", ""]).await;
        assert_eq!(idp.fetches(), 0);
    }
}
