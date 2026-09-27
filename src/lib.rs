pub mod config;
pub mod security;
pub mod agent;
pub mod agent_proxy;
pub mod known_agents;
pub mod cli;
pub mod catalog;
pub mod requirements;
pub mod web;
pub mod web_sign;
pub mod oidc_client;
pub mod signing;
pub mod files;
pub mod audit;
pub mod tls;
pub mod acme_http01;
pub mod insecure;
pub mod policy;
pub mod params;
pub mod replay;
pub mod revocation;
pub mod tsa;

/// HTTP client for OIDC discovery, JWKS, TSA and OPA calls. Bounded
/// timeouts: a hung dependency must not pin request tasks forever.
pub fn http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(10))
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .expect("static HTTP client configuration is valid")
}

#[cfg(test)]
mod golden_tests;
#[cfg(test)]
mod security_tests;
