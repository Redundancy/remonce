//! `--insecure` gating for security-degraded configuration options.
//!
//! Certain config settings broaden the trust surface in ways we consider
//! dangerous as a default. Operators who genuinely need them must opt in
//! with `--insecure` at startup. This module scans the config, collects
//! any violations, and either refuses to start (secure mode) or logs a
//! loud warning for each one (insecure mode).
//!
//! The resulting `InsecureMode` value is threaded into the audit log so
//! post-incident review can tell whether the agent was running in a
//! degraded posture.

use crate::config::Config;
use std::time::Duration;
use url::Url;

/// Maximum `operator_max_validity` the agent will accept without `--insecure`.
/// Longer windows effectively turn off the at-execution-time freshness bound.
const OPERATOR_MAX_VALIDITY_SAFE_CEILING: Duration = Duration::from_secs(60 * 60);

#[derive(Debug, Clone)]
pub struct InsecureMode {
    pub enabled: bool,
    pub active_gates: Vec<String>,
}

impl InsecureMode {
    pub fn as_bool(&self) -> bool {
        self.enabled && !self.active_gates.is_empty()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum InsecureError {
    #[error("configuration requires --insecure to run:\n{}", .0.join("\n"))]
    Refused(Vec<String>),
}

/// Scan the config, emit warnings for active insecure options, and either
/// return an `InsecureMode` (enabled or not) or refuse to start.
pub fn validate(config: &Config, insecure_flag: bool) -> Result<InsecureMode, InsecureError> {
    let mut violations = Vec::new();

    // Gate 1: OIDC issuer_url is HTTP and non-loopback.
    if let Ok(url) = Url::parse(&config.oidc.issuer_url) {
        if url.scheme() == "http" && !host_is_loopback(&url) {
            violations.push(format!(
                "oidc.issuer_url is http:// and non-loopback ({}); the JWKS fetch is MITM-able",
                config.oidc.issuer_url
            ));
        }
    }

    // Gate 2: TSA system trust store enabled.
    if config.timestamp_authority.trust_system_store {
        violations.push(
            "timestamp_authority.trust_system_store = true; trusts every CA in the OS store as a TSA signer"
                .into(),
        );
    }

    // Gate 3: operator_max_validity too long on any command.
    for cmd in &config.commands {
        let v = cmd.operator_max_validity_or_default();
        if v > OPERATOR_MAX_VALIDITY_SAFE_CEILING {
            violations.push(format!(
                "command '{}' has operator_max_validity {:?} (> {:?}); defeats the freshness bound",
                cmd.name, v, OPERATOR_MAX_VALIDITY_SAFE_CEILING
            ));
        }
    }

    // Gate 4: agent CORS wildcard.
    if let Some(agent) = &config.agent {
        if agent.cors_allowed_origins.iter().any(|o| o == "*") {
            violations.push(
                "agent.cors_allowed_origins contains '*'; allows any browser origin to call the agent".into(),
            );
        }
    }

    if violations.is_empty() {
        return Ok(InsecureMode {
            enabled: false,
            active_gates: vec![],
        });
    }

    if !insecure_flag {
        return Err(InsecureError::Refused(violations));
    }

    // `--insecure` is set; loudly announce each active gate.
    tracing::warn!(
        "================================================================"
    );
    tracing::warn!("  RUNNING WITH --insecure. Degraded security posture active.");
    for v in &violations {
        tracing::warn!("  * {}", v);
    }
    tracing::warn!(
        "================================================================"
    );

    Ok(InsecureMode {
        enabled: true,
        active_gates: violations,
    })
}

fn host_is_loopback(url: &Url) -> bool {
    match url.host_str() {
        Some(h) => {
            h == "localhost"
                || h == "127.0.0.1"
                || h == "::1"
                || h.parse::<std::net::IpAddr>()
                    .map(|ip| ip.is_loopback())
                    .unwrap_or(false)
        }
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AgentConfig, CommandConfig, OidcConfig, TlsConfig, TsaConfig};

    fn base_config() -> Config {
        Config {
            oidc: OidcConfig {
                issuer_url: "https://issuer.example/".into(),
                client_id: "x".into(),
                redirect_uri: None,
            },
            listen_address: "127.0.0.1:8080".into(),
            tls: None,
            timestamp_authority: TsaConfig::default(),
            commands: vec![],
            logs_dir: "logs".into(),
            opa_url: "http://127.0.0.1:8181".into(),
            files: vec![],
            agent: None,
            agent_url: "https://localhost:10022".into(),
            agent_ca_path: None,
        }
    }

    #[test]
    fn clean_config_passes_without_insecure() {
        let r = validate(&base_config(), false).unwrap();
        assert!(!r.enabled);
        assert!(r.active_gates.is_empty());
    }

    #[test]
    fn http_non_loopback_issuer_rejected_without_insecure() {
        let mut cfg = base_config();
        cfg.oidc.issuer_url = "http://idp.example/".into();
        assert!(matches!(
            validate(&cfg, false),
            Err(InsecureError::Refused(_))
        ));
    }

    #[test]
    fn http_loopback_issuer_is_fine() {
        let mut cfg = base_config();
        cfg.oidc.issuer_url = "http://127.0.0.1:8200/v1/identity/oidc/provider/x".into();
        let r = validate(&cfg, false).unwrap();
        assert!(!r.enabled);
    }

    #[test]
    fn long_operator_validity_rejected() {
        let mut cfg = base_config();
        cfg.commands.push(CommandConfig {
            name: "risky".into(),
            description: None,
            opa_rule: "data.x.allow".into(),
            executable: None,
            args: vec![],
            cwd: None,
            approver_max_validity: None,
            operator_max_validity: Some(Duration::from_secs(3 * 60 * 60)),
            command_timeout: None,
            env: Default::default(),
            params: vec![],
        });
        assert!(matches!(
            validate(&cfg, false),
            Err(InsecureError::Refused(_))
        ));
    }

    #[test]
    fn wildcard_cors_rejected() {
        let mut cfg = base_config();
        cfg.agent = Some(AgentConfig {
            listen_address: "0.0.0.0:10022".into(),
            tls: TlsConfig::Files {
                chain: "c".into(),
                key: "k".into(),
            },
            cors_allowed_origins: vec!["*".into()],
        });
        assert!(matches!(
            validate(&cfg, false),
            Err(InsecureError::Refused(_))
        ));
    }

    #[test]
    fn insecure_flag_allows_violations() {
        let mut cfg = base_config();
        cfg.timestamp_authority.trust_system_store = true;
        let r = validate(&cfg, true).unwrap();
        assert!(r.enabled);
        assert_eq!(r.active_gates.len(), 1);
    }
}
