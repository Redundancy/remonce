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

/// Longest `approval_validity` accepted without `--insecure`. Past a week an
/// approval stops meaning "these people agreed recently".
const APPROVAL_VALIDITY_SAFE_CEILING: Duration = Duration::from_secs(7 * 24 * 60 * 60);

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
    /// Configuration that is wrong rather than merely risky. `--insecure`
    /// does not bypass these.
    #[error("invalid configuration:\n{}", .0.join("\n"))]
    Invalid(Vec<String>),
}

/// Configuration errors that no flag can excuse: they either break the
/// security model outright or guarantee every signature fails.
fn invalid_config(config: &Config) -> Vec<String> {
    let mut errors = Vec::new();
    let oidc = &config.oidc;

    if oidc.signing_client_id.is_empty() {
        errors.push("oidc.signing_client_id must be set".into());
    }
    match oidc.viewer_client_id.as_deref() {
        Some("") => errors.push("oidc.viewer_client_id is empty; remove it or set it".into()),
        // Sharing a client would make every signing token a valid bearer
        // token for file/log viewing, and vice versa.
        Some(v) if v == oidc.signing_client_id => errors.push(
            "oidc.viewer_client_id must differ from oidc.signing_client_id; viewer tokens are bearer \
             credentials and must never share an audience with signing tokens"
                .into(),
        ),
        _ => {}
    }
    for cmd in &config.commands {
        if cmd.approval_validity_or_default().is_zero() {
            errors.push(format!(
                "command '{}' has approval_validity 0; every approval would already be expired",
                cmd.name
            ));
        }
    }
    let max_age = oidc.signing_max_age_or_default();
    if max_age > crate::security::MAX_AUTH_AGE {
        errors.push(format!(
            "oidc.signing_max_age {:?} exceeds the {:?} agents accept between authentication \
             and token issue; signatures made with it would never verify",
            max_age,
            crate::security::MAX_AUTH_AGE
        ));
    }
    errors
}

/// Scan the config, emit warnings for active insecure options, and either
/// return an `InsecureMode` (enabled or not) or refuse to start.
pub fn validate(config: &Config, insecure_flag: bool) -> Result<InsecureMode, InsecureError> {
    let errors = invalid_config(config);
    if !errors.is_empty() {
        return Err(InsecureError::Invalid(errors));
    }

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

    // Gate 3: approvals that stay usable for too long.
    for cmd in &config.commands {
        let v = cmd.approval_validity_or_default();
        if v > APPROVAL_VALIDITY_SAFE_CEILING {
            violations.push(format!(
                "command '{}' has approval_validity {} (> {}); approvals would stay usable long after anyone reviewed them",
                cmd.name,
                humantime_serde::re::humantime::format_duration(v),
                humantime_serde::re::humantime::format_duration(APPROVAL_VALIDITY_SAFE_CEILING)
            ));
        }
    }

    // Gate 4: a remote OPA reached over plaintext on the network. OPA's
    // answer is the authorization decision; a MITM could simply return allow.
    if let Some(opa_url) = &config.opa_url
        && let Ok(url) = Url::parse(opa_url)
        && url.scheme() == "http"
        && !host_is_loopback(&url)
    {
        violations.push(format!(
            "opa_url is http:// and non-loopback ({opa_url}); a MITM can forge authorization decisions"
        ));
    }

    // Gate 5: agent CORS wildcard.
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
                signing_client_id: "x".into(),
                viewer_client_id: Some("x-viewer".into()),
                signing_max_age: None,
                signing_prompt_login: false,
                redirect_uri: None,
            },
            listen_address: "127.0.0.1:8080".into(),
            tls: None,
            timestamp_authority: TsaConfig::default(),
            commands: vec![],
            logs_dir: "logs".into(),
            policy_dir: None,
            opa_url: None,
            files: vec![],
            agent: None,
            agent_url: "https://localhost:10022".into(),
            agent_ca_path: None,
            allowed_agent_urls: vec![],
            revocation_service: None,
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

    fn command_with_validity(v: Duration) -> CommandConfig {
        CommandConfig {
            name: "cmd".into(),
            description: None,
            opa_rule: "data.x.allow".into(),
            executable: None,
            args: vec![],
            cwd: None,
            approval_validity: Some(v),
            command_timeout: None,
            env: Default::default(),
            params: vec![],
        }
    }

    #[test]
    fn long_approval_validity_needs_insecure() {
        let mut cfg = base_config();
        cfg.commands.push(command_with_validity(Duration::from_secs(8 * 24 * 60 * 60)));
        assert!(matches!(validate(&cfg, false), Err(InsecureError::Refused(_))));
        assert!(validate(&cfg, true).is_ok());

        let mut week = base_config();
        week.commands.push(command_with_validity(APPROVAL_VALIDITY_SAFE_CEILING));
        assert!(validate(&week, false).is_ok());
    }

    #[test]
    fn zero_approval_validity_refused_even_with_insecure() {
        let mut cfg = base_config();
        cfg.commands.push(command_with_validity(Duration::ZERO));
        assert!(matches!(validate(&cfg, true), Err(InsecureError::Invalid(_))));
    }

    #[test]
    fn http_non_loopback_opa_rejected_without_insecure() {
        let mut cfg = base_config();
        cfg.opa_url = Some("http://opa.internal:8181".into());
        assert!(matches!(validate(&cfg, false), Err(InsecureError::Refused(_))));
        cfg.opa_url = Some("http://127.0.0.1:8181".into());
        assert!(validate(&cfg, false).is_ok());
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
            revocation_service_url: None,
            revocation_service_ca_path: None,
        });
        assert!(matches!(
            validate(&cfg, false),
            Err(InsecureError::Refused(_))
        ));
    }

    #[test]
    fn viewer_equal_to_signing_refused_even_with_insecure() {
        let mut cfg = base_config();
        cfg.oidc.viewer_client_id = Some("x".into());
        assert!(matches!(validate(&cfg, true), Err(InsecureError::Invalid(_))));
    }

    #[test]
    fn empty_client_id_refused() {
        let mut cfg = base_config();
        cfg.oidc.signing_client_id = String::new();
        assert!(matches!(validate(&cfg, true), Err(InsecureError::Invalid(_))));
    }

    #[test]
    fn signing_max_age_over_limit_refused() {
        let mut cfg = base_config();
        cfg.oidc.signing_max_age = Some(Duration::from_secs(60 * 60));
        assert!(matches!(validate(&cfg, true), Err(InsecureError::Invalid(_))));
    }

    #[test]
    fn missing_viewer_client_is_allowed() {
        // Agents may run without viewing; `remonce web` checks separately.
        let mut cfg = base_config();
        cfg.oidc.viewer_client_id = None;
        assert!(validate(&cfg, false).is_ok());
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
