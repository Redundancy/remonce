//! Validation and substitution of signed command parameters.
//!
//! The signer embeds a `params` object in the command payload (covered by
//! the approver signature). The agent validates every value against the
//! command's declared `ParamConfig` rules and substitutes `{{name}}`
//! placeholders in the configured args template. Everything here is
//! fail-closed: unknown params, missing required params, unmatched
//! placeholders, and rule violations all reject the execution.

use crate::config::{CommandConfig, ParamConfig};
use std::collections::BTreeMap;

/// Default rule for params with no explicit validation: short, conservative
/// charset, and no leading dash (argv flag injection) or leading dot (so no
/// `.`/`..` path segments when a template splices the value into a path).
const DEFAULT_PATTERN: &str = "[A-Za-z0-9_][A-Za-z0-9._-]{0,63}";

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum ParamError {
    #[error("Unknown parameter '{0}'")]
    Unknown(String),
    #[error("Missing required parameter '{0}'")]
    MissingRequired(String),
    #[error("Parameter '{0}' must be a string or number")]
    InvalidType(String),
    #[error("Parameter '{name}' rejected: {reason}")]
    Invalid { name: String, reason: String },
    #[error("Invalid param config for '{name}': {reason}")]
    BadConfig { name: String, reason: String },
    #[error("Unresolved placeholder '{0}' in args template")]
    UnresolvedPlaceholder(String),
}

fn validate_value(cfg: &ParamConfig, value: &str) -> Result<(), ParamError> {
    if let Some(allowed) = &cfg.allowed {
        if allowed.iter().any(|a| a == value) {
            return Ok(());
        }
        return Err(ParamError::Invalid {
            name: cfg.name.clone(),
            reason: format!("'{value}' is not in the allowed list"),
        });
    }

    if cfg.min.is_some() || cfg.max.is_some() {
        let n: i64 = value.parse().map_err(|_| ParamError::Invalid {
            name: cfg.name.clone(),
            reason: format!("'{value}' is not an integer"),
        })?;
        if let Some(min) = cfg.min {
            if n < min {
                return Err(ParamError::Invalid {
                    name: cfg.name.clone(),
                    reason: format!("{n} is below minimum {min}"),
                });
            }
        }
        if let Some(max) = cfg.max {
            if n > max {
                return Err(ParamError::Invalid {
                    name: cfg.name.clone(),
                    reason: format!("{n} is above maximum {max}"),
                });
            }
        }
        return Ok(());
    }

    let pattern = cfg.pattern.as_deref().unwrap_or(DEFAULT_PATTERN);
    let re =
        regex::Regex::new(&format!("^(?:{pattern})$")).map_err(|e| ParamError::BadConfig {
            name: cfg.name.clone(),
            reason: format!("invalid pattern: {e}"),
        })?;
    if !re.is_match(value) {
        return Err(ParamError::Invalid {
            name: cfg.name.clone(),
            reason: "value does not match the allowed pattern".into(),
        });
    }
    Ok(())
}

/// Validate the signed `params` object against the command's declarations and
/// return the resolved name→value map (defaults applied).
pub fn validate_params(
    cmd: &CommandConfig,
    supplied: Option<&serde_json::Value>,
) -> Result<BTreeMap<String, String>, ParamError> {
    let supplied_map: BTreeMap<String, String> = match supplied {
        None | Some(serde_json::Value::Null) => BTreeMap::new(),
        Some(serde_json::Value::Object(obj)) => {
            let mut m = BTreeMap::new();
            for (k, v) in obj {
                let s = match v {
                    serde_json::Value::String(s) => s.clone(),
                    serde_json::Value::Number(n) => n.to_string(),
                    _ => return Err(ParamError::InvalidType(k.clone())),
                };
                m.insert(k.clone(), s);
            }
            m
        }
        Some(_) => return Err(ParamError::InvalidType("params".into())),
    };

    for name in supplied_map.keys() {
        if !cmd.params.iter().any(|p| &p.name == name) {
            return Err(ParamError::Unknown(name.clone()));
        }
    }

    let mut resolved = BTreeMap::new();
    for p in &cmd.params {
        match supplied_map.get(&p.name) {
            Some(v) => {
                validate_value(p, v)?;
                resolved.insert(p.name.clone(), v.clone());
            }
            None => {
                if let Some(d) = &p.default {
                    validate_value(p, d)?;
                    resolved.insert(p.name.clone(), d.clone());
                } else if p.required {
                    return Err(ParamError::MissingRequired(p.name.clone()));
                }
            }
        }
    }
    Ok(resolved)
}

/// Substitute `{{name}}` placeholders in the args template with resolved
/// values. Any placeholder left unresolved (undeclared param, optional param
/// without value) rejects the execution rather than passing `{{...}}`
/// through to the child process.
pub fn render_args(
    template: &[String],
    resolved: &BTreeMap<String, String>,
) -> Result<Vec<String>, ParamError> {
    let placeholder = regex::Regex::new(r"\{\{\s*([A-Za-z_][A-Za-z0-9_]*)\s*\}\}").unwrap();
    let mut out = Vec::with_capacity(template.len());
    for arg in template {
        let mut rendered = String::with_capacity(arg.len());
        let mut last = 0;
        for caps in placeholder.captures_iter(arg) {
            let whole = caps.get(0).unwrap();
            let name = &caps[1];
            let value = resolved
                .get(name)
                .ok_or_else(|| ParamError::UnresolvedPlaceholder(name.to_string()))?;
            rendered.push_str(&arg[last..whole.start()]);
            rendered.push_str(value);
            last = whole.end();
        }
        rendered.push_str(&arg[last..]);
        out.push(rendered);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::CommandConfig;

    fn cmd(params: Vec<ParamConfig>, args: Vec<&str>) -> CommandConfig {
        CommandConfig {
            name: "test".into(),
            description: None,
            opa_rule: "data.remonce.authz.decision".into(),
            executable: Some("svcctl".into()),
            args: args.into_iter().map(String::from).collect(),
            cwd: None,
            approver_max_validity: None,
            operator_max_validity: None,
            command_timeout: None,
            env: Default::default(),
            params,
        }
    }

    fn param(name: &str) -> ParamConfig {
        ParamConfig {
            name: name.into(),
            description: None,
            required: false,
            default: None,
            allowed: None,
            pattern: None,
            min: None,
            max: None,
        }
    }

    #[test]
    fn enum_param_accepts_listed_value_only() {
        let mut p = param("service");
        p.allowed = Some(vec!["nginx".into(), "postgres".into()]);
        let c = cmd(vec![p], vec!["restart", "{{service}}"]);

        let ok = validate_params(&c, Some(&serde_json::json!({"service": "nginx"}))).unwrap();
        assert_eq!(render_args(&c.args, &ok).unwrap(), vec!["restart", "nginx"]);

        let err = validate_params(&c, Some(&serde_json::json!({"service": "sshd"})));
        assert!(matches!(err, Err(ParamError::Invalid { .. })));
    }

    #[test]
    fn default_pattern_rejects_flag_injection_and_shell_chars() {
        let c = cmd(vec![param("target")], vec!["{{target}}"]);
        for bad in ["-rf", "--force", "a;b", "a b", "$(reboot)", "../etc", "..", ".", ".hidden"] {
            let r = validate_params(&c, Some(&serde_json::json!({ "target": bad })));
            assert!(r.is_err(), "expected rejection for {bad:?}");
        }
        let ok = validate_params(&c, Some(&serde_json::json!({"target": "host-01.prod"})));
        assert!(ok.is_ok());
    }

    #[test]
    fn int_range_enforced_and_numbers_accepted() {
        let mut p = param("lines");
        p.min = Some(1);
        p.max = Some(1000);
        let c = cmd(vec![p], vec!["-n", "{{lines}}"]);

        let ok = validate_params(&c, Some(&serde_json::json!({"lines": 100}))).unwrap();
        assert_eq!(ok.get("lines").unwrap(), "100");

        assert!(validate_params(&c, Some(&serde_json::json!({"lines": 0}))).is_err());
        assert!(validate_params(&c, Some(&serde_json::json!({"lines": 5000}))).is_err());
        assert!(validate_params(&c, Some(&serde_json::json!({"lines": "abc"}))).is_err());
    }

    #[test]
    fn unknown_and_missing_required_rejected() {
        let mut p = param("service");
        p.required = true;
        let c = cmd(vec![p], vec!["{{service}}"]);

        assert_eq!(
            validate_params(&c, Some(&serde_json::json!({"extra": "x"}))),
            Err(ParamError::Unknown("extra".into()))
        );
        assert_eq!(
            validate_params(&c, None),
            Err(ParamError::MissingRequired("service".into()))
        );
    }

    #[test]
    fn default_applied_when_omitted() {
        let mut p = param("mode");
        p.allowed = Some(vec!["fast".into(), "safe".into()]);
        p.default = Some("safe".into());
        let c = cmd(vec![p], vec!["--mode={{mode}}"]);

        let resolved = validate_params(&c, None).unwrap();
        assert_eq!(
            render_args(&c.args, &resolved).unwrap(),
            vec!["--mode=safe"]
        );
    }

    #[test]
    fn unresolved_placeholder_rejected() {
        let c = cmd(vec![], vec!["{{ghost}}"]);
        let resolved = validate_params(&c, None).unwrap();
        assert_eq!(
            render_args(&c.args, &resolved),
            Err(ParamError::UnresolvedPlaceholder("ghost".into()))
        );
    }

    #[test]
    fn no_params_no_placeholders_passthrough() {
        let c = cmd(vec![], vec!["status", "--long"]);
        let resolved = validate_params(&c, None).unwrap();
        assert_eq!(
            render_args(&c.args, &resolved).unwrap(),
            vec!["status", "--long"]
        );
    }
}
