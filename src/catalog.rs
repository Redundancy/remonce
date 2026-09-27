//! The agent's published command catalog: what people may request here, and
//! what each command needs before it runs. Deliberately excludes how a
//! command runs (executable, arguments, working directory, environment,
//! policy rule).

use crate::config::Config;
use crate::requirements::{self, RequirementDoc};
use serde::Serialize;

#[derive(Serialize)]
pub struct Catalog {
    /// This agent's hostname — the target machine name requests must list.
    pub host: String,
    pub commands: Vec<CommandView>,
}

#[derive(Serialize)]
pub struct CommandView {
    pub name: String,
    pub description: Option<String>,
    pub params: Vec<ParamView>,
    /// How long each approval stays usable.
    pub approval_validity_secs: u64,
    /// The published requirements, if policy has any for this command.
    pub requirements: Option<RequirementDoc>,
    /// Set when a document is published but doesn't parse, so the UI can
    /// say so rather than show no requirements.
    pub requirements_error: Option<String>,
}

#[derive(Serialize)]
pub struct ParamView {
    pub name: String,
    pub description: Option<String>,
    pub required: bool,
    pub default: Option<String>,
    pub allowed: Option<Vec<String>>,
    pub min: Option<i64>,
    pub max: Option<i64>,
}

pub fn build(
    config: &Config,
    host: &str,
    published: &serde_json::Map<String, serde_json::Value>,
) -> Catalog {
    let commands = config
        .commands
        .iter()
        .map(|c| {
            let (requirements, requirements_error) = match published.get(&c.name) {
                None => (None, None),
                Some(doc) => match requirements::parse(doc) {
                    Ok(doc) => (Some(doc), None),
                    Err(e) => (None, Some(e)),
                },
            };
            CommandView {
                name: c.name.clone(),
                description: c.description.clone(),
                params: c
                    .params
                    .iter()
                    .map(|p| ParamView {
                        name: p.name.clone(),
                        description: p.description.clone(),
                        required: p.required,
                        default: p.default.clone(),
                        allowed: p.allowed.clone(),
                        min: p.min,
                        max: p.max,
                    })
                    .collect(),
                approval_validity_secs: c.approval_validity_or_default().as_secs(),
                requirements,
                requirements_error,
            }
        })
        .collect();
    Catalog {
        host: host.to_string(),
        commands,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> Config {
        crate::config::parse(
            r#"
            [[commands]]
            name = "secret-thing"
            description = "Does a thing"
            opa_rule = "data.hidden.rule"
            executable = "/opt/tools/SECRET_BINARY"
            args = ["--token", "ARG_SECRET"]
            cwd = "/srv/SECRET_DIR"
            env = { API_KEY = "ENV_SECRET" }

            [[commands]]
            name = "other"
            opa_rule = "data.x"
            approval_validity = "2h"
            "#,
        )
        .unwrap()
    }

    #[test]
    fn never_exposes_how_a_command_runs() {
        let json = serde_json::to_string(&build(&config(), "host-a", &Default::default())).unwrap();
        for secret in ["SECRET_BINARY", "ARG_SECRET", "SECRET_DIR", "ENV_SECRET", "hidden.rule"] {
            assert!(!json.contains(secret), "catalog leaks {secret}: {json}");
        }
        assert!(json.contains("Does a thing"));
    }

    #[test]
    fn attaches_requirements_by_name() {
        let mut published = serde_json::Map::new();
        published.insert(
            "other".into(),
            serde_json::json!({ "approvals": [], "executors": { "any_of": [] } }),
        );
        published.insert("secret-thing".into(), serde_json::json!({ "approvals": "bad" }));
        let c = build(&config(), "host-a", &published);
        assert_eq!(c.host, "host-a");
        let secret = &c.commands[0];
        assert!(secret.requirements.is_none() && secret.requirements_error.is_some());
        assert_eq!(secret.approval_validity_secs, 3600);
        let other = &c.commands[1];
        assert!(other.requirements.is_some());
        assert_eq!(other.approval_validity_secs, 7200);
    }
}
