//! The agent's published command catalog: what people may request here, and
//! what each command needs before it runs. Deliberately excludes how a
//! command runs (executable, arguments, working directory, environment,
//! policy rule).

use crate::config::Config;
use crate::requirements::Slot;
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
    /// What the command needs before it runs, if its config says.
    pub requirements: Option<RequirementView>,
}

/// A command's requirement as people see it: each slot with policy's
/// description of it.
#[derive(Serialize)]
pub struct RequirementView {
    pub approvals: Vec<SlotView>,
    pub executors: SlotView,
    pub additional_policy: Option<String>,
}

#[derive(Serialize)]
pub struct SlotView {
    /// The slot as written: one predicate and its argument.
    pub slot: Slot,
    /// What it asks for, in policy's words. None when no predicate library
    /// describes it, which also means it accepts no one.
    pub description: Option<String>,
}

fn slot_view(slot: Slot, description: Option<&serde_json::Value>) -> SlotView {
    SlotView {
        slot,
        description: description
            .and_then(|d| d.as_str())
            .filter(|d| !d.is_empty())
            .map(String::from),
    }
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

/// Every configured command's requirement, by command name, as policy
/// reads them.
pub fn requirements(config: &Config) -> serde_json::Map<String, serde_json::Value> {
    config
        .commands
        .iter()
        .filter_map(|c| Some((c.name.clone(), serde_json::to_value(c.requirement()?).ok()?)))
        .collect()
}

/// `descriptions` holds policy's words for each command's slots
/// (`Policy::describe_slots` of `requirements`).
pub fn build(
    config: &Config,
    host: &str,
    descriptions: &serde_json::Map<String, serde_json::Value>,
) -> Catalog {
    let commands = config
        .commands
        .iter()
        .map(|c| {
            let requirements = c.requirement().map(|req| {
                let described = descriptions.get(&c.name);
                let approvals = described.and_then(|d| d.get("approvals"));
                RequirementView {
                    approvals: req
                        .approvals
                        .into_iter()
                        .enumerate()
                        .map(|(i, slot)| slot_view(slot, approvals.and_then(|a| a.get(i))))
                        .collect(),
                    executors: slot_view(req.executors, described.and_then(|d| d.get("executors"))),
                    additional_policy: req.additional_policy,
                }
            });
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
            approvals = [{ groups_in = "dba" }, { made_up = 1 }]
            executors = { anyone = true }
            additional_policy = "Only on db-* hosts"
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
    fn shows_each_requirement_with_policys_words() {
        // What policy is asked to describe: only commands that say.
        let reqs = requirements(&config());
        assert_eq!(reqs.keys().collect::<Vec<_>>(), ["other"]);
        assert_eq!(reqs["other"]["approvals"][0], serde_json::json!({ "groups_in": "dba" }));

        let mut descriptions = serde_json::Map::new();
        descriptions.insert(
            "other".into(),
            serde_json::json!({ "approvals": ["someone in the dba group", ""], "executors": "anyone" }),
        );
        let c = build(&config(), "host-a", &descriptions);
        assert_eq!(c.host, "host-a");
        let secret = &c.commands[0];
        assert!(secret.requirements.is_none());
        assert_eq!(secret.approval_validity_secs, 3600);
        let other = &c.commands[1];
        assert_eq!(other.approval_validity_secs, 7200);
        let req = other.requirements.as_ref().unwrap();
        assert_eq!(req.approvals[0].description.as_deref(), Some("someone in the dba group"));
        // A predicate nobody describes is shown as written, with no words.
        assert_eq!(req.approvals[1].description, None);
        assert_eq!(req.approvals[1].slot.predicate, "made_up");
        assert_eq!(req.executors.description.as_deref(), Some("anyone"));
        assert_eq!(req.additional_policy.as_deref(), Some("Only on db-* hosts"));
        let json = serde_json::to_value(req).unwrap();
        assert_eq!(json["approvals"][0]["slot"], serde_json::json!({ "groups_in": "dba" }));
    }
}
