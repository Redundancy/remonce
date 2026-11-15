//! Requirements: what a command needs before it may run.
//!
//! A command's requirement is part of its entry in the agent's config:
//! `approvals`, one slot per approval, and `executors`, who may run it.
//! The agent sends it to policy with every execution decision
//! (`input.requirement`), where the shipped Rego helper (`policy/lib.rego`)
//! enforces it, and serves it in its catalog. Keeping one requirement for
//! both is what makes the displayed requirement the enforced one.
//!
//! A slot names a predicate and gives it an argument, as in
//! `{ groups_in = "dba" }`. Predicates are Rego functions, each with a
//! description (`policy/predicates.rego`); nothing here knows what any of
//! them means. This module is the typed shape; it does no enforcement.

use serde::{Deserialize, Serialize};

/// Most approval slots a requirement may have (the Rego helper checks every
/// subset of slots, so this bounds its work).
pub const MAX_SLOTS: usize = 8;

type JsonObject = serde_json::Map<String, serde_json::Value>;

/// Who may fill a role: one predicate and its argument. An empty slot, or
/// one naming two predicates, is rejected here (and accepts no one in
/// Rego), so a typo can't open a slot up.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(try_from = "JsonObject", into = "JsonObject")]
pub struct Slot {
    pub predicate: String,
    pub argument: serde_json::Value,
}

impl TryFrom<JsonObject> for Slot {
    type Error = String;

    fn try_from(map: JsonObject) -> Result<Self, String> {
        const EXAMPLE: &str = r#"{ groups_in = "dba" }"#;
        if map.contains_key("any_of") {
            return Err(format!(
                "the `any_of` form is no longer supported: name one predicate and its argument, as in {EXAMPLE}"
            ));
        }
        let mut entries = map.into_iter();
        match (entries.next(), entries.next()) {
            (Some((predicate, argument)), None) => Ok(Slot { predicate, argument }),
            (None, _) => Err(format!("a slot names one predicate and its argument, as in {EXAMPLE}")),
            (Some((first, _)), Some((second, _))) => Err(format!(
                "a slot names one predicate, not several (`{first}`, `{second}`): use one, as in {EXAMPLE}"
            )),
        }
    }
}

impl From<Slot> for JsonObject {
    fn from(slot: Slot) -> Self {
        JsonObject::from_iter([(slot.predicate, slot.argument)])
    }
}

/// A command's requirement, as policy receives it.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Requirement {
    /// One approval per slot, each from a different person.
    pub approvals: Vec<Slot>,
    /// Who may execute (submit) a fully approved request.
    pub executors: Slot,
    /// Set when policy adds rules beyond the slots, so the UI can say they
    /// aren't the whole story.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub additional_policy: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(value: serde_json::Value) -> Result<Requirement, String> {
        serde_json::from_value(value).map_err(|e| e.to_string())
    }

    #[test]
    fn a_slot_is_one_predicate_and_its_argument() {
        let req = parse(serde_json::json!({
            "approvals": [ { "groups_in": "dba" }, { "claim_equals": ["team", "db"] } ],
            "executors": { "anyone": true },
        }))
        .unwrap();
        assert_eq!(req.approvals[0].predicate, "groups_in");
        assert_eq!(req.approvals[1].argument, serde_json::json!(["team", "db"]));
        // And it goes back out in the same shape, as policy will read it.
        assert_eq!(
            serde_json::to_value(&req).unwrap(),
            serde_json::json!({
                "approvals": [ { "groups_in": "dba" }, { "claim_equals": ["team", "db"] } ],
                "executors": { "anyone": true },
            })
        );
    }

    #[test]
    fn empty_and_double_slots_are_rejected() {
        for slot in [serde_json::json!({}), serde_json::json!({ "anyone": true, "groups_in": "dba" })] {
            let req = serde_json::json!({ "approvals": [slot], "executors": { "anyone": true } });
            assert!(parse(req.clone()).is_err(), "{req}");
        }
    }

    #[test]
    fn the_old_predicate_form_says_what_replaced_it() {
        let err = parse(serde_json::json!({
            "approvals": [ { "any_of": [ { "op": "contains", "claim": "groups", "value": "dba" } ] } ],
            "executors": { "any_of": [] },
        }))
        .unwrap_err();
        assert!(err.contains("any_of") && err.contains("groups_in"), "{err}");
    }
}
