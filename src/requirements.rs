//! Requirement documents: what a command needs before it may run, published
//! by policy so people can see it.
//!
//! Each command's document lives in OPA data at
//! `data.remonce.requirements["<command>"]`. The shipped Rego helper
//! (`policy/lib.rego`) enforces it; the agent's catalog serves it to the UI.
//! Keeping one document for both is what makes the displayed requirement
//! the enforced one.
//!
//! A slot names a predicate and gives it an argument, as in
//! `{"groups_in": "dba"}`. Predicates are Rego functions, each with a
//! description (`policy/predicates.rego`); nothing here knows what any of
//! them means. This module is the typed shape the catalog validates
//! against; it does no enforcement itself.

use serde::{Deserialize, Serialize};

/// Most approval slots a document may have (the Rego helper checks every
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
        const EXAMPLE: &str = r#"{"groups_in": "dba"}"#;
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

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RequirementDoc {
    /// One approval per slot, each from a different person.
    pub approvals: Vec<Slot>,
    /// Who may execute (submit) a fully approved request.
    pub executors: Slot,
    /// Set when policy adds rules beyond this document, so the UI can say
    /// the document isn't the whole story.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub additional_policy: Option<String>,
}

pub fn parse(value: &serde_json::Value) -> Result<RequirementDoc, String> {
    let doc: RequirementDoc =
        serde_json::from_value(value.clone()).map_err(|e| format!("Invalid requirements: {e}"))?;
    if doc.approvals.len() > MAX_SLOTS {
        return Err(format!(
            "Invalid requirements: {} approval slots (at most {MAX_SLOTS})",
            doc.approvals.len()
        ));
    }
    Ok(doc)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shipped_requirements_parse() {
        let data: serde_json::Value =
            serde_json::from_str(include_str!("../policy/requirements.json")).unwrap();
        let reqs = data["remonce"]["requirements"].as_object().expect("requirements object");
        assert!(!reqs.is_empty());
        for (name, doc) in reqs {
            parse(doc).unwrap_or_else(|e| panic!("{name}: {e}"));
        }
    }

    #[test]
    fn a_slot_is_one_predicate_and_its_argument() {
        let doc = parse(&serde_json::json!({
            "approvals": [ { "groups_in": "dba" }, { "claim_equals": ["team", "db"] } ],
            "executors": { "anyone": true },
        }))
        .unwrap();
        assert_eq!(doc.approvals[0].predicate, "groups_in");
        assert_eq!(doc.approvals[1].argument, serde_json::json!(["team", "db"]));
        // And it goes back out in the same shape.
        assert_eq!(
            serde_json::to_value(&doc).unwrap()["executors"],
            serde_json::json!({ "anyone": true })
        );
    }

    #[test]
    fn empty_and_double_slots_are_rejected() {
        for slot in [serde_json::json!({}), serde_json::json!({ "anyone": true, "groups_in": "dba" })] {
            let doc = serde_json::json!({ "approvals": [slot], "executors": { "anyone": true } });
            assert!(parse(&doc).is_err(), "{doc}");
        }
    }

    #[test]
    fn the_old_predicate_form_says_what_replaced_it() {
        let doc = serde_json::json!({
            "approvals": [ { "any_of": [ { "op": "contains", "claim": "groups", "value": "dba" } ] } ],
            "executors": { "any_of": [] },
        });
        let err = parse(&doc).unwrap_err();
        assert!(err.contains("any_of") && err.contains("groups_in"), "{err}");
    }

    #[test]
    fn too_many_slots_rejected() {
        let slot = serde_json::json!({ "anyone": true });
        let doc = serde_json::json!({
            "approvals": vec![slot.clone(); MAX_SLOTS + 1],
            "executors": slot,
        });
        assert!(parse(&doc).is_err());
    }
}
