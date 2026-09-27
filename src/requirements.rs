//! Requirement documents: what a command needs before it may run, published
//! by policy so people can see it.
//!
//! Each command's document lives in OPA data at
//! `data.remonce.requirements["<command>"]`. The shipped Rego helper
//! (`policy/lib.rego`) enforces it; the agent's catalog serves it to the UI.
//! Keeping one document for both is what makes the displayed requirement
//! the enforced one. This module is the typed schema the catalog validates
//! against; it does no enforcement itself.

use serde::{Deserialize, Serialize};

/// Most approval slots a document may have (the Rego helper checks every
/// subset of slots, so this bounds its work).
pub const MAX_SLOTS: usize = 8;

/// A predicate over OIDC claims.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum ClaimPredicate {
    /// The claim equals `value`.
    Equals {
        claim: String,
        value: serde_json::Value,
    },
    /// The claim is an array containing `value`.
    Contains {
        claim: String,
        value: serde_json::Value,
    },
}

/// Who may fill a role: anyone matching at least one predicate. `any_of`
/// is required: an empty list means anyone, and a missing one is rejected
/// here (and matches no one in Rego), so a typo can't open a slot up.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Slot {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub any_of: Vec<ClaimPredicate>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RequirementDoc {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
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
    fn missing_any_of_is_rejected() {
        let doc = serde_json::json!({
            "approvals": [ { "description": "typo", "anyof": [] } ],
            "executors": { "any_of": [] },
        });
        assert!(parse(&doc).is_err());
    }

    #[test]
    fn too_many_slots_rejected() {
        let slot = serde_json::json!({ "any_of": [] });
        let doc = serde_json::json!({
            "approvals": vec![slot.clone(); MAX_SLOTS + 1],
            "executors": slot,
        });
        assert!(parse(&doc).is_err());
    }
}
