use reqwest::Client;
use serde::{Deserialize, Serialize};

/// An approver (or revoker): who signed, their verified claims, and when.
#[derive(Serialize)]
pub struct Signer {
    pub username: String,
    pub claims: serde_json::Value,
    pub signed_at: String,
}

/// Someone identified by their login session rather than a signature.
#[derive(Serialize)]
pub struct Identity {
    pub username: String,
    pub claims: serde_json::Value,
}

/// Input for a decision on a signed request.
#[derive(Serialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum OpaInput {
    /// Run a request: the approvers so far and who is submitting it.
    Execute {
        command: serde_json::Value,
        request_id: String,
        approvers: Vec<Signer>,
        executor: Identity,
        host: String,
    },
    /// Cancel someone else's request.
    Revoke {
        command: serde_json::Value,
        request_id: String,
        approvers: Vec<Signer>,
        revoker: Signer,
        host: String,
    },
}

#[derive(Deserialize)]
pub struct OpaResult {
    pub allow: bool,
    pub reason: String,
}

#[derive(Deserialize)]
struct OpaResponse<T> {
    result: Option<T>,
}

pub async fn check_authorization(
    client: &Client,
    opa_base_url: &str,
    opa_rule: &str,
    input: &OpaInput,
) -> Result<OpaResult, Box<dyn std::error::Error>> {
    let url = format!("{}/v1/{}", opa_base_url, opa_rule.replace('.', "/"));
    let res: OpaResponse<OpaResult> = client
        .post(url)
        .json(&serde_json::json!({ "input": input }))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    Ok(res.result.unwrap_or(OpaResult {
        allow: false,
        reason: "No decision from policy".into(),
    }))
}

/// Ask `data.remonce.authz.allow` about a viewing action (`view_docs`,
/// `read_file`, `view_execution`). An unreachable OPA is an error, not a
/// denial, so callers can tell the two apart.
pub async fn allows_viewing(
    client: &Client,
    opa_base_url: &str,
    input: serde_json::Value,
) -> Result<bool, Box<dyn std::error::Error>> {
    let url = format!("{opa_base_url}/v1/data/remonce/authz/allow");
    let res: OpaResponse<bool> = client
        .post(url)
        .json(&serde_json::json!({ "input": input }))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    Ok(res.result.unwrap_or(false))
}

/// The published requirement documents, by command name. No documents
/// published is an empty map.
pub async fn fetch_requirements(
    client: &Client,
    opa_base_url: &str,
) -> Result<serde_json::Map<String, serde_json::Value>, Box<dyn std::error::Error>> {
    let url = format!("{opa_base_url}/v1/data/remonce/requirements");
    let res: OpaResponse<serde_json::Map<String, serde_json::Value>> =
        client.get(url).send().await?.error_for_status()?.json().await?;
    Ok(res.result.unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signer(name: &str) -> Signer {
        Signer {
            username: name.into(),
            claims: serde_json::json!({ "sub": name, "groups": ["dba"] }),
            signed_at: "2026-04-23T10:00:00Z".into(),
        }
    }

    #[test]
    fn execute_input_shape() {
        let input = OpaInput::Execute {
            command: serde_json::json!({ "command": "test" }),
            request_id: "ab".into(),
            approvers: vec![signer("alice"), signer("bob")],
            executor: Identity {
                username: "carol".into(),
                claims: serde_json::json!({ "sub": "carol" }),
            },
            host: "agent-01".into(),
        };
        let v = serde_json::to_value(&input).unwrap();
        assert_eq!(v["action"], "execute");
        assert_eq!(v["command"]["command"], "test");
        assert_eq!(v["approvers"][1]["username"], "bob");
        assert_eq!(v["executor"]["claims"]["sub"], "carol");
        assert_eq!(v["request_id"], "ab");
        assert!(v.get("approver").is_none() && v.get("operator").is_none());
    }

    #[test]
    fn revoke_input_shape() {
        let input = OpaInput::Revoke {
            command: serde_json::json!({ "command": "test" }),
            request_id: "ab".into(),
            approvers: vec![signer("alice")],
            revoker: signer("bob"),
            host: "agent-01".into(),
        };
        let v = serde_json::to_value(&input).unwrap();
        assert_eq!(v["action"], "revoke");
        assert_eq!(v["revoker"]["username"], "bob");
    }
}
