use reqwest::Client;
use serde::{Deserialize, Serialize};

#[derive(Serialize)]
pub struct SignerContext {
    pub username: String,
    pub claims: serde_json::Value,
    pub signed_at: String,
}

#[derive(Serialize)]
pub struct OpaInput {
    /// "execute" for command execution, "revoke" for approval revocation.
    pub action: String,
    pub command: serde_json::Value,
    pub approver: SignerContext,
    pub operator: SignerContext,
    pub self_executed: bool,
    pub host: String,
}

#[derive(Deserialize)]
pub struct OpaResult {
    pub allow: bool,
    pub reason: String,
}

#[derive(Deserialize)]
struct OpaResponse {
    result: Option<OpaResult>,
}

pub async fn evaluate(
    client: &Client,
    opa_url: &str,
    input: &OpaInput,
) -> Result<OpaResult, Box<dyn std::error::Error>> {
    let opa_request = serde_json::json!({ "input": input });
    let opa_res = client.post(opa_url).json(&opa_request).send().await?;
    let opa_decision: OpaResponse = opa_res.json().await?;
    Ok(opa_decision.result.unwrap_or(OpaResult {
        allow: false,
        reason: "No decision from policy".into(),
    }))
}

pub async fn check_authorization(
    client: &Client,
    opa_base_url: &str,
    opa_rule: &str,
    input: OpaInput,
) -> Result<OpaResult, Box<dyn std::error::Error>> {
    let opa_url = format!("{}/v1/{}", opa_base_url, opa_rule.replace(".", "/"));
    evaluate(client, &opa_url, &input).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_opa_input_serialization() {
        let input = OpaInput {
            action: "execute".into(),
            command: serde_json::json!({ "command": "test" }),
            approver: SignerContext {
                username: "alice".into(),
                claims: serde_json::json!({ "sub": "alice", "groups": ["approvers"] }),
                signed_at: "2026-04-23T10:00:00Z".into(),
            },
            operator: SignerContext {
                username: "bob".into(),
                claims: serde_json::json!({ "sub": "bob", "groups": ["noc-l2"] }),
                signed_at: "2026-04-23T10:05:00Z".into(),
            },
            self_executed: false,
            host: "agent-01".into(),
        };

        let json = serde_json::to_string(&input).unwrap();
        let val: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(val["command"]["command"], "test");
        assert_eq!(val["approver"]["username"], "alice");
        assert_eq!(val["operator"]["claims"]["groups"][0], "noc-l2");
        assert_eq!(val["self_executed"], false);
    }
}
