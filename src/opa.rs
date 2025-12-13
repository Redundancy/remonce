use reqwest::Client;
use serde::{Deserialize, Serialize};

#[derive(Serialize)]
pub struct OpaInput {
    pub command: serde_json::Value,
    pub jwt: String,
    pub timestamp: String,
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
    command: serde_json::Value,
    jwt: String,
    timestamp: String,
    host: String,
) -> Result<OpaResult, Box<dyn std::error::Error>> {
    let input = OpaInput {
        command,
        jwt,
        timestamp,
        host,
    };

    let opa_url = format!("{}/v1/{}", opa_base_url, opa_rule.replace(".", "/"));
    evaluate(client, &opa_url, &input).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_opa_input_serialization() {
        let input = OpaInput {
            command: serde_json::json!({"cmd": "test"}),
            jwt: "fake.jwt.token".to_string(),
            timestamp: "2023-01-01T00:00:00Z".to_string(),
            host: "test-host".to_string(),
        };

        let json = serde_json::to_string(&input).unwrap();
        let val: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(val["command"]["cmd"], "test");
        assert_eq!(val["jwt"], "fake.jwt.token");
        assert_eq!(val["timestamp"], "2023-01-01T00:00:00Z");
        assert_eq!(val["host"], "test-host");
    }
}
