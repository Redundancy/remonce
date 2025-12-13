use serde::{Deserialize, Serialize};

/// Application configuration structure, verified against `config.toml` at startup.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Config {
    /// The base URL of the OpenID Connect provider (e.g., Vault).
    /// Used for OIDC discovery (.well-known/openid-configuration).
    pub issuer_url: String,

    /// The OIDC Client ID for this application, registered in Vault.
    pub client_id: String,

    /// The Redirect URI registered with the OIDC provider.
    /// This application will listen for callbacks at this URL.
    /// If not specified, defaults to "http://{listen_address}/oidc/callback".
    pub redirect_uri: Option<String>,

    /// The interface and port to bind the web server to (e.g., "127.0.0.1:8080").
    #[serde(default = "default_listen_address")]
    pub listen_address: String,

    /// The URL of the RFC 3161 Timestamp Authority (TSA).
    /// Used to cryptographically timestamp command signatures.
    #[serde(default = "default_tsa_url")]
    pub tsa_url: String,

    /// List of commands that the agent is allowed to execute.
    #[serde(default)]
    pub commands: Vec<CommandConfig>,

    /// Directory where execution logs will be stored.
    /// Defaults to "logs" if not specified.
    #[serde(default = "default_logs_dir")]
    pub logs_dir: String,

    /// The URL of the Open Policy Agent (OPA) server.
    /// Used for authorization decisions (e.g., "http://localhost:8181").
    #[serde(default = "default_opa_url")]
    pub opa_url: String,

    /// Path to a custom CA certificate (PEM) for verifying the TSA signature.
    /// If not provided, the system's native certificate store will be used.
    pub tsa_ca_path: Option<String>,
}

fn default_logs_dir() -> String {
    "logs".to_string()
}

fn default_listen_address() -> String {
    "127.0.0.1:8080".to_string()
}

fn default_tsa_url() -> String {
    "http://timestamp.digicert.com".to_string()
}

fn default_opa_url() -> String {
    "http://localhost:8181".to_string()
}

/// Configuration for a specific executable command.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct CommandConfig {
    /// The unique reference name for this command (used in API requests).
    pub name: String,

    /// A human-readable description of what this command does.
    pub description: Option<String>,

    /// The OPA rule path to query for authorization (e.g., "data.remonse.authz.decision").
    pub opa_rule: String,

    /// The actual executable binary to run.
    /// If not provided, defaults to the `name` field.
    pub executable: Option<String>,

    /// List of arguments to pass to the executable.
    #[serde(default)]
    pub args: Vec<String>,

    /// The working directory for command execution.
    /// Defaults to the agent's current working directory if not specified.
    pub cwd: Option<String>,
}

impl Config {
    pub fn get_redirect_uri(&self) -> String {
        match &self.redirect_uri {
            Some(uri) => uri.clone(),
            None => format!("http://{}/oidc/callback", self.listen_address),
        }
    }
}
