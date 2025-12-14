use serde::{Deserialize, Serialize};

/// Application configuration structure, verified against `config.toml` at startup.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Config {
    /// OIDC Configuration
    #[serde(default)]
    pub oidc: OidcConfig,

    /// The interface and port to bind the web server to (e.g., "127.0.0.1:8080").
    #[serde(default = "default_listen_address")]
    pub listen_address: String,

    /// Configuration for the RFC 3161 Timestamp Authority (TSA).
    #[serde(default)]
    pub timestamp_authority: TsaConfig,

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
}

fn default_logs_dir() -> String {
    "logs".to_string()
}

fn default_listen_address() -> String {
    "127.0.0.1:8080".to_string()
}

fn default_opa_url() -> String {
    "http://localhost:8181".to_string()
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct TsaConfig {
    /// The URL of the RFC 3161 Timestamp Authority (TSA).
    /// Used to cryptographically timestamp command signatures.
    #[serde(default = "default_tsa_url")]
    pub url: String,

    /// Path to a custom CA certificate (PEM) for verifying the TSA signature.
    /// If not provided, the system's native certificate store will be used.
    pub ca_path: Option<String>,
}

impl Default for TsaConfig {
    fn default() -> Self {
        Self {
            url: default_tsa_url(),
            ca_path: None,
        }
    }
}

fn default_tsa_url() -> String {
    "http://timestamp.digicert.com".to_string()
}

/// OIDC Configuration parameters.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct OidcConfig {
    /// The base URL of the OpenID Connect provider (e.g., Vault).
    /// Used for OIDC discovery (.well-known/openid-configuration).
    pub issuer_url: String,

    /// The OIDC Client ID for this application, registered in Vault.
    pub client_id: String,

    /// The Redirect URI registered with the OIDC provider.
    /// This application will listen for callbacks at this URL.
    /// If not specified, defaults to "http://{listen_address}/oidc/callback".
    pub redirect_uri: Option<String>,
}

// Default implementation for OidcConfig to make it optional in toml if needed, 
// though these fields seem mandatory. 
// However, serde default on the parent struct field requires a Default impl.
// Given they are Strings, we can derive Default but they would be empty. 
// Let's assume the user must provide them in the [oidc] section.
// But to use #[serde(default)] in Config::oidc we need Default.
impl Default for OidcConfig {
    fn default() -> Self {
        Self {
            issuer_url: "".to_string(),
            client_id: "".to_string(),
            redirect_uri: None,
        }
    }
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

    /// Maximum validity duration for a signed command (e.g., "3d", "1h").
    /// Defaults to 3 days if not specified.
    #[serde(default, with = "humantime_serde")]
    pub max_validity: Option<std::time::Duration>,
}

impl Config {
    pub fn get_redirect_uri(&self) -> String {
        match &self.oidc.redirect_uri {
            Some(uri) => uri.clone(),
            None => format!("http://{}/oidc/callback", self.listen_address),
        }
    }
}
