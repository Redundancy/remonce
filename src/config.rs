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

    /// TLS Configuration (optional).
    pub tls: Option<TlsConfig>,

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

    /// List of allowed files for read-only access.
    #[serde(default)]
    pub files: Vec<FileConfig>,

    /// Agent-specific configuration. Required when running `remonce agent`.
    pub agent: Option<AgentConfig>,
}

/// Configuration for the remote agent. TLS is mandatory — the agent is the
/// one network-facing component, and all command-execution requests must
/// travel over TLS.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct AgentConfig {
    #[serde(default = "default_agent_listen_address")]
    pub listen_address: String,

    /// TLS configuration (Files or ACME). There is no plaintext mode.
    pub tls: TlsConfig,

    /// CORS origins the agent should allow. Empty = no CORS layer.
    #[serde(default)]
    pub cors_allowed_origins: Vec<String>,
}

fn default_agent_listen_address() -> String {
    "0.0.0.0:10022".to_string()
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
pub struct FileConfig {
    /// The allowed path, supports glob patterns (e.g., "/var/log/*.log").
    pub path: String,

    /// An optional alias for the file or glob pattern.
    pub name: Option<String>,

    /// Optional description for the UI.
    pub description: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct TsaConfig {
    /// The URL of the RFC 3161 Timestamp Authority (TSA).
    /// Used to cryptographically timestamp command signatures.
    #[serde(default = "default_tsa_url")]
    pub url: String,

    /// Path to a PEM file containing extra trust anchors for TSA signature
    /// verification. These are *added* to the bundled DigiCert Trusted Root G4
    /// which ships with the binary.
    pub ca_path: Option<String>,

    /// If true, the agent will additionally trust every CA in the operating
    /// system's native trust store for TSA signature verification. This
    /// widens the trust surface to hundreds of CAs and is **insecure**;
    /// the agent refuses to start with this enabled unless `--insecure` is
    /// passed on the command line.
    #[serde(default)]
    pub trust_system_store: bool,
}

impl Default for TsaConfig {
    fn default() -> Self {
        Self {
            url: default_tsa_url(),
            ca_path: None,
            trust_system_store: false,
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

    /// The OPA rule path to query for authorization (e.g., "data.remonce.authz.decision").
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

    /// Maximum age of an approver's signature, measured from their TSA timestamp.
    /// Controls how long a pre-signed command remains usable after the approver signs.
    /// Defaults to 3 days if not specified.
    #[serde(default, with = "humantime_serde")]
    pub approver_max_validity: Option<std::time::Duration>,

    /// Maximum age of the executing-signer's TSA timestamp. In delegated flows this
    /// is the operator's co-sign; in self-execute flows this is the approver's own
    /// signature (acting as both roles). Defaults to 10 minutes if not specified.
    #[serde(default, with = "humantime_serde")]
    pub operator_max_validity: Option<std::time::Duration>,
}

impl CommandConfig {
    pub fn approver_max_validity_or_default(&self) -> std::time::Duration {
        self.approver_max_validity
            .unwrap_or_else(|| std::time::Duration::from_secs(3 * 24 * 60 * 60))
    }

    pub fn operator_max_validity_or_default(&self) -> std::time::Duration {
        self.operator_max_validity
            .unwrap_or_else(|| std::time::Duration::from_secs(10 * 60))
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum TlsConfig {
    /// Use local certificate files.
    Files {
        chain: String,
        key: String,
    },
    /// Use ACME (Let's Encrypt or other).
    Acme {
        domains: Vec<String>,
        email: Option<String>,
        /// Directory to cache certificates.
        cache_dir: String,
        /// ACME Directory URL (e.g., https://acme-staging-v02.api.letsencrypt.org/directory).
        /// If not provided, defaults to Let's Encrypt Production.
        directory_url: Option<String>,
    },
}

impl Config {
    pub fn get_redirect_uri(&self) -> String {
        match &self.oidc.redirect_uri {
            Some(uri) => uri.clone(),
            None => format!("http://{}/oidc/callback", self.listen_address),
        }
    }
}
