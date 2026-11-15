use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Application configuration structure, verified against `config.toml` at startup.
#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
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

    /// Where policy decisions come from. Set one of these, or neither:
    ///
    /// `policy_dir`: a directory of Rego (`.rego`) and data (`.json`) files,
    /// laid out as for `opa run`, evaluated inside remonce. The default,
    /// with `DEFAULT_POLICY_DIR`.
    pub policy_dir: Option<String>,
    /// `opa_url`: an OPA server to ask instead (e.g. "http://localhost:8181").
    pub opa_url: Option<String>,

    /// List of allowed files for read-only access.
    #[serde(default)]
    pub files: Vec<FileConfig>,

    /// Agent-specific configuration. Required when running `remonce agent`.
    pub agent: Option<AgentConfig>,

    /// Default agent URL the signer UI submits bundles to. Must be https.
    /// The browser never talks to the agent directly — the loopback web tier
    /// proxies all agent traffic so cert trust is handled server-side.
    #[serde(default = "default_agent_url")]
    pub agent_url: String,

    /// Optional PEM file with extra root CA(s) trusted when the web tier
    /// connects to the agent (e.g. a self-signed agent cert). Added on top
    /// of the system trust store.
    pub agent_ca_path: Option<String>,

    /// Additional agents the signer UI may target besides `agent_url` (and
    /// the user's agents file, see `known_agents`). The signer refuses any
    /// other browser-supplied agent URL, since it sends the user's ID token
    /// and approvals to whichever agent is chosen.
    #[serde(default)]
    pub allowed_agent_urls: Vec<String>,

    /// Central revocation service configuration. Required when running
    /// `remonce revocation-service`.
    pub revocation_service: Option<RevocationServiceConfig>,
}

fn default_agent_url() -> String {
    "https://localhost:10022".to_string()
}

/// Configuration for the remote agent. TLS is mandatory — the agent is the
/// one network-facing component, and all command-execution requests must
/// travel over TLS.
#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct AgentConfig {
    #[serde(default = "default_agent_listen_address")]
    pub listen_address: String,

    /// TLS configuration (Files or ACME). There is no plaintext mode.
    pub tls: TlsConfig,

    /// CORS origins the agent should allow. Empty = no CORS layer.
    #[serde(default)]
    pub cors_allowed_origins: Vec<String>,

    /// Central revocation service this agent consults before every
    /// execution. Must be https. FAIL-CLOSED: if set and the service is
    /// unreachable, executions are denied.
    pub revocation_service_url: Option<String>,

    /// Optional PEM file with extra root CA(s) trusted when connecting to
    /// the revocation service (e.g. a self-signed cert). Added on top of
    /// the system trust store.
    pub revocation_service_ca_path: Option<String>,

    /// Directory where the agent keeps what must survive a restart: which
    /// requests it has run (replay protection) and which were revoked here.
    /// Unset, both live in memory, and a restart forgets them — a request
    /// that already ran can then run again while its approvals last.
    pub state_dir: Option<String>,

    /// File the agent appends its audit records to (one JSON object per
    /// line), as well as printing them on stdout.
    pub audit_log_path: Option<String>,
}

fn default_agent_listen_address() -> String {
    "0.0.0.0:10022".to_string()
}

/// Configuration for the central revocation service
/// (`remonce revocation-service`). TLS is mandatory.
#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct RevocationServiceConfig {
    #[serde(default = "default_revocation_listen_address")]
    pub listen_address: String,

    /// TLS configuration (Files or ACME). There is no plaintext mode.
    pub tls: TlsConfig,

    /// JSONL file persisting revocations across restarts.
    #[serde(default = "default_revocation_persist_path")]
    pub persist_path: String,

    /// Minimum time a revocation is kept (counted from the revocation, or the
    /// request's latest approval if later), whatever this service's own
    /// `[[commands]]` say. Must be at least the longest `approval_validity`
    /// any agent allows.
    /// Default: 30 days.
    #[serde(default, with = "humantime_serde")]
    pub retention: Option<std::time::Duration>,
}

impl RevocationServiceConfig {
    pub fn retention_or_default(&self) -> std::time::Duration {
        self.retention
            .unwrap_or(std::time::Duration::from_secs(30 * 24 * 60 * 60))
    }
}

fn default_revocation_listen_address() -> String {
    "0.0.0.0:10023".to_string()
}

fn default_revocation_persist_path() -> String {
    "revocations.jsonl".to_string()
}

fn default_logs_dir() -> String {
    "logs".to_string()
}

fn default_listen_address() -> String {
    "127.0.0.1:8080".to_string()
}

/// Where the embedded engine reads policy when neither `policy_dir` nor
/// `opa_url` is set.
pub const DEFAULT_POLICY_DIR: &str = "policy";

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct FileConfig {
    /// The allowed path, supports glob patterns (e.g., "/var/log/*.log").
    pub path: String,

    /// An optional alias for the file or glob pattern.
    pub name: Option<String>,

    /// Optional description for the UI.
    pub description: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
pub struct OidcConfig {
    /// The base URL of the OpenID Connect provider (e.g., Vault).
    /// Used for OIDC discovery (.well-known/openid-configuration).
    pub issuer_url: String,

    /// The *signing* OIDC client. Every approval and revocation is
    /// made with a fresh login to this client; agents only accept its tokens
    /// on the signing path, never as bearer credentials. (`client_id` is
    /// accepted as an older name.)
    #[serde(alias = "client_id")]
    pub signing_client_id: String,

    /// The *viewer* OIDC client, used for browsing (files, execution logs).
    /// Its tokens are bearer credentials accepted only by the agent's
    /// read-only endpoints. Must differ from `signing_client_id`. Required by
    /// `remonce web`; agents without it refuse file/log viewing.
    #[serde(default)]
    pub viewer_client_id: Option<String>,

    /// `max_age` sent on every signing authorization, forcing the user to
    /// re-authenticate. Defaults to 1s: effectively "always", and portable —
    /// some IdPs (e.g. Vault) reject `max_age=0`. Must not exceed
    /// `security::MAX_AUTH_AGE`, or the resulting signatures can never verify.
    #[serde(default, with = "humantime_serde")]
    pub signing_max_age: Option<std::time::Duration>,

    /// Also send `prompt=login` on signing authorizations, for IdPs that
    /// ignore `max_age`.
    #[serde(default)]
    pub signing_prompt_login: bool,

    /// The Redirect URI registered with the OIDC provider (for both clients).
    /// This application will listen for callbacks at this URL.
    /// If not specified, defaults to "http://{listen_address}/oidc/callback".
    pub redirect_uri: Option<String>,
}

impl OidcConfig {
    /// `max_age` for signing logins (default 1s: always re-authenticate).
    pub fn signing_max_age_or_default(&self) -> std::time::Duration {
        self.signing_max_age.unwrap_or(std::time::Duration::from_secs(1))
    }
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
            signing_client_id: "".to_string(),
            viewer_client_id: None,
            signing_max_age: None,
            signing_prompt_login: false,
            redirect_uri: None,
        }
    }
}

/// Configuration for a specific executable command.
#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct CommandConfig {
    /// The unique reference name for this command (used in API requests).
    pub name: String,

    /// A human-readable description of what this command does.
    pub description: Option<String>,

    /// The policy rule asked whether a request for this command may run.
    /// Defaults to the shipped policy's decision, `DEFAULT_OPA_RULE`.
    #[serde(default = "default_opa_rule")]
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

    /// How long each approval of a request stays usable, measured from the
    /// approver's login. A request runs only while all of its approvals are
    /// within this window. Defaults to 1 hour.
    #[serde(default, with = "humantime_serde")]
    pub approval_validity: Option<std::time::Duration>,

    /// Wall-clock timeout for the spawned process. Once exceeded, the agent
    /// kills it, along with every process it started, and writes a "TIMEOUT"
    /// trailer into the execution log. Defaults to 5 minutes if not specified.
    #[serde(default, with = "humantime_serde")]
    pub command_timeout: Option<std::time::Duration>,

    /// How much of the command's output (stdout and stderr together) is
    /// kept in its run log, in bytes. Past this the log notes the cut and
    /// the rest is discarded; the command keeps running. Defaults to 64 MiB.
    pub max_output_bytes: Option<u64>,

    /// Environment variables passed to the spawned process. The agent calls
    /// `env_clear()` before applying these — no parent-process env leaks
    /// through. Empty by default; add `PATH` here if your executable needs it.
    #[serde(default)]
    pub env: std::collections::BTreeMap<String, String>,

    /// Parameters the signer may supply with this command. Each `{{name}}`
    /// placeholder in `args` is replaced with the validated value at
    /// execution time. Validation is fail-closed: a param with no explicit
    /// rule gets a conservative default pattern (no leading dash, short,
    /// alphanumeric-ish). See `crate::params`.
    #[serde(default)]
    pub params: Vec<ParamConfig>,
}

/// A declared, validated parameter for a command.
#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct ParamConfig {
    /// Placeholder name; must match `[A-Za-z_][A-Za-z0-9_]*`.
    pub name: String,

    /// Human-readable description for the UI.
    pub description: Option<String>,

    /// Whether the signer must supply a value (no `default` fallback).
    #[serde(default)]
    pub required: bool,

    /// Value used when the signer omits the param. Must itself pass validation.
    pub default: Option<String>,

    /// Validation: exact allow-list of values. Takes precedence over `pattern`.
    pub allowed: Option<Vec<String>>,

    /// Validation: regex the full value must match (implicitly anchored).
    /// CAUTION: if your pattern admits values starting with `-`, a signer can
    /// inject flags into the executable's argv.
    pub pattern: Option<String>,

    /// Validation: integer range (value must parse as i64 within bounds).
    pub min: Option<i64>,
    pub max: Option<i64>,
}

/// The shipped policy's decision rule: what a command's `opa_rule` is when it
/// doesn't set one.
pub const DEFAULT_OPA_RULE: &str = "data.remonce.authz.decision";

fn default_opa_rule() -> String {
    DEFAULT_OPA_RULE.to_string()
}

pub const DEFAULT_APPROVAL_VALIDITY: std::time::Duration = std::time::Duration::from_secs(60 * 60);
pub const DEFAULT_MAX_OUTPUT_BYTES: u64 = 64 * 1024 * 1024;

impl CommandConfig {
    pub fn approval_validity_or_default(&self) -> std::time::Duration {
        self.approval_validity.unwrap_or(DEFAULT_APPROVAL_VALIDITY)
    }

    pub fn max_output_bytes_or_default(&self) -> u64 {
        self.max_output_bytes.unwrap_or(DEFAULT_MAX_OUTPUT_BYTES)
    }

    pub fn command_timeout_or_default(&self) -> std::time::Duration {
        self.command_timeout
            .unwrap_or_else(|| std::time::Duration::from_secs(5 * 60))
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
        /// How the CA validates the domains. Default: TLS-ALPN-01, which
        /// the CA checks on port 443.
        #[serde(default)]
        challenge: AcmeChallenge,
        /// For HTTP-01: where to answer the CA while a certificate is being
        /// issued. Open only then. Default: "0.0.0.0:80".
        http_challenge_address: Option<String>,
    },
}

#[derive(Debug, Deserialize, Serialize, Clone, Copy, Default, PartialEq, Eq)]
pub enum AcmeChallenge {
    /// Validated on port 443 of each domain; the listener must be there
    /// (or 443 forwarded to it).
    #[default]
    #[serde(rename = "tls-alpn-01")]
    TlsAlpn01,
    /// Validated on port 80 of each domain, opened only while a certificate
    /// is being issued; the listener itself can use any port.
    #[serde(rename = "http-01")]
    Http01,
}

/// Command keys removed in the move to independent approvals, with what to
/// use instead. `deny_unknown_fields` would reject them anyway; this names
/// the replacement.
const REMOVED_COMMAND_KEYS: &[(&str, &str)] = &[
    (
        "approver_max_validity",
        "replaced by approval_validity (how long each approval stays usable)",
    ),
    (
        "operator_max_validity",
        "the operator role is gone; use approval_validity",
    ),
];

/// The directory of drop-in files, beside the main configuration file.
pub const DROP_IN_DIR: &str = "config.d";

/// Top-level lists that add up across files. Every other setting may be set
/// in one file only.
const ADDITIVE_LISTS: &[&str] = &["commands", "files"];

fn check_removed_keys(table: &toml::Table) -> Result<(), String> {
    let Some(commands) = table.get("commands").and_then(|c| c.as_array()) else {
        return Ok(());
    };
    for cmd in commands {
        let name = cmd.get("name").and_then(|n| n.as_str()).unwrap_or("?");
        for (key, hint) in REMOVED_COMMAND_KEYS {
            if cmd.get(*key).is_some() {
                return Err(format!("command '{name}': `{key}` is no longer supported: {hint}"));
            }
        }
    }
    Ok(())
}

/// A command name may be offered once: requests name a command, and two
/// definitions would leave which one runs to the order of the files.
fn check_duplicate_commands(config: &Config) -> Result<(), String> {
    let mut seen = std::collections::BTreeSet::new();
    for c in &config.commands {
        if !seen.insert(c.name.as_str()) {
            return Err(format!("command '{}' is defined more than once", c.name));
        }
    }
    Ok(())
}

/// Parse configuration text.
pub fn parse(text: &str) -> Result<Config, String> {
    if let Ok(table) = text.parse::<toml::Table>() {
        check_removed_keys(&table)?;
    }
    let config: Config = toml::from_str(text).map_err(|e| e.to_string())?;
    check_duplicate_commands(&config)?;
    Ok(config)
}

/// Read the configuration: the file at `path`, then every `.toml` file in
/// the `config.d` directory beside it, in name order.
///
/// Drop-in files use the same settings as the main file. `[[commands]]` and
/// `[[files]]` add up across files, so one file can hold one command. Tables
/// such as `[agent]` may be filled in from several files. Any single setting
/// given in two files is an error naming both, as is a command name defined
/// twice: nothing overrides anything.
pub fn load(path: &str) -> Result<Config, String> {
    let main = Path::new(path);
    let text = read(main)?;
    let drop_ins = drop_in_files(main)?;
    if drop_ins.is_empty() {
        return parse(&text).map_err(|e| format!("Failed to parse {path}: {e}"));
    }

    let mut merged = toml::Table::new();
    let mut origins = BTreeMap::new();
    let mut command_origins: BTreeMap<String, PathBuf> = BTreeMap::new();
    let mut texts = vec![(main.to_path_buf(), text)];
    for file in &drop_ins {
        texts.push((file.clone(), read(file)?));
    }
    for (file, text) in &texts {
        let table: toml::Table = text
            .parse()
            .map_err(|e| format!("Failed to parse {}: {e}", file.display()))?;
        check_removed_keys(&table).map_err(|e| format!("{}: {e}", file.display()))?;
        for cmd in table.get("commands").and_then(|c| c.as_array()).into_iter().flatten() {
            let Some(name) = cmd.get("name").and_then(|n| n.as_str()) else {
                continue;
            };
            if let Some(first) = command_origins.insert(name.to_string(), file.clone()) {
                return Err(format!(
                    "command '{name}' is defined in both {} and {}",
                    first.display(),
                    file.display()
                ));
            }
        }
        merge_tables(&mut merged, table, "", file, &mut origins)?;
    }

    let config: Config = merged.try_into().map_err(|e: toml::de::Error| {
        // The merged tables have lost their line numbers. If one file is
        // wrong by itself, say which and where.
        for (file, text) in &texts {
            if let Err(own) = toml::from_str::<Config>(text)
                && own.message().starts_with("unknown field")
            {
                return format!("Failed to parse {}: {own}", file.display());
            }
        }
        format!("Failed to parse {path} with the files in {}: {e}", drop_in_dir(main).display())
    })?;
    tracing::info!(
        files = drop_ins.len(),
        dir = %drop_in_dir(main).display(),
        "Read configuration drop-ins"
    );
    Ok(config)
}

fn read(path: &Path) -> Result<String, String> {
    std::fs::read_to_string(path).map_err(|e| format!("Failed to read {}: {e}", path.display()))
}

fn drop_in_dir(main: &Path) -> PathBuf {
    main.parent().unwrap_or(Path::new("")).join(DROP_IN_DIR)
}

/// The `.toml` files in the drop-in directory, in name order. No directory
/// means no drop-ins; other files in it (backups, editor swap files) are
/// ignored.
fn drop_in_files(main: &Path) -> Result<Vec<PathBuf>, String> {
    let dir = drop_in_dir(main);
    let entries = match std::fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(format!("Failed to read {}: {e}", dir.display())),
    };
    let mut files = Vec::new();
    for entry in entries {
        let path = entry.map_err(|e| format!("Failed to read {}: {e}", dir.display()))?.path();
        let hidden = path.file_name().is_some_and(|n| n.to_string_lossy().starts_with('.'));
        if path.is_file() && !hidden && path.extension().is_some_and(|e| e == "toml") {
            files.push(path);
        }
    }
    files.sort();
    Ok(files)
}

/// Record which file set every value under `value`, by dotted path.
fn record_origins(value: &toml::Value, path: &str, file: &Path, origins: &mut BTreeMap<String, PathBuf>) {
    match value {
        toml::Value::Table(t) => {
            for (k, v) in t {
                record_origins(v, &format!("{path}.{k}"), file, origins);
            }
        }
        _ => {
            origins.insert(path.to_string(), file.to_path_buf());
        }
    }
}

/// Merge `from` (read from `file`) into `into`. Tables merge key by key and
/// the additive lists are appended to; anything else already present is a
/// conflict.
fn merge_tables(
    into: &mut toml::Table,
    from: toml::Table,
    prefix: &str,
    file: &Path,
    origins: &mut BTreeMap<String, PathBuf>,
) -> Result<(), String> {
    for (key, value) in from {
        let path = if prefix.is_empty() { key.clone() } else { format!("{prefix}.{key}") };
        match (into.get_mut(&key), value) {
            (None, value) => {
                record_origins(&value, &path, file, origins);
                into.insert(key, value);
            }
            (Some(toml::Value::Array(have)), toml::Value::Array(more))
                if prefix.is_empty() && ADDITIVE_LISTS.contains(&key.as_str()) =>
            {
                have.extend(more);
            }
            (Some(toml::Value::Table(have)), toml::Value::Table(more)) => {
                merge_tables(have, more, &path, file, origins)?;
            }
            (Some(_), _) => {
                let first = origins
                    .iter()
                    .find(|(p, _)| *p == &path || p.starts_with(&format!("{path}.")))
                    .map(|(_, f)| f.display().to_string())
                    .unwrap_or_else(|| "an earlier file".into());
                return Err(format!(
                    "`{path}` is set in both {first} and {}; a setting may be given in one file only",
                    file.display()
                ));
            }
        }
    }
    Ok(())
}

impl Config {
    pub fn get_redirect_uri(&self) -> String {
        match &self.oidc.redirect_uri {
            Some(uri) => uri.clone(),
            None => format!("http://{}/oidc/callback", self.listen_address),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shipped_config_parses() {
        let cfg = parse(include_str!("../config.toml"))
            .expect("config.toml must parse with deny_unknown_fields");
        let test = cfg.commands.iter().find(|c| c.name == "test").unwrap();
        assert_eq!(
            test.approval_validity_or_default(),
            std::time::Duration::from_secs(24 * 60 * 60)
        );
        let other = cfg.commands.iter().find(|c| c.name == "fail").unwrap();
        assert_eq!(other.approval_validity_or_default(), DEFAULT_APPROVAL_VALIDITY);
    }

    #[test]
    fn signing_client_id_accepts_its_older_name() {
        for key in ["signing_client_id", "client_id"] {
            let cfg = parse(&format!("[oidc]
issuer_url = \"https://idp.example\"
{key} = \"abc\"
")).unwrap();
            assert_eq!(cfg.oidc.signing_client_id, "abc", "{key}");
        }
    }

    #[test]
    fn removed_keys_explain_their_replacement() {
        for key in ["approver_max_validity", "operator_max_validity"] {
            let text = format!("[[commands]]\nname = \"x\"\nopa_rule = \"data.x\"\n{key} = \"1d\"\n");
            let err = parse(&text).unwrap_err();
            assert!(err.contains(key) && err.contains("approval_validity"), "{err}");
        }
    }

    #[test]
    fn opa_rule_defaults_to_the_shipped_decision() {
        let cfg = parse("[[commands]]\nname = \"x\"\n").unwrap();
        assert_eq!(cfg.commands[0].opa_rule, DEFAULT_OPA_RULE);
    }

    #[test]
    fn a_command_defined_twice_is_rejected() {
        let err = parse("[[commands]]\nname = \"x\"\n\n[[commands]]\nname = \"x\"\n").unwrap_err();
        assert!(err.contains("'x'") && err.contains("more than once"), "{err}");
    }

    /// A fresh directory holding `config.toml` and the given drop-ins.
    fn config_dir(tag: &str, main: &str, drop_ins: &[(&str, &str)]) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("remonce-config-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("config.toml"), main).unwrap();
        if !drop_ins.is_empty() {
            std::fs::create_dir_all(dir.join(DROP_IN_DIR)).unwrap();
        }
        for (name, text) in drop_ins {
            std::fs::write(dir.join(DROP_IN_DIR).join(name), text).unwrap();
        }
        dir
    }

    fn load_dir(dir: &Path) -> Result<Config, String> {
        let result = load(&dir.join("config.toml").to_string_lossy());
        let _ = std::fs::remove_dir_all(dir);
        result
    }

    const MAIN: &str = "[oidc]\nissuer_url = \"https://idp.example\"\nsigning_client_id = \"s\"\n\n\
        [[commands]]\nname = \"base\"\n";

    #[test]
    fn drop_ins_add_commands_and_files_in_name_order() {
        let dir = config_dir(
            "adds",
            MAIN,
            &[
                ("20-restart.toml", "[[commands]]\nname = \"restart\"\nexecutable = \"systemctl\"\n\n[[commands.params]]\nname = \"service\"\n"),
                ("10-logs.toml", "[[files]]\npath = \"/var/log/*.log\"\n\n[[commands]]\nname = \"tail\"\n"),
                ("notes.txt", "not configuration"),
                (".hidden.toml", "[[commands]]\nname = \"hidden\"\n"),
            ],
        );
        let cfg = load_dir(&dir).unwrap();
        let names: Vec<_> = cfg.commands.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(names, ["base", "tail", "restart"]);
        assert_eq!(cfg.commands[2].params[0].name, "service");
        assert_eq!(cfg.files.len(), 1);
        assert_eq!(cfg.oidc.signing_client_id, "s");
    }

    #[test]
    fn a_table_can_be_filled_in_from_several_files() {
        let dir = config_dir(
            "tables",
            "[agent]\nlisten_address = \"0.0.0.0:443\"\n",
            &[("tls.toml", "[agent.tls]\nmode = \"files\"\nchain = \"c.pem\"\nkey = \"k.pem\"\n")],
        );
        let agent = load_dir(&dir).unwrap().agent.unwrap();
        assert_eq!(agent.listen_address, "0.0.0.0:443");
        assert!(matches!(agent.tls, TlsConfig::Files { .. }));
    }

    #[test]
    fn a_setting_given_in_two_files_is_rejected() {
        let dir = config_dir("conflict", MAIN, &[("oidc.toml", "[oidc]\nissuer_url = \"https://other.example\"\n")]);
        let err = load_dir(&dir).unwrap_err();
        assert!(err.contains("`oidc.issuer_url`"), "{err}");
        assert!(err.contains("config.toml") && err.contains("oidc.toml"), "{err}");
    }

    #[test]
    fn a_command_defined_in_two_files_is_rejected() {
        let dir = config_dir("dup", MAIN, &[("again.toml", "[[commands]]\nname = \"base\"\n")]);
        let err = load_dir(&dir).unwrap_err();
        assert!(err.contains("'base'") && err.contains("again.toml"), "{err}");
    }

    #[test]
    fn a_misspelled_setting_in_a_drop_in_names_the_file() {
        let dir = config_dir("typo", MAIN, &[("typo.toml", "[[commands]]\nname = \"x\"\nexecutible = \"ls\"\n")]);
        let err = load_dir(&dir).unwrap_err();
        assert!(err.contains("typo.toml") && err.contains("executible"), "{err}");
    }

    #[test]
    fn no_drop_in_directory_is_just_the_main_file() {
        let dir = config_dir("plain", MAIN, &[]);
        assert_eq!(load_dir(&dir).unwrap().commands.len(), 1);
    }

    #[test]
    fn misspelled_field_is_rejected() {
        // A typo must fail loudly rather than silently fall back to a default.
        let r: Result<Config, _> = toml::from_str(
            r#"
            [[commands]]
            name = "x"
            opa_rule = "data.x"
            max_validity = "1d"
            "#,
        );
        assert!(r.is_err());
    }
}
