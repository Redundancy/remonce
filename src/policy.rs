//! Policy decisions, from either of two interchangeable backends:
//!
//! - **Embedded** (default): the Rego policy in `policy_dir` is evaluated
//!   in-process with [Regorus](https://github.com/microsoft/regorus), so
//!   there is no OPA server to run. The directory is laid out as for
//!   `opa run`: every `.rego` file is a module, and every `.json` or
//!   `.yaml` file is data mounted at its directory's path (`policy/requirements.json` at
//!   `data`, `policy/x/y.json` at `data.x`). Edits are picked up on the
//!   next decision.
//! - **Remote**: an OPA server at `opa_url`, asked through its data API.
//!
//! Both get the same input and are asked the same paths, so one policy runs
//! on either. A backend that can't answer (unreachable, or a policy that
//! fails to load) is an error, never an allow; callers fail closed.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::SystemTime;

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
pub enum RequestInput {
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

/// Input for a read-only action by a logged-in viewer. `viewer.claims` are
/// the verified claims of their viewer token.
#[derive(Serialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum ViewInput {
    ViewDocs { viewer: Identity },
    ReadFile { viewer: Identity, file: serde_json::Value },
    ViewExecution { viewer: Identity, execution_id: String },
}

#[derive(Deserialize)]
pub struct Decision {
    pub allow: bool,
    pub reason: String,
}

/// Where viewing decisions come from.
const VIEW_RULE: &str = "data.remonce.authz.allow";
/// Where requirement documents are published.
const REQUIREMENTS: &str = "data.remonce.requirements";

/// Files that make up the policy, with what identifies their content.
type Fingerprint = Vec<(PathBuf, Option<SystemTime>, u64)>;

pub enum Policy {
    Embedded(Box<Embedded>),
    Remote(Remote),
}

impl Policy {
    /// The backend the config asks for: `opa_url` for a remote OPA, else
    /// the embedded engine over `policy_dir` (loaded now, so a broken
    /// policy stops startup rather than denying everything quietly).
    pub fn from_config(config: &crate::config::Config) -> Result<Self, String> {
        match (&config.opa_url, &config.policy_dir) {
            (Some(_), Some(_)) => Err(
                "Set either opa_url (a remote OPA server) or policy_dir (evaluated in remonce), not both".into(),
            ),
            (Some(url), None) => Remote::new(url).map(Policy::Remote),
            (None, dir) => Embedded::load(dir.as_deref().unwrap_or(crate::config::DEFAULT_POLICY_DIR))
                .map(|e| Policy::Embedded(Box::new(e))),
        }
    }

    /// For the startup log.
    pub fn describe(&self) -> String {
        match self {
            Policy::Embedded(e) => format!("embedded, from {}", e.dir.display()),
            Policy::Remote(r) => format!("OPA server at {}", r.base),
        }
    }

    async fn eval(&self, input: &impl Serialize, rule: &str) -> Result<serde_json::Value, String> {
        match self {
            Policy::Embedded(e) => e.eval(input, rule),
            Policy::Remote(r) => r.eval(input, rule).await,
        }
    }

    /// The decision `rule` (e.g. `data.remonce.authz.decision`) makes about
    /// a request. An undefined decision is a denial.
    pub async fn decide(&self, rule: &str, input: &RequestInput) -> Result<Decision, String> {
        match self.eval(input, rule).await? {
            serde_json::Value::Null => Ok(Decision {
                allow: false,
                reason: "No decision from policy".into(),
            }),
            v => serde_json::from_value(v).map_err(|e| format!("{rule} is not {{allow, reason}}: {e}")),
        }
    }

    /// Whether `data.remonce.authz.allow` permits a viewing action.
    pub async fn allows_viewing(&self, input: &ViewInput) -> Result<bool, String> {
        Ok(self.eval(input, VIEW_RULE).await? == serde_json::Value::Bool(true))
    }

    /// The published requirement documents, by command name. None published
    /// is an empty map.
    pub async fn requirements(&self) -> Result<serde_json::Map<String, serde_json::Value>, String> {
        match self.eval(&serde_json::json!({}), REQUIREMENTS).await? {
            serde_json::Value::Null => Ok(Default::default()),
            serde_json::Value::Object(m) => Ok(m),
            _ => Err(format!("{REQUIREMENTS} is not an object")),
        }
    }
}

/// An OPA server, asked `POST /v1/data/<path>` with `{"input": ...}`.
pub struct Remote {
    base: url::Url,
    client: reqwest::Client,
}

impl Remote {
    fn new(raw: &str) -> Result<Self, String> {
        let mut base: url::Url = raw.trim().parse().map_err(|e| format!("Invalid opa_url '{raw}': {e}"))?;
        if !base.path().ends_with('/') {
            let with_slash = format!("{}/", base.path());
            base.set_path(&with_slash);
        }
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(std::time::Duration::from_secs(5))
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .map_err(|e| e.to_string())?;
        Ok(Remote { base, client })
    }

    async fn eval(&self, input: &impl Serialize, rule: &str) -> Result<serde_json::Value, String> {
        let path = rule
            .strip_prefix("data.")
            .filter(|p| !p.is_empty())
            .ok_or_else(|| format!("Policy path '{rule}' must start with 'data.'"))?;
        let url = self
            .base
            .join(&format!("v1/data/{}", path.replace('.', "/")))
            .map_err(|e| e.to_string())?;
        #[derive(Deserialize)]
        struct Response {
            result: Option<serde_json::Value>,
        }
        let res: Response = self
            .client
            .post(url)
            .json(&serde_json::json!({ "input": input }))
            .send()
            .await
            .map_err(|e| format!("OPA unreachable: {}", e.without_url()))?
            .error_for_status()
            .map_err(|e| format!("OPA error: {}", e.without_url()))?
            .json()
            .await
            .map_err(|e| format!("OPA response: {}", e.without_url()))?;
        // No `result` is OPA's "undefined".
        Ok(res.result.unwrap_or(serde_json::Value::Null))
    }
}

struct Loaded {
    engine: regorus::Engine,
    fingerprint: Fingerprint,
}

/// The Rego policy in a directory, evaluated in-process.
pub struct Embedded {
    dir: PathBuf,
    loaded: Mutex<Option<Loaded>>,
}

impl Embedded {
    /// Load the policy in `dir`; fails if it doesn't load.
    pub fn load(dir: impl Into<PathBuf>) -> Result<Self, String> {
        let policy = Embedded {
            dir: dir.into(),
            loaded: Mutex::new(None),
        };
        policy.engine()?;
        Ok(policy)
    }

    /// A ready engine for the policy as it is on disk now: reloaded if any
    /// file changed. Cloning shares the parsed modules and data.
    fn engine(&self) -> Result<regorus::Engine, String> {
        let fingerprint = fingerprint(&self.dir)?;
        let mut guard = self.loaded.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(l) = guard.as_ref()
            && l.fingerprint == fingerprint
        {
            return Ok(l.engine.clone());
        }
        let engine = build_engine(&self.dir, &fingerprint).inspect_err(|_| {
            // Don't keep serving the old policy after an edit: the edit may
            // be a restriction. Forget it, so every decision errors until
            // the policy loads again.
            *guard = None;
        })?;
        if guard.is_some() {
            tracing::info!(dir = %self.dir.display(), "Policy reloaded");
        }
        *guard = Some(Loaded {
            engine: engine.clone(),
            fingerprint,
        });
        Ok(engine)
    }

    fn eval(&self, input: &impl Serialize, rule: &str) -> Result<serde_json::Value, String> {
        let mut engine = self.engine()?;
        let input = serde_json::to_string(input).map_err(|e| e.to_string())?;
        engine.set_input_json(&input).map_err(|e| e.to_string())?;
        // A query rather than eval_rule: like OPA's data API, it reads data
        // documents as well as rules, and an undefined path is no result
        // rather than an error.
        let results = engine.eval_query(rule.to_string(), false).map_err(|e| format!("{rule}: {e}"))?;
        let Some(value) = results.result.first().and_then(|r| r.expressions.first()).map(|e| &e.value) else {
            return Ok(serde_json::Value::Null);
        };
        if *value == regorus::Value::Undefined {
            return Ok(serde_json::Value::Null);
        }
        let json = value.to_json_str().map_err(|e| e.to_string())?;
        serde_json::from_str(&json).map_err(|e| e.to_string())
    }
}

fn policy_files(dir: &Path) -> Result<Vec<PathBuf>, String> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) -> std::io::Result<()> {
        for entry in std::fs::read_dir(dir)? {
            let path = entry?.path();
            if path.is_dir() {
                walk(&path, out)?;
            } else if matches!(path.extension().and_then(|e| e.to_str()), Some("rego" | "json" | "yaml" | "yml")) {
                out.push(path);
            }
        }
        Ok(())
    }
    let mut files = Vec::new();
    walk(dir, &mut files).map_err(|e| format!("Failed to read policy directory {}: {e}", dir.display()))?;
    files.sort();
    Ok(files)
}

fn fingerprint(dir: &Path) -> Result<Fingerprint, String> {
    policy_files(dir)?
        .into_iter()
        .map(|p| {
            let meta = std::fs::metadata(&p).map_err(|e| format!("{}: {e}", p.display()))?;
            Ok((p, meta.modified().ok(), meta.len()))
        })
        .collect()
}

fn build_engine(dir: &Path, files: &Fingerprint) -> Result<regorus::Engine, String> {
    let mut engine = regorus::Engine::new();
    // Rego v1 (OPA 1.0 syntax) is the default; errors in builtins are
    // errors, not undefined, so a typo can't quietly deny or allow.
    engine.set_strict_builtin_errors(true);
    let mut modules = 0;
    for (path, _, _) in files {
        let err = |e: &dyn std::fmt::Display| format!("Policy file {}: {e}", path.display());
        if path.extension().and_then(|e| e.to_str()) == Some("rego") {
            let text = std::fs::read_to_string(path).map_err(|e| err(&e))?;
            engine.add_policy(path.display().to_string(), text).map_err(|e| err(&e))?;
            modules += 1;
        } else {
            let text = std::fs::read_to_string(path).map_err(|e| err(&e))?;
            let mut value: serde_json::Value = if path.extension().and_then(|e| e.to_str()) == Some("json") {
                serde_json::from_str(&text).map_err(|e| err(&e))?
            } else {
                let yaml = regorus::Value::from_yaml_str(&text).map_err(|e| err(&e))?;
                serde_json::from_str(&yaml.to_json_str().map_err(|e| err(&e))?).map_err(|e| err(&e))?
            };
            // Mount at the file's directory, relative to the policy root.
            let rel = path.parent().and_then(|p| p.strip_prefix(dir).ok()).unwrap_or(Path::new(""));
            for part in rel.iter().rev() {
                value = serde_json::json!({ part.to_string_lossy(): value });
            }
            engine.add_data_json(&value.to_string()).map_err(|e| err(&e))?;
        }
    }
    if modules == 0 {
        return Err(format!("No .rego policy files in {}", dir.display()));
    }
    // Resolve every module now, so a builtin the embedded engine lacks (or
    // any other static error) is reported at load, not at the first
    // decision.
    engine.eval_query("data".to_string(), false).map_err(|e| {
        let hint = if e.to_string().contains("could not find function") {
            " (a builtin the embedded engine doesn't provide; see CONFIGURATION.md, or set opa_url to use an OPA server)"
        } else {
            ""
        };
        format!("Policy in {}: {e}{hint}", dir.display())
    })?;
    Ok(engine)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signer(name: &str, groups: &[&str]) -> Signer {
        Signer {
            username: name.into(),
            claims: serde_json::json!({ "sub": name, "groups": groups }),
            signed_at: "2026-04-23T10:00:00Z".into(),
        }
    }

    fn execute(command: &str, approvers: Vec<Signer>, executor_groups: &[&str]) -> RequestInput {
        RequestInput::Execute {
            command: serde_json::json!({ "command": command }),
            request_id: "ab".into(),
            approvers,
            executor: Identity {
                username: "carol".into(),
                claims: serde_json::json!({ "sub": "carol", "groups": executor_groups }),
            },
            host: "agent-01".into(),
        }
    }

    fn shipped() -> Policy {
        Policy::Embedded(Box::new(
            Embedded::load(concat!(env!("CARGO_MANIFEST_DIR"), "/policy")).expect("shipped policy loads"),
        ))
    }

    #[test]
    fn execute_input_shape() {
        let v = serde_json::to_value(execute("test", vec![signer("alice", &[]), signer("bob", &[])], &[])).unwrap();
        assert_eq!(v["action"], "execute");
        assert_eq!(v["approvers"][1]["username"], "bob");
        assert_eq!(v["executor"]["claims"]["sub"], "carol");
        assert_eq!(v["request_id"], "ab");
    }

    #[test]
    fn view_input_shape() {
        let v = serde_json::to_value(ViewInput::ReadFile {
            viewer: Identity { username: "v".into(), claims: serde_json::json!({ "sub": "v" }) },
            file: serde_json::json!({ "name": "logs" }),
        })
        .unwrap();
        assert_eq!(v["action"], "read_file");
        assert_eq!(v["viewer"]["claims"]["sub"], "v");
        assert_eq!(v["file"]["name"], "logs");
        assert!(v.get("jwt").is_none());
    }

    #[tokio::test]
    async fn shipped_policy_decides() {
        let p = shipped();
        let users = ["webapp-users"];
        let rule = "data.remonce.authz.decision";

        let d = p.decide(rule, &execute("ping-test", vec![signer("alice", &users)], &users)).await.unwrap();
        assert!(d.allow, "{}", d.reason);

        let d = p.decide(rule, &execute("ping-pair", vec![signer("alice", &users)], &users)).await.unwrap();
        assert!(!d.allow);
        assert_eq!(d.reason, "The approvals do not meet the published requirements");

        let two = vec![signer("alice", &users), signer("bob", &users)];
        assert!(p.decide(rule, &execute("ping-pair", two, &users)).await.unwrap().allow);

        let d = p.decide(rule, &execute("ping-test", vec![signer("alice", &users)], &[])).await.unwrap();
        assert_eq!(d.reason, "You are not allowed to execute this command");

        let d = p.decide(rule, &execute("fail", vec![signer("alice", &users)], &users)).await.unwrap();
        assert_eq!(d.reason, "No published requirements for 'fail'");

        let d = p.decide("data.remonce.nothing.here", &execute("test", vec![], &[])).await.unwrap();
        assert!(!d.allow, "an undefined decision denies");
    }

    #[tokio::test]
    async fn shipped_policy_viewing_and_requirements() {
        let p = shipped();
        let viewer = |groups: &[&str]| Identity {
            username: "v".into(),
            claims: serde_json::json!({ "sub": "v", "groups": groups }),
        };
        assert!(p.allows_viewing(&ViewInput::ViewDocs { viewer: viewer(&["webapp-users"]) }).await.unwrap());
        assert!(!p.allows_viewing(&ViewInput::ViewDocs { viewer: viewer(&[]) }).await.unwrap());
        assert!(!p.allows_viewing(&ViewInput::ReadFile { viewer: viewer(&["other"]), file: serde_json::json!({}) }).await.unwrap());

        let reqs = p.requirements().await.unwrap();
        assert!(reqs.contains_key("ping-pair"));
        assert_eq!(reqs["ping-pair"]["approvals"].as_array().unwrap().len(), 2);
    }

    /// Run the Rego test suite in `policy_test/` against the shipped policy,
    /// the way `opa test policy policy_test` would: every `test_*` rule must
    /// be true.
    #[test]
    fn rego_test_suite_passes() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let mut engine = build_engine(&root.join("policy"), &fingerprint(&root.join("policy")).unwrap()).unwrap();
        let tests_dir = root.join("policy_test");
        let mut ran = 0;
        let mut failed = Vec::new();
        for file in policy_files(&tests_dir).unwrap() {
            let package = engine
                .add_policy(file.display().to_string(), std::fs::read_to_string(&file).unwrap())
                .unwrap();
            let text = std::fs::read_to_string(&file).unwrap();
            let names: Vec<&str> = text
                .lines()
                .filter_map(|l| l.strip_prefix("test_"))
                .filter_map(|l| l.split(|c: char| !(c.is_alphanumeric() || c == '_')).next())
                .collect();
            for name in names {
                let rule = format!("{package}.test_{name}");
                ran += 1;
                match engine.eval_rule(rule.clone()) {
                    Ok(regorus::Value::Bool(true)) => {}
                    other => failed.push(format!("{rule}: {other:?}")),
                }
            }
        }
        assert!(ran >= 20, "only found {ran} tests");
        assert!(failed.is_empty(), "failing Rego tests:\n{}", failed.join("\n"));
    }

    /// The two backends must agree. Runs against a live OPA serving this
    /// repo's `policy/` when `REMONCE_TEST_OPA_URL` is set, e.g.
    /// `opa run --server policy` and `REMONCE_TEST_OPA_URL=http://127.0.0.1:8181`.
    #[tokio::test]
    async fn remote_opa_matches_embedded() {
        let Ok(url) = std::env::var("REMONCE_TEST_OPA_URL") else {
            eprintln!("skipped: set REMONCE_TEST_OPA_URL to compare with a live OPA");
            return;
        };
        let embedded = shipped();
        let remote = Policy::Remote(Remote::new(&url).unwrap());
        let users = ["webapp-users"];
        let rule = "data.remonce.authz.decision";
        let cases = || {
            vec![
                execute("ping-test", vec![signer("alice", &users)], &users),
                execute("ping-test", vec![signer("alice", &users)], &[]),
                execute("ping-pair", vec![signer("alice", &users)], &users),
                execute("ping-pair", vec![signer("alice", &users), signer("bob", &users)], &users),
                execute("fail", vec![signer("alice", &users)], &users),
                execute("test", vec![signer("alice", &["other"])], &users),
            ]
        };
        for (a, b) in cases().iter().zip(cases().iter()) {
            let (x, y) = (embedded.decide(rule, a).await.unwrap(), remote.decide(rule, b).await.unwrap());
            assert_eq!((x.allow, &x.reason), (y.allow, &y.reason));
        }
        let undefined = execute("test", vec![], &[]);
        assert_eq!(
            embedded.decide("data.remonce.nothing.here", &undefined).await.unwrap().reason,
            remote.decide("data.remonce.nothing.here", &undefined).await.unwrap().reason
        );
        for groups in [&["webapp-users"][..], &[][..]] {
            let viewer = || Identity { username: "v".into(), claims: serde_json::json!({ "groups": groups }) };
            assert_eq!(
                embedded.allows_viewing(&ViewInput::ViewDocs { viewer: viewer() }).await.unwrap(),
                remote.allows_viewing(&ViewInput::ViewDocs { viewer: viewer() }).await.unwrap()
            );
        }
        assert_eq!(embedded.requirements().await.unwrap(), remote.requirements().await.unwrap());
    }

    #[tokio::test]
    async fn data_files_mount_by_directory() {
        let dir = std::env::temp_dir().join(format!("remonce-policy-data-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("teams").join("db")).unwrap();
        std::fs::write(dir.join("p.rego"), "package p

x := 1
").unwrap();
        std::fs::write(dir.join("root.json"), r#"{"remonce": {"requirements": {"a": {}}}}"#).unwrap();
        std::fs::write(dir.join("teams").join("db").join("members.yaml"), "owners:
  - alice
").unwrap();
        let p = Policy::Embedded(Box::new(Embedded::load(&dir).unwrap()));
        assert!(p.requirements().await.unwrap().contains_key("a"));
        let Policy::Embedded(e) = &p else { unreachable!() };
        let owners = e.eval(&serde_json::json!({}), "data.teams.db.owners").unwrap();
        assert_eq!(owners, serde_json::json!(["alice"]));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_builtin_is_reported_at_load() {
        let dir = std::env::temp_dir().join(format!("remonce-policy-builtin-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("authz.rego"),
            "package remonce.authz\n\nallow if io.jwt.decode(input.token)[1].sub == \"x\"\n",
        )
        .unwrap();
        let err = Embedded::load(&dir).err().expect("load should fail");
        assert!(err.contains("io.jwt.decode") && err.contains("opa_url"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn broken_policy_is_an_error_not_a_denial() {
        let dir = std::env::temp_dir().join(format!("remonce-policy-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("authz.rego");
        std::fs::write(&file, "package remonce.authz\n\nallow if input.action == \"view_docs\"\n").unwrap();
        let p = Policy::Embedded(Box::new(Embedded::load(&dir).unwrap()));
        let view = || ViewInput::ViewDocs { viewer: Identity { username: "v".into(), claims: serde_json::json!({}) } };
        assert!(p.allows_viewing(&view()).await.unwrap());

        // A broken edit must not leave the previous policy in force.
        std::fs::write(&file, "package remonce.authz\n\nallow if {{ nope\n").unwrap();
        assert!(p.allows_viewing(&view()).await.is_err());

        // Fixed: picked up again without a restart.
        std::fs::write(&file, "package remonce.authz\n\nallow := false\n").unwrap();
        assert!(!p.allows_viewing(&view()).await.unwrap());

        let _ = std::fs::remove_dir_all(&dir);
        assert!(Embedded::load(std::env::temp_dir().join("remonce-no-such-policy-dir")).is_err());
    }
}

