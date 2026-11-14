//! The agent end to end: its real router on a loopback socket (plain TCP,
//! no TLS), a fake IdP key set and TSA from `security_tests`, the shipped
//! policy, and a command that really runs.

use crate::agent::{AgentState, build_router};
use crate::security::RequestBundle;
use crate::security_tests::tests::{
    ALICE, BOB, CLIENT, Env, ISSUER, approve, create_valid_jwt, new_env, new_env_with_kid,
};
use futures::StreamExt;
use serde_json::json;
use std::path::PathBuf;
use std::time::Duration;
use time::OffsetDateTime;

pub(crate) const VIEWER_CLIENT: &str = "remonce-viewer";
pub(crate) const HOST: &str = "testhost";

/// A directory under the system temp dir, removed on drop.
pub(crate) struct TempDir(pub PathBuf);

impl TempDir {
    pub(crate) fn new(label: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("remonce-{label}-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        TempDir(dir)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// `echo {{count}}`, without a shell where the platform has an echo binary.
fn echo_command() -> (String, Vec<&'static str>) {
    if cfg!(windows) {
        (
            std::env::var("ComSpec").unwrap_or_else(|_| "cmd.exe".into()),
            vec!["/C", "echo", "{{count}}"],
        )
    } else {
        ("/bin/echo".into(), vec!["{{count}}"])
    }
}

/// A command that prints a line and then runs for 30 seconds unless it is
/// stopped, as `(executable, args, env)`. The waiting is done by a process
/// the command starts (a shell's child), which holds the command's output
/// open: stopping only the shell would leave it running.
fn sleep_command() -> (String, Vec<&'static str>, String) {
    if cfg!(windows) {
        // ping needs SystemRoot to load Winsock, and cmd needs PATH to find
        // ping; the agent clears everything else.
        let system_root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
        let path = format!(r"{system_root}\System32");
        (
            std::env::var("ComSpec").unwrap_or_else(|_| "cmd.exe".into()),
            vec!["/C", "ping", "-n", "30", "127.0.0.1"],
            format!("env = {{ SystemRoot = {system_root:?}, PATH = {path:?} }}"),
        )
    } else {
        (
            "/bin/sh".into(),
            vec!["-c", "echo waiting for thirty seconds; sleep 30; true"],
            r#"env = { PATH = "/bin:/usr/bin" }"#.into(),
        )
    }
}

/// An agent config with runnable commands the shipped policy publishes
/// requirements for (approvers and an executor in `webapp-users`):
/// `ping-test` echoes its `count`; `test` runs far longer than its
/// one-second timeout; and `ping-pair` (two approvals) runs for 30 seconds
/// and keeps only the first 10 bytes of its output. The run logs are also
/// offered as files.
pub(crate) fn test_config(logs_dir: &std::path::Path) -> crate::config::Config {
    let (executable, args) = echo_command();
    let (sleep_executable, sleep_args, sleep_env) = sleep_command();
    let log_files = logs_dir.join("*.log");
    let text = format!(
        r#"
logs_dir = {logs:?}
policy_dir = {policy:?}

[oidc]
issuer_url = "{ISSUER}"
signing_client_id = "{CLIENT}"
viewer_client_id = "{VIEWER_CLIENT}"

[[commands]]
name = "ping-test"
opa_rule = "data.remonce.authz.decision"
executable = {executable:?}
args = {args:?}

[[commands.params]]
name = "count"
min = 1
max = 100

[[commands]]
name = "test"
opa_rule = "data.remonce.authz.decision"
executable = {sleep_executable:?}
args = {sleep_args:?}
command_timeout = "1s"
{sleep_env}

[[commands]]
name = "ping-pair"
opa_rule = "data.remonce.authz.decision"
executable = {sleep_executable:?}
args = {sleep_args:?}
max_output_bytes = 10
{sleep_env}

[[files]]
path = {log_files:?}
name = "execution-logs"
"#,
        logs = logs_dir.to_string_lossy(),
        log_files = log_files.to_string_lossy(),
        policy = concat!(env!("CARGO_MANIFEST_DIR"), "/policy"),
    );
    crate::config::parse(&text).expect("test config parses")
}

pub(crate) struct TestAgent {
    pub env: Env,
    pub addr: std::net::SocketAddr,
    pub logs: std::sync::Arc<TempDir>,
    pub http: reqwest::Client,
    /// The agent's running commands (its last "boot", after a restart).
    pub runs: crate::agent::Runs,
}

impl TestAgent {
    /// Serve `state`'s router on a loopback port.
    pub(crate) async fn serve(state: AgentState) -> std::net::SocketAddr {
        Self::serve_with_cors(state, &[]).await
    }

    pub(crate) async fn serve_with_cors(state: AgentState, cors_allowed_origins: &[String]) -> std::net::SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = build_router(state, cors_allowed_origins);
        tokio::spawn(async move {
            let _ = axum::serve(
                listener,
                app.into_make_service_with_connect_info::<crate::tls::PeerAddr>(),
            )
            .await;
        });
        addr
    }

    pub(crate) fn state(env: &Env, config: crate::config::Config) -> AgentState {
        let policy = crate::policy::Policy::from_config(&config).expect("shipped policy loads");
        AgentState {
            http_client: crate::http_client(),
            config,
            idp_keys: crate::idp_keys::IdpKeys::fixed(env.jwks.clone()),
            hostname: HOST.into(),
            trusted_roots: vec![env.tsa_keys.cert_der.clone()],
            replay_cache: crate::replay::ReplayCache::new(),
            revocations: crate::replay::RevocationCache::new(),
            revocation_service: None,
            policy: std::sync::Arc::new(policy),
            runs: crate::agent::Runs::default(),
        }
    }

    pub(crate) async fn start() -> Self {
        let env = new_env();
        let logs = std::sync::Arc::new(TempDir::new("agent-logs"));
        let state = Self::state(&env, test_config(&logs.0));
        let runs = state.runs.clone();
        let addr = Self::serve(state).await;
        TestAgent {
            env,
            addr,
            logs,
            http: reqwest::Client::new(),
            runs,
        }
    }

    /// The same agent, as seen by people whose tokens come from `env`.
    pub(crate) fn with_env(&self, env: Env) -> Self {
        TestAgent {
            env,
            addr: self.addr,
            logs: self.logs.clone(),
            http: self.http.clone(),
            runs: self.runs.clone(),
        }
    }

    /// A viewer login for `who`, in `webapp-users`.
    pub(crate) fn viewer_token(&self, who: &str) -> String {
        create_valid_jwt(
            &self.env.idp,
            ISSUER,
            VIEWER_CLIENT,
            who,
            "viewer-nonce",
            OffsetDateTime::now_utc(),
            json!({ "groups": ["webapp-users"] }),
        )
    }

    /// A new `ping-test` request for this agent, approved by `approvers`.
    pub(crate) fn request(&self, approvers: &[usize]) -> RequestBundle {
        self.request_for("ping-test", json!({ "count": "42" }), approvers)
    }

    /// A new request for `command` on this agent, approved by `approvers`.
    pub(crate) fn request_for(&self, command: &str, params: serde_json::Value, approvers: &[usize]) -> RequestBundle {
        let command = json!({
            "command": command,
            "id": uuid::Uuid::new_v4().to_string(),
            "target_machines": [HOST],
            "params": params,
        });
        let now = OffsetDateTime::now_utc();
        RequestBundle {
            approvals: approvers.iter().map(|who| approve(&self.env, *who, &command, now)).collect(),
            command,
        }
    }

    /// A viewer login for `who` with these groups.
    pub(crate) fn viewer_token_in(&self, who: &str, groups: &[&str]) -> String {
        create_valid_jwt(
            &self.env.idp,
            ISSUER,
            VIEWER_CLIENT,
            who,
            "viewer-nonce",
            OffsetDateTime::now_utc(),
            json!({ "groups": groups }),
        )
    }

    pub(crate) async fn get(&self, path: &str, token: Option<&str>) -> reqwest::Response {
        let mut req = self.http.get(format!("http://{}{path}", self.addr));
        if let Some(token) = token {
            req = req.bearer_auth(token);
        }
        req.send().await.unwrap()
    }

    pub(crate) async fn execute(&self, bundle: &RequestBundle, token: Option<&str>) -> reqwest::Response {
        let mut req = self.http.post(format!("http://{}/execute", self.addr)).json(bundle);
        if let Some(token) = token {
            req = req.bearer_auth(token);
        }
        req.send().await.unwrap()
    }

    /// The run's log once its trailer has been written.
    pub(crate) async fn finished_log(&self, execution_id: &str) -> String {
        let path = self.logs.0.join(format!("{execution_id}.log"));
        for _ in 0..200 {
            if let Ok(text) = std::fs::read_to_string(&path)
                && ["--- EXIT", "--- TIMEOUT", "--- WAIT ERROR", "--- STOPPED"].iter().any(|t| text.contains(t))
            {
                return text;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("run {execution_id} did not finish: {:?}", std::fs::read_to_string(&path));
    }
}

async fn execution_id(resp: reqwest::Response) -> String {
    assert_eq!(resp.status(), 200, "execute should be accepted");
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "authorized");
    body["message"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn approved_request_runs_once_and_its_log_streams() {
    let agent = TestAgent::start().await;
    let bundle = agent.request(&[ALICE]);
    let token = agent.viewer_token("bob");

    // It runs: the command's output and exit land in the run log.
    let id = execution_id(agent.execute(&bundle, Some(&token)).await).await;
    assert_eq!(id, bundle.command["id"].as_str().unwrap());
    let log = agent.finished_log(&id).await;
    assert!(log.contains("Approver: alice"), "{log}");
    assert!(log.contains("Executor: bob"), "{log}");
    assert!(log.contains("42"), "{log}");
    assert!(log.contains("--- EXIT"), "{log}");

    // The log streams to a logged-in viewer policy accepts.
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    let mut ws_req = format!("ws://{}/stream/{id}", agent.addr).into_client_request().unwrap();
    ws_req
        .headers_mut()
        .insert("Authorization", format!("Bearer {token}").parse().unwrap());
    let (mut ws, _) = tokio_tungstenite::connect_async(ws_req).await.expect("stream opens");
    let mut streamed = String::new();
    while !streamed.contains("--- EXIT") {
        let msg = tokio::time::timeout(Duration::from_secs(10), ws.next())
            .await
            .expect("stream keeps up")
            .expect("stream stays open")
            .unwrap();
        if let tokio_tungstenite::tungstenite::Message::Text(t) = msg {
            streamed.push_str(t.as_str());
        }
    }
    assert!(streamed.contains("Executor: bob"), "{streamed}");

    // The same request doesn't run twice, whoever submits it.
    let again = agent.execute(&bundle, Some(&agent.viewer_token("carol"))).await;
    assert_eq!(again.status(), 409);
}

#[tokio::test]
async fn execution_needs_an_identified_executor_and_a_genuine_approval() {
    let agent = TestAgent::start().await;
    let bundle = agent.request(&[ALICE]);

    // Nobody: refused, and the request isn't used up.
    assert_eq!(agent.execute(&bundle, None).await.status(), 401);

    // A signing-client token is not an executor credential.
    let signing_token = bundle.approvals[0].id_token.clone();
    assert_eq!(agent.execute(&bundle, Some(&signing_token)).await.status(), 401);

    // An approval of another request doesn't carry over.
    let mut transplanted = agent.request(&[]);
    transplanted.approvals = bundle.approvals.clone();
    let token = agent.viewer_token("bob");
    assert_eq!(agent.execute(&transplanted, Some(&token)).await.status(), 400);

    // An executor policy doesn't accept: refused, still not used up.
    let outsider = create_valid_jwt(
        &agent.env.idp,
        ISSUER,
        VIEWER_CLIENT,
        "mallory",
        "viewer-nonce",
        OffsetDateTime::now_utc(),
        json!({ "groups": ["someone-else"] }),
    );
    assert_eq!(agent.execute(&bundle, Some(&outsider)).await.status(), 403);

    // After all that, the genuine submission still runs.
    let id = execution_id(agent.execute(&bundle, Some(&token)).await).await;
    agent.finished_log(&id).await;
}

#[tokio::test]
async fn two_approvals_from_one_person_do_not_run() {
    let agent = TestAgent::start().await;
    let mut bundle = agent.request(&[ALICE, BOB]);
    let second_alice = approve(&agent.env, ALICE, &bundle.command, OffsetDateTime::now_utc());
    bundle.approvals[1] = second_alice;
    let resp = agent.execute(&bundle, Some(&agent.viewer_token("bob"))).await;
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn idp_key_rotation_is_followed_without_a_restart() {
    // The IdP signs with one key, then rotates to another and withdraws the
    // first. The agent keeps running throughout.
    let old = new_env_with_kid("idp-2025");
    let new = new_env_with_kid("idp-2026");
    let published = std::sync::Arc::new(std::sync::Mutex::new(old.jwks.clone()));

    let logs = std::sync::Arc::new(TempDir::new("agent-logs"));
    let mut state = TestAgent::state(&old, test_config(&logs.0));
    state.trusted_roots.push(new.tsa_keys.cert_der.clone());
    state.idp_keys = crate::idp_keys::IdpKeys::refreshing(
        old.jwks.clone(),
        {
            let published = published.clone();
            move || {
                let keys = published.lock().unwrap().clone();
                async move { Ok(keys) }
            }
        },
        Duration::ZERO,
    );
    let before = TestAgent {
        env: old,
        runs: state.runs.clone(),
        addr: TestAgent::serve(state).await,
        logs,
        http: reqwest::Client::new(),
    };

    // Before the rotation, the old key's tokens work.
    let token = before.viewer_token("bob");
    let id = execution_id(before.execute(&before.request(&[ALICE]), Some(&token)).await).await;
    before.finished_log(&id).await;
    let approved_before = before.request(&[ALICE]);

    *published.lock().unwrap() = new.jwks.clone();
    let after = before.with_env(new);

    // Tokens signed with the new key are accepted straight away.
    let token = after.viewer_token("bob");
    let id = execution_id(after.execute(&after.request(&[ALICE]), Some(&token)).await).await;
    after.finished_log(&id).await;

    // The withdrawn key no longer verifies anything: not a login...
    let stale_login = before.viewer_token("bob");
    assert_eq!(after.execute(&after.request(&[ALICE]), Some(&stale_login)).await.status(), 401);
    // ...and not an approval made while it was current.
    assert_eq!(after.execute(&approved_before, Some(&token)).await.status(), 400);
}

#[tokio::test]
async fn state_dir_remembers_runs_and_revocations_across_a_restart() {
    use crate::security_tests::tests::revoke_sig;

    let env = new_env();
    let logs = std::sync::Arc::new(TempDir::new("agent-logs"));
    let state_dir = TempDir::new("agent-state");
    // An agent process over the same directories: each call is a restart.
    let boot = |env: &Env| {
        let mut state = TestAgent::state(env, test_config(&logs.0));
        state.replay_cache = crate::replay::ReplayCache::persistent(&state_dir.0).unwrap();
        state.revocations = crate::replay::RevocationCache::persistent(&state_dir.0).unwrap();
        TestAgent::serve(state)
    };
    let mut agent = TestAgent {
        addr: boot(&env).await,
        env,
        logs: logs.clone(),
        http: reqwest::Client::new(),
        runs: Default::default(),
    };
    let token = agent.viewer_token("bob");

    // One request runs; another is revoked by its approver before it does.
    let ran = agent.request(&[ALICE]);
    let id = execution_id(agent.execute(&ran, Some(&token)).await).await;
    agent.finished_log(&id).await;

    let revoked = agent.request(&[ALICE]);
    let request_id = crate::security::request_id(&revoked.command);
    let revocation = crate::security::RevocationBundle {
        revoker: revoke_sig(&agent.env, ALICE, &request_id, OffsetDateTime::now_utc()),
        request: revoked.clone(),
    };
    let resp = agent
        .http
        .post(format!("http://{}/revoke", agent.addr))
        .json(&revocation)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "{:?}", resp.text().await);

    // The agent restarts. Both are still remembered.
    agent.addr = boot(&agent.env).await;
    assert_eq!(agent.execute(&ran, Some(&token)).await.status(), 409);
    assert_eq!(agent.execute(&revoked, Some(&token)).await.status(), 403);

    // A request it has never seen still runs.
    let id = execution_id(agent.execute(&agent.request(&[ALICE]), Some(&token)).await).await;
    agent.finished_log(&id).await;
}

#[tokio::test]
async fn without_state_dir_a_restart_forgets() {
    // The default (no `state_dir`), pinned down so the difference is
    // deliberate: after a restart the same approved request runs again.
    let env = new_env();
    let logs = std::sync::Arc::new(TempDir::new("agent-logs"));
    let boot = |env: &Env| TestAgent::serve(TestAgent::state(env, test_config(&logs.0)));
    let mut agent = TestAgent {
        addr: boot(&env).await,
        env,
        logs: logs.clone(),
        http: reqwest::Client::new(),
        runs: Default::default(),
    };
    let token = agent.viewer_token("bob");
    let bundle = agent.request(&[ALICE]);
    let id = execution_id(agent.execute(&bundle, Some(&token)).await).await;
    agent.finished_log(&id).await;
    assert_eq!(agent.execute(&bundle, Some(&token)).await.status(), 409);

    agent.addr = boot(&agent.env).await;
    let second = execution_id(agent.execute(&bundle, Some(&token)).await).await;
    assert_ne!(second, id, "the second run gets its own log");
    agent.finished_log(&second).await;
}

/// The audit records about one request, as (event type, decision, record).
fn audit_of(bundle: &RequestBundle) -> Vec<(String, String, serde_json::Value)> {
    let request_id = crate::security::request_id(&bundle.command);
    crate::audit::test_capture::matching("request_id", &request_id)
        .into_iter()
        .map(|r| {
            (
                r["event_type"].as_str().unwrap().to_string(),
                r["decision"].as_str().unwrap().to_string(),
                r,
            )
        })
        .collect()
}

#[tokio::test]
async fn a_run_is_audited_from_start_to_finish() {
    let agent = TestAgent::start().await;
    let bundle = agent.request(&[ALICE]);
    let id = execution_id(agent.execute(&bundle, Some(&agent.viewer_token("bob"))).await).await;
    agent.finished_log(&id).await;

    let records = audit_of(&bundle);
    let kinds: Vec<(&str, &str)> = records.iter().map(|(e, d, _)| (e.as_str(), d.as_str())).collect();
    assert_eq!(kinds, [("command_execution", "allow"), ("command_finished", "completed")], "{records:#?}");
    for (_, _, record) in &records {
        assert_eq!(record["execution_id"], id.as_str());
        assert_eq!(record["user"], "bob");
        assert_eq!(record["approvers"][0]["username"], "alice");
        assert_eq!(record["command"]["command"], "ping-test");
    }
    let outcome = &records[1].2["outcome"];
    assert_eq!(outcome["result"], "exited");
    assert_eq!(outcome["exit_code"], 0);
    assert!(outcome["duration_ms"].is_u64());
}

#[tokio::test]
async fn a_timed_out_run_is_killed_and_audited_as_a_timeout() {
    let agent = TestAgent::start().await;
    let bundle = agent.request_for("test", json!({}), &[ALICE]);
    let started = std::time::Instant::now();
    let id = execution_id(agent.execute(&bundle, Some(&agent.viewer_token("bob"))).await).await;
    let log = agent.finished_log(&id).await;
    assert!(log.contains("--- TIMEOUT"), "{log}");
    // The command's own child does the waiting and holds its output open.
    // Had only the command been killed, the log would have stayed open for
    // the 5s drain limit (and the child would still be running).
    assert!(
        started.elapsed() < Duration::from_secs(4),
        "everything the command started was stopped with it ({:?})",
        started.elapsed()
    );

    let records = audit_of(&bundle);
    let finished = records.iter().find(|(e, _, _)| e == "command_finished").expect("finish record");
    assert_eq!(finished.2["outcome"]["result"], "timeout");
    assert!(finished.2["outcome"].get("exit_code").is_none());
}

#[tokio::test]
async fn refused_requests_are_audited_with_the_reason() {
    let agent = TestAgent::start().await;
    let bundle = agent.request(&[ALICE]);
    let outsider = agent.viewer_token_in("mallory", &["someone-else"]);
    assert_eq!(agent.execute(&bundle, Some(&outsider)).await.status(), 403);

    let records = audit_of(&bundle);
    assert_eq!(records.len(), 1, "{records:#?}");
    let (event, decision, record) = &records[0];
    assert_eq!((event.as_str(), decision.as_str()), ("command_execution", "deny"));
    assert_eq!(record["user"], "mallory");
    assert!(record["reason"].as_str().unwrap().contains("not allowed to execute"), "{record}");
    assert!(record.get("execution_id").is_none());
}

#[tokio::test]
async fn what_the_agent_offers_is_shown_only_as_policy_allows_and_audited() {
    let agent = TestAgent::start().await;
    // Names unique to this test, to find its audit records by.
    let member = format!("member-{}", uuid::Uuid::new_v4());
    let outsider = format!("outsider-{}", uuid::Uuid::new_v4());
    let member_token = agent.viewer_token_in(&member, &["webapp-users"]);
    let outsider_token = agent.viewer_token_in(&outsider, &["someone-else"]);

    for path in ["/api/commands", "/api/files"] {
        assert_eq!(agent.get(path, None).await.status(), 401, "{path}");
        assert_eq!(agent.get(path, Some(&outsider_token)).await.status(), 403, "{path}");
        assert_eq!(agent.get(path, Some(&member_token)).await.status(), 200, "{path}");
    }

    let seen = |user: &str| -> Vec<(String, String)> {
        crate::audit::test_capture::matching("user", user)
            .iter()
            .map(|r| (r["event_type"].as_str().unwrap().to_string(), r["decision"].as_str().unwrap().to_string()))
            .collect()
    };
    let pairs = |decision: &str| {
        vec![
            ("catalog_access".to_string(), decision.to_string()),
            ("file_list_access".to_string(), decision.to_string()),
        ]
    };
    assert_eq!(seen(&member), pairs("allow"));
    assert_eq!(seen(&outsider), pairs("deny"));
}

#[tokio::test]
async fn file_policy_and_audit_see_where_a_path_resolves() {
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;

    let agent = TestAgent::start().await;
    let viewer = format!("viewer-{}", uuid::Uuid::new_v4());
    let token = agent.viewer_token_in(&viewer, &["webapp-users"]);

    // A run log to read, asked for by a roundabout spelling of its path.
    let id = execution_id(agent.execute(&agent.request(&[ALICE]), Some(&token)).await).await;
    agent.finished_log(&id).await;
    let direct = agent.logs.0.join(format!("{id}.log"));
    let roundabout = agent
        .logs
        .0
        .join("..")
        .join(agent.logs.0.file_name().unwrap())
        .join(format!("{id}.log"));

    let mut url = url::Url::parse(&format!("ws://{}/api/files/stream", agent.addr)).unwrap();
    url.query_pairs_mut().append_pair("path", &roundabout.to_string_lossy());
    let mut req = url.as_str().into_client_request().unwrap();
    req.headers_mut()
        .insert("Authorization", format!("Bearer {token}").parse().unwrap());
    let (mut ws, _) = tokio_tungstenite::connect_async(req).await.expect("the file streams");
    let first = tokio::time::timeout(Duration::from_secs(10), ws.next()).await.unwrap().unwrap().unwrap();
    assert!(first.to_text().unwrap().contains("--- EXECUTION LOG ---"));

    let record = crate::audit::test_capture::matching("user", &viewer)
        .into_iter()
        .find(|r| r["event_type"] == "file_access")
        .expect("file access is audited");
    assert_eq!(record["decision"], "allow");
    assert_eq!(record["file"]["path"], roundabout.to_string_lossy().as_ref());
    let resolved = std::fs::canonicalize(&direct).unwrap();
    assert_eq!(record["file"]["resolved_path"], resolved.to_string_lossy().as_ref());
}

/// Wait until the run's log contains `needle`.
async fn log_containing(agent: &TestAgent, execution_id: &str, needle: &str) -> String {
    let path = agent.logs.0.join(format!("{execution_id}.log"));
    for _ in 0..200 {
        if let Ok(bytes) = std::fs::read(&path) {
            let text = String::from_utf8_lossy(&bytes).into_owned();
            if text.contains(needle) {
                return text;
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("run {execution_id}: no {needle:?} in {:?}", std::fs::read_to_string(&path));
}

#[tokio::test]
async fn output_past_the_limit_is_cut_and_shutdown_stops_running_commands() {
    let agent = TestAgent::start().await;
    // `ping-pair`: 30 seconds, more than 10 bytes of output, two approvals.
    let bundle = agent.request_for("ping-pair", json!({}), &[ALICE, BOB]);
    let started = std::time::Instant::now();
    let id = execution_id(agent.execute(&bundle, Some(&agent.viewer_token("carol"))).await).await;

    // The log keeps the first 10 bytes and says it stopped there; the
    // command itself is left running.
    let log = log_containing(&agent, &id, "--- OUTPUT TRUNCATED").await;
    let output = log.split("---------------------\n").nth(1).expect("output follows the header");
    let kept = output.split("\n--- OUTPUT TRUNCATED").next().unwrap();
    assert_eq!(kept.len(), 10, "{log}");
    assert!(!log.contains("--- EXIT") && !log.contains("--- STOPPED"), "{log}");

    // The agent shuts down: the command is stopped, and says why.
    agent.runs.stop_all(Duration::from_secs(10)).await;
    let log = agent.finished_log(&id).await;
    assert!(log.contains("--- STOPPED: the agent shut down"), "{log}");
    assert!(started.elapsed() < Duration::from_secs(15), "the 30s command was cut short");

    let records = audit_of(&bundle);
    let finished = records.iter().find(|(e, _, _)| e == "command_finished").expect("finish record");
    assert_eq!(finished.2["outcome"]["result"], "agent_shutdown");
    assert_eq!(finished.2["outcome"]["output_truncated"], true);

    // Nothing new starts on an agent that is shutting down.
    let late = agent.execute(&agent.request(&[ALICE]), Some(&agent.viewer_token("carol"))).await;
    assert_eq!(late.status(), 503);
}

#[tokio::test]
async fn cors_allows_the_configured_origins_or_any() {
    let env = new_env();
    let logs = TempDir::new("agent-logs");
    let http = reqwest::Client::new();
    let allowed_for = |cors: Vec<String>, origin: &'static str| {
        let state = TestAgent::state(&env, test_config(&logs.0));
        let http = http.clone();
        async move {
            let addr = TestAgent::serve_with_cors(state, &cors).await;
            let resp = http
                .get(format!("http://{addr}/api/commands"))
                .header("Origin", origin)
                .send()
                .await
                .unwrap();
            resp.headers()
                .get("access-control-allow-origin")
                .map(|v| v.to_str().unwrap().to_string())
        }
    };

    // Named origins: only those.
    let named = vec!["https://ui.example".to_string()];
    assert_eq!(allowed_for(named.clone(), "https://ui.example").await.as_deref(), Some("https://ui.example"));
    assert_eq!(allowed_for(named, "https://other.example").await, None);
    // "*": any origin (this used to stop the agent at startup).
    assert_eq!(allowed_for(vec!["*".to_string()], "https://other.example").await.as_deref(), Some("*"));
    // None configured: no CORS headers at all.
    assert_eq!(allowed_for(vec![], "https://ui.example").await, None);
}

#[tokio::test]
async fn an_absurd_tail_length_is_just_the_whole_file() {
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;

    let agent = TestAgent::start().await;
    let token = agent.viewer_token("bob");
    let id = execution_id(agent.execute(&agent.request(&[ALICE]), Some(&token)).await).await;
    agent.finished_log(&id).await;

    let mut url = url::Url::parse(&format!("ws://{}/api/files/stream", agent.addr)).unwrap();
    url.query_pairs_mut()
        .append_pair("path", &agent.logs.0.join(format!("{id}.log")).to_string_lossy())
        .append_pair("tail_lines", &u64::MAX.to_string());
    let mut req = url.as_str().into_client_request().unwrap();
    req.headers_mut()
        .insert("Authorization", format!("Bearer {token}").parse().unwrap());
    let (mut ws, _) = tokio_tungstenite::connect_async(req).await.expect("the file streams");
    let first = tokio::time::timeout(Duration::from_secs(10), ws.next()).await.unwrap().unwrap().unwrap();
    assert!(first.to_text().unwrap().starts_with("--- EXECUTION LOG ---"), "{first:?}");
}
