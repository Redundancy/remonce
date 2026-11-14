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

/// An agent config with one runnable command, `ping-test`, which the
/// shipped policy publishes requirements for (one approval and an executor,
/// both in `webapp-users`).
pub(crate) fn test_config(logs_dir: &std::path::Path) -> crate::config::Config {
    let (executable, args) = echo_command();
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
"#,
        logs = logs_dir.to_string_lossy(),
        policy = concat!(env!("CARGO_MANIFEST_DIR"), "/policy"),
    );
    crate::config::parse(&text).expect("test config parses")
}

pub(crate) struct TestAgent {
    pub env: Env,
    pub addr: std::net::SocketAddr,
    pub logs: std::sync::Arc<TempDir>,
    pub http: reqwest::Client,
}

impl TestAgent {
    /// Serve `state`'s router on a loopback port.
    pub(crate) async fn serve(state: AgentState) -> std::net::SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = build_router(state, &[]);
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
        }
    }

    pub(crate) async fn start() -> Self {
        let env = new_env();
        let logs = std::sync::Arc::new(TempDir::new("agent-logs"));
        let state = Self::state(&env, test_config(&logs.0));
        let addr = Self::serve(state).await;
        TestAgent {
            env,
            addr,
            logs,
            http: reqwest::Client::new(),
        }
    }

    /// The same agent, as seen by people whose tokens come from `env`.
    pub(crate) fn with_env(&self, env: Env) -> Self {
        TestAgent {
            env,
            addr: self.addr,
            logs: self.logs.clone(),
            http: self.http.clone(),
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
        let command = json!({
            "command": "ping-test",
            "id": uuid::Uuid::new_v4().to_string(),
            "target_machines": [HOST],
            "params": { "count": "42" },
        });
        let now = OffsetDateTime::now_utc();
        RequestBundle {
            approvals: approvers.iter().map(|who| approve(&self.env, *who, &command, now)).collect(),
            command,
        }
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
                && (text.contains("--- EXIT") || text.contains("--- TIMEOUT") || text.contains("--- WAIT ERROR"))
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
