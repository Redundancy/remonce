# Use Cases

Concrete scenarios that map a real operational need onto Remonce's primitives. Each one shows what people do, what configuration the agent needs, and what policy publishes.

The primitives in play across all of these:

- **Request** — a command (what, where, with which parameters, and a unique `id`) handed around as a file.
- **Approval** — one person's signature over a request, each with its own fresh login and one-time key. Valid for the command's `approval_validity` (default 1 hour). A request collects as many as it needs, in any order, from different people.
- **Executor** — whoever submits the approved request, identified by their ordinary (viewer) login. Never anonymous, and subject to policy like everyone else.
- **Requirement document** — policy's statement of what a command needs: which approvals (one slot per person) and who may execute. The agent publishes it in its catalog, so the UI shows it next to the command.
- **Signer + agent** — the signer (`remonce web`) runs on each person's workstation; the agent (`remonce agent`) runs on the target and serves its catalog.

---

## Use case 1 — "I'm deploying a new VM and need to test/inspect it without enabling SSH"

**Scenario.** You're spinning up `host-canary-04`. You want to run `cloud-init status`, check `/var/log/cloud-init.log`, and run a smoke-test command without ever putting an SSH key on the box. You're the only person involved.

**Identities.** Just you: you approve, then you execute.

**Flow.**

1. The agent is provisioned by your image with `remonce agent` running under TLS (Files-mode self-signed cert if no public DNS, or ACME if reachable).
2. From your workstation: `remonce web` is already running on loopback. Select the new agent in the Agent field; the Commands page shows what it offers.
3. Prepare `check-cloud-init`, **Approve** (you log in again for the signature), then **Execute now**. The Runs page streams the output.
4. For files: the agent's `[[files]]` config exposes a read-only allowlist. The Files page lists what's available and streams the contents.

**Agent config.**

```toml
[[commands]]
name = "check-cloud-init"
description = "Run cloud-init status and recent log lines"
opa_rule = "data.remonce.authz.decision"
executable = "cloud-init"
args = ["status", "--long"]
command_timeout = "30s"
env = { PATH = "/usr/bin:/bin" }

[[files]]
path = "/var/log/cloud-init.log"
name = "cloud-init"
description = "Cloud-init log"
```

**Requirement document.**

```json
"check-cloud-init": {
  "approvals": [ { "description": "a VM deployer", "any_of": [ { "op": "contains", "claim": "groups", "value": "vm-deployers" } ] } ],
  "executors":   { "description": "a VM deployer", "any_of": [ { "op": "contains", "claim": "groups", "value": "vm-deployers" } ] }
}
```

File reads are a separate policy decision (`read_file`) on the viewer token's claims.

**UI status.** ✅ Fully supported: Commands → Prepare → Approve → Execute now.

---

## Use case 2 — "CI runs sensitive actions on VMs as part of an approved workflow"

**Scenario.** Your deploy pipeline needs to run `restart-app-tier` on production VMs as the last step of a release. You don't want a static credential on the runner, and you don't want CI alone to decide what runs in prod. A human approves the release; the CI runner executes it later.

**Identities.**

- **Approver:** the human who approves the release, in `release-approvers`.
- **Executor:** the CI workload, with its own identity and claims like `workflow == "deploy-prod"`.

**Flow.**

1. The release approver prepares the request and approves it (`remonce approve`, or the UI), producing `….approval.json`.
2. The file is handed to CI as a build artifact or stored in the release record.
3. At the deploy step, CI submits it (`remonce submit`, or `POST /execute` with its token as `Authorization: Bearer`). CI doesn't sign anything; it is identified as the executor.
4. The agent verifies the approval (still within `approval_validity`, e.g. 1 day for this command), and policy checks that it came from a release approver and that the executor is the deploy workflow. The replay cache refuses a second run of the same request: a retried pipeline needs a new request, approved again.

**Agent config.**

```toml
[[commands]]
name = "restart-app-tier"
description = "Rolling restart of webapp processes"
opa_rule = "data.remonce.authz.decision"
executable = "/usr/local/bin/restart-app"
command_timeout = "5m"
env = { PATH = "/usr/local/bin:/usr/bin:/bin" }
approval_validity = "1d"
```

**Requirement document** plus an extra rule, because `any_of` is OR and this needs two claims to hold together:

```json
"restart-app-tier": {
  "approvals": [ { "description": "a release approver", "any_of": [ { "op": "contains", "claim": "groups", "value": "release-approvers" } ] } ],
  "executors":   { "description": "the deploy-prod workflow", "any_of": [ { "op": "equals", "claim": "workflow", "value": "deploy-prod" } ] },
  "additional_policy": "Only from the acme/webapp repository"
}
```

```rego
extra_denials contains "restart-app-tier runs only from acme/webapp" if {
    input.action == "execute"
    input.command.command == "restart-app-tier"
    input.executor.claims.repository != "acme/webapp"
}
```

**UI status.** ⚠️ Supported in the protocol; the identity is the gap. Approving is a human step and works today. Submitting needs no nonce-bound key any more, but CI still needs an ID token **from the configured issuer, for the viewer client**. Platform issuers (GitHub Actions OIDC) are different issuers, so today this means minting the token through your IdP (for example Vault's JWT auth plus an identity token for that client). A first-class machine-executor path is on the roadmap (see PRODUCTION_READINESS.md).

---

## Use case 3 — "Authorize a NOC operator to perform actions on my behalf"

**Scenario.** You're going on call rotation but you'll be asleep at 3am. There's a runbook for "fail over the database to the secondary" that you trust the L2 NOC to execute, but you want your name on the authorization. You approve it in advance; the NOC operator runs it when the alert fires.

**Identities.**

- **Approver:** you, in `oncall-managers`.
- **Executor:** the NOC engineer who handles the alert, in `noc-l2`.

**Flow.**

1. Before bed, you prepare `db-failover` and approve it. Its `approval_validity` is set long enough to cover the night.
2. You attach `….approval.json` to the runbook ticket. There's nothing in it worth more than this one run: it can't be edited, it runs once, and only someone policy accepts as executor can submit it.
3. At 3am the NOC engineer opens the file on **Execute**, checks what was approved and by whom, and presses **Execute**. They don't sign anything; their login identifies them.
4. The audit log and run log record both: you approved, they executed.

**Agent config.**

```toml
[[commands]]
name = "db-failover"
opa_rule = "data.remonce.authz.decision"
executable = "/usr/local/bin/db-failover"
approval_validity = "12h"
```

**Requirement document** plus a separation-of-duties rule:

```json
"db-failover": {
  "approvals": [ { "description": "an on-call manager", "any_of": [ { "op": "contains", "claim": "groups", "value": "oncall-managers" } ] } ],
  "executors":   { "description": "NOC L2", "any_of": [ { "op": "contains", "claim": "groups", "value": "noc-l2" } ] },
  "additional_policy": "The executor can't be one of the approvers"
}
```

```rego
extra_denials contains "An approver can't also execute this request" if {
    input.action == "execute"
    input.command.command == "db-failover"
    some a in input.approvers
    a.claims.sub == input.executor.claims.sub
}
```

Comparing `sub` across the signing and viewer clients works when the IdP issues the same subject to both (Vault uses the entity id). With an IdP that issues pairwise subjects per client, compare a stable claim such as `email` instead.

**UI status.** ✅ Fully supported: Approve, save the file; the NOC engineer opens it on Execute. Or `remonce submit` from a terminal.

---

## Use case 4 — "I trigger actions on someone else's VMs as part of my role"

**Scenario.** You're a platform-ops engineer. The webapp team owns `host-webapp-{01..99}`, but you're authorized to run a fixed menu of actions there (restart services, collect diagnostics) without having to wake them up. There's no per-action sign-off by another person — the *role* is what authorizes you.

**Identities.** Just you: you approve and execute.

**Flow.**

1. The webapp team operates the agents on `host-webapp-*`. Their config exposes the platform-ops-friendly commands and points at the shared OPA policy.
2. From your workstation: select one of their agents, pick a command, approve, execute. Same as use case 1.
3. Policy accepts your approval because of your group. Your action runs, and the audit log shows your identity and the team's host.

**Agent config** (on the webapp team's hosts):

```toml
[[commands]]
name = "restart-webapp"
opa_rule = "data.remonce.authz.decision"
executable = "/usr/local/bin/restart-webapp"
command_timeout = "2m"
env = { PATH = "/usr/local/bin:/usr/bin:/bin" }

[[commands]]
name = "collect-diagnostics"
opa_rule = "data.remonce.authz.decision"
executable = "/usr/local/bin/collect-webapp-diag"
command_timeout = "5m"
env = { PATH = "/usr/local/bin:/usr/bin:/bin" }

[[commands]]
name = "rotate-logs"
opa_rule = "data.remonce.authz.decision"
executable = "/usr/local/bin/rotate-webapp-logs"
```

**Requirement documents** (with the webapp team's policy bundle):

```json
"restart-webapp": {
  "approvals": [ { "description": "webapp team or platform-ops", "any_of": [
    { "op": "contains", "claim": "groups", "value": "webapp-team" },
    { "op": "contains", "claim": "groups", "value": "platform-ops" } ] } ],
  "executors": { "description": "webapp team or platform-ops", "any_of": [
    { "op": "contains", "claim": "groups", "value": "webapp-team" },
    { "op": "contains", "claim": "groups", "value": "platform-ops" } ] }
},
"rotate-logs": {
  "approvals": [ { "description": "the webapp team", "any_of": [ { "op": "contains", "claim": "groups", "value": "webapp-team" } ] } ],
  "executors":   { "description": "the webapp team", "any_of": [ { "op": "contains", "claim": "groups", "value": "webapp-team" } ] }
}
```

`collect-diagnostics` is the same as `restart-webapp`. Platform-ops get a *subset*: they can restart and diagnose, but not rotate logs (which needs awareness of log shipping). The documents are the contract, and the Commands page shows each person what they'd need.

**UI status.** ✅ Fully supported.

---

## Use case 5 — "Changes that need two people"

**Scenario.** Restarting the primary database needs a DBA and someone from security to agree, and only the on-call SRE runs it.

**Flow.**

1. The DBA prepares `restart-db`, approves it, and sends `….approval.json` to security. The UI shows "1 of 2 needed" and which slot is still open.
2. Security opens it under **Sign a request**, sees the DBA's approval and what's missing, and approves. (The same person approving twice is refused.)
3. The on-call SRE opens the file on **Execute** and runs it.

**Requirement document.**

```json
"restart-db": {
  "description": "A DBA and security must both agree",
  "approvals": [
    { "description": "a DBA",    "any_of": [ { "op": "contains", "claim": "groups", "value": "dba" } ] },
    { "description": "security", "any_of": [ { "op": "contains", "claim": "groups", "value": "security" } ] }
  ],
  "executors": { "description": "on-call SRE", "any_of": [ { "op": "contains", "claim": "groups", "value": "sre-oncall" } ] }
}
```

Each slot needs a *different* person. Someone in both `dba` and `security` still fills only one slot, and policy finds a valid assignment whatever order the approvals arrive in.

**UI status.** ✅ Fully supported. The dev stack ships `ping-pair` (two approvals) with two Vault users, `webapp` and `webapp2`, to try it.

---

## Patterns and trade-offs

- **One approval is the common case.** Cases 1 and 4: approve, execute, done. More approvals are for commands where one compromised or mistaken account shouldn't be enough.
- **Executing is separate from approving.** Whoever holds a complete request can submit it from any machine, but they are always identified, and `executors` decides who that may be. Hand a request to the person who'll run it; don't make them re-approve. Approvers may execute their own requests by default (the one-person case needs it); where you want separation of duties, add it per command as in use case 3.
- **Requirements belong to policy, not the requester.** Nothing in a request says what it needs, so nobody can weaken it by editing the file. Change a command's requirements in one place (the document) and every agent's catalog shows it.
- **Keep extra Rego visible.** Anything the predicate language can't express goes in `extra_denials`, with `additional_policy` set so people see that more applies.
- **Replay safety is automatic.** A request runs once per agent. Running the same thing again is a new request (new `id`), approved again.
- **The wire format is portable.** Requests are plain JSON. Email them, attach them to tickets, paste them into chat — the signatures protect them, not the channel.
