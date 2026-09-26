# Use Cases

Concrete scenarios that map a real operational need onto Remonce's primitives. Each one shows what the operator does, what configuration the agent needs, and how the UI/CLI supports it.

The four primitives in play across all of these:

- **Approver bundle** — the cryptographic authorization. Long validity (default 3 days). Carries a command + optional `operator_requires`. Its presence (signed) marks the bundle as delegated — it must then be co-signed, and its claim predicates restrict who may do so; without it the bundle is self-execute only.
- **Operator cosign** — the at-execution-time freshness + attribution layer. Short validity (default 10 minutes).
- **OPA policy** — business-logic allow/deny. Sees both identities and `self_executed`.
- **Loopback signer + remote agent** — the signer (`remonce web`) runs on the operator's workstation; the agent (`remonce agent`) runs on the target.

---

## Use case 1 — "I'm deploying a new VM and need to test/inspect it without enabling SSH"

**Scenario.** You're spinning up `host-canary-04`. You want to run `cloud-init status`, check `/var/log/cloud-init.log`, and run a smoke-test command without ever putting an SSH key on the box. You're the only person involved — no delegation.

**Identities.** Just you. Approver and operator are the same OIDC identity. This is the `self_executed = true` path.

**Flow.**

1. The agent is provisioned by your image with `remonce agent` running under TLS (Files-mode self-signed cert if no public DNS, or ACME if reachable).
2. From your workstation: `remonce web` is already running on loopback.
3. You log in via OIDC, pick a command from the menu (e.g. `check-cloud-init`), the signer signs it. Because you submit immediately, the approver's TSA timestamp falls inside `operator_max_validity` (default 10 min) so no operator cosign is required.
4. Submit to `https://host-canary-04:10022/execute`. Agent verifies, runs the command, streams stdout/stderr back over the WebSocket.
5. For files: the agent's `[[files]]` config exposes a read-only allowlist (e.g. `path = "/var/log/cloud-init.log"`). The signer's Files page lists what's available and streams the contents.

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

**OPA policy snippet.**

```rego
allow if {
    input.command.command == "check-cloud-init"
    "vm-deployers" in input.approver.claims.groups
}

allow if {
    input.action == "read_file"
    "vm-deployers" in input.approver.claims.groups
}
```

**UI status.** ✅ Fully supported. Generate → Inspect & Sign → Execute is exactly this path. The Files page covers the read-only file flow.

---

## Use case 2 — "CI runs sensitive actions on VMs as part of an approved workflow"

**Scenario.** Your deploy pipeline needs to run `restart-app-tier` on production VMs as the last step of a release. You don't want a static credential on the runner, and you don't want CI alone to decide what runs in prod. A human approves the release, and the CI runner executes within a small window after approval.

**Identities.**

- **Approver:** the human who clicks "approve release" — has an OIDC identity in the `release-approvers` group.
- **Operator:** the CI workload — has its own OIDC identity (workload identity / GitHub OIDC / Vault JWT auth) with claims like `workflow == "deploy-prod"` and `repository == "acme/webapp"`.

**Flow.**

1. Human approves release in the dashboard. The signer produces an `ExecutionBundle` with `operator: null`, embedding `operator_requires` constraining the executor to specific CI claims:
   ```json
   "operator_requires": {
     "any_of": [
       { "op": "equals", "claim": "workflow",   "value": "deploy-prod" },
       { "op": "equals", "claim": "repository", "value": "acme/webapp" }
     ]
   }
   ```
   *(Note: `any_of` means at least one matches. For a strict AND of two claims you'd add the rule in OPA — see below.)*
2. The bundle is handed to CI as a build artifact (or stored in the release record).
3. The CI job, when it reaches the deploy step, cosigns the approver bundle with its own OIDC identity (`remonce cosign -b bundle.json --submit`) and submits the resulting `ExecutionBundle` to the agent's `/execute`.
4. Agent verifies: approver sig still within `approver_max_validity` (e.g. 1 day), CI's cosign within `operator_max_validity` (10 min), CI's claims satisfy `operator_requires`. The replay cache prevents the same cosign from being submitted twice.
5. If the CI run is retried, it produces a *new* cosign over the same approver bundle — a fresh execution with its own audit trail.

**Agent config.**

```toml
[[commands]]
name = "restart-app-tier"
description = "Rolling restart of webapp processes"
opa_rule = "data.remonce.authz.decision"
executable = "/usr/local/bin/restart-app"
command_timeout = "5m"
env = { PATH = "/usr/local/bin:/usr/bin:/bin" }
approver_max_validity = "1d"
operator_max_validity = "10m"
```

**OPA policy snippet** (enforces both approver group AND CI workflow):

```rego
allow if {
    input.command.command == "restart-app-tier"
    "release-approvers" in input.approver.claims.groups
    input.operator.claims.workflow == "deploy-prod"
    input.operator.claims.repository == "acme/webapp"
}
```

**UI status.** ✅ Supported, with one identity-provider caveat.
- ✅ The Generate page has an `operator_requires` builder; Inspect & Sign exports the approver bundle as copyable base64 or downloadable JSON.
- ✅ `remonce cosign` covers the executor side: reads the bundle from a file or stdin, does the cosign locally, and `--submit`s to the agent.
- ⚠️ Caveat: the cosigner's OIDC token must carry a `nonce` bound to its ephemeral key. Machine-minted tokens generally can't: GitHub Actions OIDC has fixed claims, and Vault's machine flows ([identity tokens](https://developer.hashicorp.com/vault/docs/secrets/identity/identity-token)) take no caller-selected nonce either. Until the planned machine-operator path lands (see PRODUCTION_READINESS.md), a human runs the cosign step.

---

## Use case 3 — "Authorize a NOC operator to perform actions on my behalf"

**Scenario.** You're going on call rotation but you'll be asleep at 3am. There's a runbook for "fail over the database to the secondary" that you trust the L2 NOC to execute, but you want your name on the authorization. You pre-sign the action; the NOC operator co-signs and runs it when the alert fires.

**Identities.**

- **Approver:** you, in `oncall-managers`.
- **Operator:** the NOC engineer who handles the alert, in `noc-l2`.

**Flow.**

1. Before bed, you sign the runbook command via the signer UI. You set `operator_requires` to require `groups contains "noc-l2"`. `approver_max_validity` defaults to 3 days.
2. You hand the bundle off — an attachment in the runbook ticket, a paste into a ChatOps thread, anything. There's no secret in the bundle that's worth more than a single execution.
3. At 3am the NOC engineer pages in. They open the ticket, copy the bundle, log into `remonce web` running on their laptop, paste the bundle into the Co-sign page, and re-authenticate when asked (every signature gets its own login).
4. Their workstation co-signs with a one-time key, then forwards the resulting `ExecutionBundle` to the agent. The agent verifies you authorized it, verifies them as a fresh cosigner with the right group, runs the action.
5. Audit log records both identities — you authorized, they executed.

**Agent config.** Same shape as use case 2, but `operator_requires` constrains to `noc-l2` and policy doesn't care about workflow claims.

**OPA policy snippet.**

```rego
allow if {
    input.command.command == "db-failover"
    "oncall-managers" in input.approver.claims.groups
    "noc-l2" in input.operator.claims.groups
    not input.self_executed
}
```

The `not input.self_executed` is a four-eyes constraint — even if you happen to also be in `noc-l2`, you can't both authorize and execute the same bundle. Drop the line if you don't need separation of duties.

**UI status.** ✅ Fully supported.
- ✅ The approver builds the delegation on the Generate page (operator-requirements builder), signs on Inspect & Sign, and exports via copy or Download JSON.
- ✅ The NOC side uses the **Cosign** page: paste the bundle, inspect the command + who approved it, co-sign, Execute Now — or `remonce cosign` from a terminal.

---

## Use case 4 — "I trigger actions on someone else's VMs as part of my role"

**Scenario.** You're a platform-ops engineer. The webapp team owns `host-webapp-{01..99}`, but you're authorized to run a fixed menu of actions there (restart services, collect diagnostics, rotate logs) without having to wake them up. There's no per-action approval — the *role* is what authorizes you.

**Identities.** Just you. Self-execute path. The "delegation" is structural (your group has standing authorization), not bundle-level.

**Flow.**

1. The webapp team operates the agents on `host-webapp-*`. Their config exposes the platform-ops-friendly commands and points at the shared OPA policy.
2. From your workstation: log in as you, pick a command, sign, submit. Same self-execute as use case 1.
3. The agent verifies your bundle, OPA evaluates against your claims (`team == "platform-ops"`), allows because the policy says so. Your action runs.
4. Audit log shows your identity and the team's host — clear attribution if anything goes wrong.

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
```

**OPA policy snippet** (lives with the webapp team's policy bundle):

```rego
# Webapp owners have full access.
allow if {
    "webapp-team" in input.approver.claims.groups
    input.command.command in {"restart-webapp", "collect-diagnostics", "rotate-logs"}
}

# Platform-ops can run the cross-team menu.
allow if {
    "platform-ops" in input.approver.claims.groups
    input.command.command in {"restart-webapp", "collect-diagnostics"}
}
```

Notice the platform-ops menu is a *subset* — they can restart and diagnose, but not rotate logs (which needs ops awareness of log shipping). The policy is the contract; nothing in the agent's command list is platform-ops-specific.

**UI status.** ✅ Fully supported. Identical to use case 1 from the operator's perspective — sign and submit. The cross-team part is entirely an OPA-policy concern.

---

## Patterns and trade-offs

A few cross-cutting notes that fall out of these four:

- **Self-execute is the default**. Cases 1 and 4 don't need the cosign machinery at all. Don't reach for delegation unless there's an actual time gap or an actual handoff between identities.
- **Delegation makes sense when the approver and executor are different identities at different times**. Cases 2 and 3 fit; case 4 (different identities at the *same* time, structurally authorized) doesn't — that's just OPA policy.
- **`operator_requires` is enforced before OPA**. Predicates expressible there (e.g. "in this group") are agent-level, fail-closed even if the OPA policy is buggy. Keep critical executor restrictions there; use OPA for richer business logic.
- **Replay safety is automatic**. The agent's in-memory replay cache means a single approver bundle can be cosigned by multiple operators (use case 2's CI retries) without each cosign being individually unique — what's gated is the *executor signature*.
- **The wire format is portable**. Approver bundles are plain JSON. Email them, attach them to tickets, paste them into Slack — the cryptography is what protects them, not the channel.

## Delegation tooling

The delegation use cases (2 and 3) are covered by:

1. **"Create a delegation"** — on the Generate page tick **Delegate** and optionally add `operator_requires` rows (claim/op/value); Inspect & Sign exports the signed approver bundle via copy-to-clipboard or Download JSON.
2. **Cosign page** (`/ui/cosign`) — paste an approver bundle, inspect the command + claimed approver identity (best-effort; the agent is the final authority), co-sign with your session identity, and submit.
3. **`remonce cosign` CLI** — reads an approver bundle from a file or stdin, runs its own browser-based OIDC login (PKCE + nonce-bound ephemeral key), cosigns locally, and writes the ExecutionBundle to stdout/a file or `--submit`s it to the agent. See CONFIGURATION.md.
