# Configuration Guide

This document identifies the configuration options available for Remonce, including authentication, authorization, and security settings.

## Configuration File (`config.toml`)

Both `remonce web` (the signer) and `remonce agent` (the executor) read the same `config.toml` from the current working directory. Each binary only uses the sections relevant to it.

Unknown keys are rejected at startup: a misspelled setting (say `approval_valid` instead of `approval_validity`) fails loudly instead of silently falling back to a default.

### Deployment model

Remonce is designed around a split:

- **`remonce web`** — the **signer** runs on the user's own workstation, always on loopback. It hosts the OIDC login, the approval UI, and the proxy through which the browser reaches agents. Because nothing crosses the network, TLS on this tier is unnecessary and the server **refuses to bind anything other than `127.0.0.1` / `::1`**.
- **`remonce agent`** — runs on the remote target server, publishes its command catalog, and runs approved requests submitted over the network. It is the one network-facing component, so **TLS is mandatory**. There is no plaintext mode.

### The `--insecure` flag

Several config knobs broaden the trust surface in ways we consider dangerous by default. The agent refuses to start if any of them are set, unless you pass `--insecure` on the command line:

```bash
remonce --insecure agent       # or: remonce --insecure web
```

With `--insecure` active, the agent logs a loud warning banner at startup listing every active gate, and every audit log entry carries `"insecure": true` so post-incident review can see that the run was in a degraded posture. The flag is blunt on purpose — it's meant to be visible, not convenient.

Currently gated settings:

| Setting | Why it's gated |
|---------|----------------|
| `oidc.issuer_url` is `http://` and non-loopback | JWKS fetch at startup is MITM-able; compromises the entire identity trust chain |
| `timestamp_authority.trust_system_store = true` | Trusts every CA in the OS store as a TSA signer (hundreds of CAs) |
| `commands[].approval_validity > 7d` | Approvals that stay usable for weeks are standing credentials, and the replay cache must remember them as long |
| `opa_url` is `http://` and non-loopback | OPA's answer *is* the authorization decision; a MITM could return `allow` |
| `agent.cors_allowed_origins` contains `"*"` | Allows any browser origin to call the agent |

Loopback HTTP for OIDC (e.g., local Vault in dev) is **not** gated — it stays fine without the flag.

A few settings are refused outright, even with `--insecure`, because they are wrong rather than risky:

| Setting | Why it's refused |
|---------|------------------|
| `oidc.client_id` empty | There is no signing client |
| `oidc.viewer_client_id` equal to `oidc.client_id` (or empty) | Every signing token would also be a viewing and executing bearer token |
| `oidc.signing_max_age` above 5 minutes | Agents reject logins older than that, so no signature could verify |
| `commands[].approval_validity = "0s"` | No approval could ever be used |

### Web tier settings (`remonce web`)

Loopback-only binding and storage paths.

```toml
# Interface and port to bind the signer UI to.
# Must resolve to a loopback address (127.0.0.0/8 or ::1).
# Default: "127.0.0.1:8080"
listen_address = "127.0.0.1:8080"

# Directory where execution logs will be stored.
# Default: "logs"
logs_dir = "logs"

# Agent the web UI talks to. The browser never contacts the agent directly:
# the signer proxies the catalog, executions, /ws/* log streams and
# revocations to this URL over TLS. Must be https://. Because the signer
# makes the calls, "localhost" here means the machine running the signer;
# the UI labels such URLs with the signer's hostname.
# Default: "https://localhost:10022"
agent_url = "https://agent.example.com:10022"

# Other agents the UI may be pointed at. The agent box in the UI can only
# select agent_url or one of these; any other URL is refused, because the
# signer sends the user's viewer token and approvals to whichever agent is used.
allowed_agent_urls = ["https://db01.example.com:10022", "https://web01.example.com:10022"]

# Optional: PEM file with extra CA roots trusted when the signer connects to
# the agent (e.g. a self-signed agent cert or private CA). System roots are
# always trusted; this is additive.
agent_ca_path = "./certs/agent-fullchain.pem"
```

### Web tier TLS (optional)

Because the signer only accepts loopback connections, TLS here is purely optional and most deployments can skip it. The configuration shape matches the agent's TLS block below.

```toml
[tls]
mode = "files"
chain = "./certs/fullchain.pem"
key = "./certs/privkey.pem"
```

### Agent settings (`remonce agent`) — **required**

The agent requires an `[agent]` block with TLS configured. Startup will fail with a clear error if it is missing.

```toml
[agent]
# Address the agent listens on. Typically 0.0.0.0 for remote access.
# Default: "0.0.0.0:10022"
listen_address = "0.0.0.0:10022"

# CORS origins allowed to call the agent. Empty = no CORS layer (recommended
# unless a browser app talks to the agent directly).
cors_allowed_origins = []
```

### Agent TLS — **required**

#### Mode: Files (recommended for local dev with a self-signed cert)

```toml
[agent.tls]
mode = "files"
chain = "./certs/agent-fullchain.pem"
key   = "./certs/agent-key.pem"
```

Generate a self-signed cert for local testing with e.g. `rcgen`, `mkcert`, or `openssl`:

```bash
openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
  -keyout certs/agent-key.pem -out certs/agent-fullchain.pem \
  -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
  -addext "basicConstraints=critical,CA:FALSE"
```

`CA:FALSE` matters: `openssl req -x509` otherwise marks the certificate as a CA, and the signer's WebSocket client (used for log and file streaming) rejects a CA certificate presented as a server certificate.

Certificates are hot-reloaded on change.

#### Mode: ACME (production)

```toml
[agent.tls]
mode = "acme"
domains = ["agent.example.com"]
email = ["ops@example.com"]
cache_dir = "./certs/acme-cache"
# directory_url = "https://acme-staging-v02.api.letsencrypt.org/directory"  # for testing
```

> [!WARNING]
> ACME support is experimental. When first wiring up a new domain, point `directory_url` at Let's Encrypt **staging** to avoid hitting production rate limits.

### Identity (OIDC)

These settings connect the signer, agent and revocation service to your OIDC provider (Vault, Keycloak, etc.). Remonce uses **two clients**:

- the **signing** client (`client_id`): every approval and revocation is a fresh login to it, with a new ephemeral key bound through the `nonce` and forced re-authentication. Agents accept its tokens only inside approvals and revocations.
- the **viewer** client (`viewer_client_id`): the ordinary login. Its tokens are bearer credentials that agents accept on the read-only endpoints (catalog, files, logs) and as the **executor's identity** when a request is submitted.

```toml
[oidc]
# Base URL of the OIDC provider's issuer.
# Must match the 'iss' claim in your JWTs.
issuer_url = "http://127.0.0.1:8200/v1/identity/oidc/provider/vaultprovider"

# The signing client.
client_id = "your_signing_client_id"

# The viewer client. Must differ from client_id. Required by `remonce web`
# and `remonce agent` (it identifies whoever submits a request).
viewer_client_id = "your_viewer_client_id"

# max_age sent on signing logins. Default "1s": always re-authenticate
# (Vault rejects max_age=0). At most 5 minutes.
#signing_max_age = "1s"

# Also send prompt=login on signing logins, for IdPs that ignore max_age.
#signing_prompt_login = false

# Redirect URI for the OIDC callback, shared by both clients.
# Ensure this matches exactly what is registered in your OIDC provider.
redirect_uri = "http://localhost:8080/oidc/callback"
```

#### IdP requirements

- **Two clients**, both allowed to use the redirect URI and both permitted by the provider.
- **A single audience**: each token's `aud` must be exactly its client ID (a string, or a one-element array); `azp`, if present, must match. Tokens issued to several audiences are rejected, so don't add audience mappers to these clients.
- **`iat` and `auth_time`** in the ID token. OIDC requires `auth_time` whenever `max_age` is requested. Agents require a signing token to be timestamped within 5 minutes of its `iat`, and its `auth_time` to be within 5 minutes before `iat`.
- **`max_age` honored**, or `signing_prompt_login = true`. The signer checks a returned signing token and fails the flow with a clear error if the IdP didn't actually re-authenticate.
- **Token lifetime is up to you.** A signature's validity is measured from the login, not the token's `exp`, so long-lived tokens no longer widen any window. Keep viewer-token lifetimes short, though: those are bearer credentials.
### Authorization (OPA)

These settings determine how the agent checks permissions.

```toml
# URL of the Open Policy Agent service.
# If omitted, defaults to "http://localhost:8181".
opa_url = "http://127.0.0.1:8181"
```

Policy decisions requested by the agent (`input.action`):

| Action | When | Input |
|--------|------|-------|
| `execute` | Running an approved request | `command`, `request_id`, `approvers` (each `username`, `claims`, `signed_at`), `executor` (`username`, `claims`), `host` |
| `revoke` | Someone who didn't approve a request revokes it | `command`, `request_id`, `approvers`, `revoker`, `host` |
| `read_file` | Streaming an allowed file | `jwt`, `file` |
| `view_execution` | Streaming an execution's output log | `jwt`, `execution_id` |
| `view_docs` | Reading the agent's command catalog | `jwt` |

The agent also reads `data.remonce.requirements` (see [Requirement documents](#requirement-documents)) to publish in its catalog.

The agent's catalog, file and log-stream endpoints, and `/execute`, take the caller's **viewer** ID token as an `Authorization: Bearer` header (never a query parameter), and reject tokens for any other audience. The signer attaches it when proxying.

### Security & TSA (RFC 3161)

To ensure non-repudiation of executed commands, the agent verifies RFC 3161 Timestamp Tokens. Chain validation is performed by `rustls-webpki` and enforces the `id-kp-timeStamping` Extended Key Usage (RFC 3161 §2.3). Certificate validity is checked against the TSA's own `gen_time`, not wall-clock — a TSA cert that was valid when it signed will still verify historically, which is the correct semantics for timestamps.

```toml
[timestamp_authority]
# URL of the Time Stamping Authority.
url = "http://timestamp.digicert.com"

# Optional: path to a PEM file of additional trusted TSA roots. Adds to the
# bundled DigiCert root. Use this when you run a private internal TSA or
# prefer a non-DigiCert public TSA.
ca_path = "./tsa_chain.pem"

# Opt in to additionally trust every CA in the OS native trust store as a
# valid TSA signer. This broadens the trust surface to hundreds of CAs and
# is considered INSECURE — the agent refuses to start with this enabled
# unless `--insecure` is also passed on the command line.
trust_system_store = false
```

**Trust model:** the agent ships with **DigiCert Trusted Root G4** bundled into the binary (valid through 2038). This forms the default trust anchor and aligns with the default TSA URL (`http://timestamp.digicert.com`, DigiCert's free public TSA). DigiCert's intermediates ride the timestamp token itself; rotation of intermediates does not require a Remonce rebuild.

To use a different TSA, point `ca_path` at a PEM containing your TSA's root (or full chain). The bundled DigiCert root remains trusted unless you also disable — we don't provide a knob for that, but adding your own roots is strictly additive.

> [!NOTE]
> **Pre-0.1 behavior change.** Earlier versions trusted the OS native store by default, which effectively made every CA in the OS trust store a valid TSA signer. That's now opt-in via `trust_system_store = true` + `--insecure`.

### Commands

Define the commands that can be executed by the agent.

```toml
[[commands]]
name = "ping-test"
description = "Pings localhost for connectivity check."
opa_rule = "data.remonce.authz.decision" # The OPA rule to query for authorization
executable = "ping"
args = ["-n", "4", "127.0.0.1"]

# Optional: wall-clock timeout. Once exceeded, the agent SIGKILLs the child
# and writes a TIMEOUT trailer into the execution log. Default: 5m.
command_timeout = "5m"

# Optional: environment variables passed to the child. The agent calls
# env_clear() before applying these — *no* parent-process env leaks
# through. If your executable needs PATH, add it explicitly.
env = { PATH = "/usr/bin:/bin" }

# Optional: how long each approval stays usable after the approver's login.
# Every approval in a request must still be valid when it runs. Default: 1h;
# above 7d needs --insecure.
approval_validity = "1h"
```

### Command parameters (`[[commands.params]]`)

Args templates may contain `{{name}}` placeholders, filled from a `params`
object in the signed command payload. Because `params` sits inside the
command object, it is covered by every approval — nobody can alter values
after approval.

```toml
[[commands]]
name = "restart-service"
opa_rule = "data.remonce.authz.decision"
executable = "systemctl"
args = ["restart", "{{service}}"]

[[commands.params]]
name = "service"                      # placeholder name: [A-Za-z_][A-Za-z0-9_]*
description = "Service to restart"    # shown in the UI
required = true                       # signer must supply a value
allowed = ["nginx", "postgres"]       # exact allow-list (highest precedence)

[[commands.params]]
name = "count"
default = "10"                        # used when omitted; must itself validate
min = 1                               # integer range (value must parse as i64)
max = 100

[[commands.params]]
name = "host"
pattern = '[a-z0-9-]+\.internal'      # anchored regex the full value must match
```

Validation is **fail-closed** and runs on the agent at execution time:

- Rule precedence per param: `allowed` > `min`/`max` > `pattern` > default rule.
- The default rule (no explicit validation) allows short alphanumeric-ish
  values (`[A-Za-z0-9._][A-Za-z0-9._-]{0,63}`) — notably **no leading dash**,
  which prevents injecting flags into the executable's argv.
- Unknown params, missing required params, type violations, and unresolved
  `{{placeholders}}` all reject the execution.
- Commands are spawned without a shell, so shell metacharacters are inert;
  the validation rules exist to constrain *argv* content.

> [!WARNING]
> If you write a custom `pattern` that admits values starting with `-`, a
> signer can inject flags into the executable's argv. Keep patterns tight.

OPA sees the validated `params` via `input.command.params`, so policies can
authorize per-value (e.g. only `oncall-managers` may restart `postgres`).

### Approval validity

Each approval is usable for the command's `approval_validity` (default 1 hour), measured from the signing login — the ID token's IdP-signed `iat` — as well as the TSA time. A TSA will timestamp any bytes, so a holder can always get a fresh timestamp over an old signature; the agent therefore also requires the TSA time to be within 5 minutes of `iat`, which a re-timestamp can't satisfy. An approval is usable until `iat + approval_validity`, whatever lifetime the IdP gives its tokens.

When a request needs several approvals, **all** of them must be valid when it runs, so the first approver's clock is the one that matters: collect approvals within the window, or set a longer one for commands whose approvals take time to gather. The replay cache remembers a run for the same window, so a longer validity also means more memory held per run.

### Requirement documents

What a command needs before it runs — how many approvals, from whom, and who may submit it — is published by policy, as OPA data at `data.remonce.requirements[<command>]`. The shipped policy loads it from [policy/requirements.json](policy/requirements.json) (OPA mounts JSON files in the policy directory under their `data` path):

```json
{
  "remonce": {
    "requirements": {
      "restart-db": {
        "description": "A DBA and security must both agree",
        "approvals": [
          { "description": "a DBA", "any_of": [ { "op": "contains", "claim": "groups", "value": "dba" } ] },
          { "description": "security", "any_of": [ { "op": "contains", "claim": "groups", "value": "security" } ] }
        ],
        "executors": { "description": "on-call SRE", "any_of": [ { "op": "contains", "claim": "groups", "value": "sre-oncall" } ] },
        "additional_policy": "Only on db-* hosts"
      }
    }
  }
}
```

| Field | Meaning |
|---|---|
| `approvals` | Up to 8 **slots**. Each needs its own approver, a different person per slot, whose claims match one of its predicates. `[]` means one approval from anyone. |
| `executors` | Who may submit the request (their viewer login's claims). |
| `any_of` | Predicates: `{"op": "contains", "claim", "value"}` (claim is an array containing `value`) or `{"op": "equals", "claim", "value"}`. `[]` means anyone; a missing `any_of` means no one. |
| `description` | Shown to people instead of the raw predicates (optional, on the document and on each slot). |
| `additional_policy` | A description of rules the policy adds beyond the document (optional). Set it whenever `authz.rego` denies more than the document says. |

The agent serves each command's document in its catalog (`GET /api/commands`), so the UI can show what a command needs and which slots a request's approvals already fill. The shipped [policy/authz.rego](policy/authz.rego) allows an execution exactly when `lib.satisfied(requirement, input)` holds and no `extra_denials` rule fires, and denies a command with no document. The agent verifies every approval before asking, and rejects two approvals from the same person outright.

Run the policy tests with `bin/opa test policy policy_test`. One of them checks that meeting each published document is enough to be allowed (unless it declares `additional_policy`), so the documents can't silently drift from the rules.

## Handing requests and approvals to someone

Requests travel as files (or as the same JSON pasted), so they work across any path you already use: chat and ticket attachments, email, SCP, remote-desktop clipboard or file transfer. The web UI saves them as:

| File | Contains | Open it in |
|---|---|---|
| `remonce-<command>-<id>.request.json` | A request with no approvals yet | **Sign a request** |
| `remonce-<command>-<id>.approval.json` | A request with one or more approvals | **Sign a request** (to add yours) or **Execute** (once it has enough) |

On those pages, drop the file onto the input panel, use **Open file…**, or paste anywhere on the page. Files are read in the browser and never uploaded. Both pages show the approvals so far and, from the selected agent's catalog, which requirement slots they fill. They are the same JSON the CLI reads.

## CLI (`remonce approve`, `remonce submit`)

Approve and run requests without the web UI:

```bash
# Add your approval ('-' reads stdin; -o writes the result instead of stdout)
remonce approve --bundle remonce-backup-db-1a2b3c4d.request.json -o remonce-backup-db-1a2b3c4d.approval.json

# Submit an approved request to an agent; you log in (viewer client) as the executor
remonce submit --bundle remonce-backup-db-1a2b3c4d.approval.json --agent https://db01.example.com:10022
```

The commands read `[oidc]` and `agent_url` / `agent_ca_path` from `config.toml`. `approve` generates a fresh ephemeral keypair, runs a browser-based OIDC authorization-code flow against the signing client (PKCE, the nonce bound to the ephemeral key, and forced re-authentication — the same as the web UI), obtains an RFC 3161 timestamp on the signature, and appends the approval. It refuses to add a second approval from someone who already approved. `submit` runs an ordinary login to the viewer client and sends the request with that token.

- `--agent <url>` overrides `agent_url`. Must be `https://`.
- The OIDC redirect listener binds the host/port from `oidc.redirect_uri`. If `remonce web` is already running on that port, use its pages instead.
- A bare command object (`{"command": "name", "id": …}`) is accepted as a request with no approvals.
- Note for CI: tokens minted by platform OIDC issuers (e.g. GitHub Actions) cannot carry a custom nonce, so they cannot bind an ephemeral key. Approving is for humans; machine flows need an issuer that honors the `nonce` parameter.

## Revoking a request (`remonce revoke`)

A request can be cancelled before it runs by submitting it, with at least one of its approvals, to the agent's `POST /revoke` endpoint together with a fresh, nonce-bound attestation from the revoker:

```bash
# '-' reads stdin
remonce revoke --bundle remonce-backup-db-1a2b3c4d.approval.json

# Target a specific agent
remonce revoke -b remonce-backup-db-1a2b3c4d.approval.json --agent https://agent.example.com:10022
```

The same flow is on the web UI's Execute page (**Revoke request**), which runs its own re-authenticating login and submits the revocation to the selected agent.

How it works:

- A revocation cancels the **whole request**, by request id (the hash of the signed request). Neither its current approvals nor any later ones can run it.
- The revoker signs a domain-separated payload, `REMONCE-REVOKE/v2:` || request id || their public key, which is never valid as an approval (and an approval is never valid as a revocation).
- The agent re-verifies the request's approvals first (they needn't still be fresh). Only requests with a genuine approval can be pinned to the revocation list, which prevents filling it with invented requests.
- **Any approver** of the request (same OIDC `sub`) may always revoke it. **Anyone else** needs an OPA decision with `input.action == "revoke"` (see `policy/authz.rego`).
- The revoker's attestation must be at most 10 minutes old.
- A revocation lasts until no approval of the request could still be valid (`approval_validity` after the latest approver's login).

Without a central revocation service (below), the revocation list is **in-memory and per-agent**: submit the revocation to every agent the request targets, and note that an agent restart forgets it.

## Central revocation service (`remonce revocation-service`)

For multi-agent estates, run a single revocation service so one submission revokes everywhere, durably:

```toml
[revocation_service]
listen_address = "0.0.0.0:10023"
persist_path = "revocations.jsonl"   # survives restarts; compacted on load
retention = "30d"                    # keep revocations at least this long (default 30d)

[revocation_service.tls]
mode = "files"                        # or "acme", same options as [agent.tls]
chain = "certs/revocation-cert.pem"
key = "certs/revocation-key.pem"
```

Then point each agent at it:

```toml
[agent]
revocation_service_url = "https://revocations.example.com:10023"
# revocation_service_ca_path = "certs/revocation-cert.pem"  # for self-signed certs
```

Semantics:

- The service exposes the same `POST /revoke` endpoint as the agent and performs the **same full verification** (genuine approvals, revoker attestation, approver-vs-third-party OPA check) — it cannot be poisoned with unverified entries. `remonce revoke --agent https://revocations...` can therefore target it directly.
- When `revocation_service_url` is set, the agent checks `GET /v2/revoked/{request_id}` (64 lowercase hex characters) before every execution, and a revocation submitted to any agent is forwarded to the service.
- **Fail-closed**: if the service is configured but unreachable, the agent denies execution (`Revocation Check Failed`). A configured revocation service must be available — there is deliberately no fail-open mode.
- Revocations expire from the store once they can no longer matter (see `retention`); expired entries are compacted out of the JSONL file on service restart.
- The service reads the same `config.toml` sections as the agent (`[oidc]`, `[timestamp_authority]`, `[[commands]]`, `opa_url`), since it performs the same verification. It also accepts revocations for commands missing from its own `[[commands]]` (verified with the default `approval_validity`; third parties judged by the default OPA rule), since it serves agents whose command sets it may not mirror.
- `retention` must be at least the longest `approval_validity` any agent allows; each revocation is kept until the latest approver's `iat` plus the larger of the two.
- Writes are fsync'd before the service acknowledges them. A torn final line left by a crash is ignored at startup; corruption anywhere else refuses to start (agents then fail closed).

## Upgrading to per-signature logins

This release changes what agents accept, with no compatibility mode:

1. **Register two OIDC clients.** Create a new signing client (or reuse the old one) and a new viewer client, add both to the provider, and set `client_id` and `viewer_client_id`. See "IdP requirements" above; for Vault, [docs/idp/VAULT.md](docs/idp/VAULT.md).
2. **Upgrade the signer, CLI, agents and revocation service together.** Bundles signed by older signers lack the re-authentication evidence (and may carry high-S signatures), so agents reject them. Re-sign any outstanding approvals.
3. **Archive the revocation log.** The revocation service now records key bindings instead of signature hex, and refuses to start on an old `revocations.jsonl`. Move it aside; approvals it listed can't pass the new verification anyway.

## Upgrading to requests with independent approvals

This release replaces approver/operator bundles, again with no compatibility mode:

1. **Requests, not delegation.** A request is `{command, approvals}`; each approval is an independent signature over the same payload. `operator_requires`, co-signing and `remonce cosign` are gone. Signers, CLIs and agents reject each other's formats across versions, and name the old one when they see it. Re-create outstanding requests.
2. **Move rules into requirement documents.** What `operator_requires` said (who may run it) and any four-eyes rules (`not input.self_executed`) become a command's `executors` and `approvals` in `policy/requirements.json`; see [Requirement documents](#requirement-documents). OPA input changed: `input.approver` / `input.operator` / `input.self_executed` are replaced by `input.approvers`, `input.executor` and `input.request_id`. The shipped policy denies commands with no document.
3. **Replace validity settings.** `approver_max_validity` and `operator_max_validity` are replaced by `approval_validity`; the old keys are rejected with a hint.
4. **Agents need `viewer_client_id`.** Submitting a request now requires a viewer login, which identifies the executor.
5. **Upgrade agents and the revocation service together**, and archive the revocation log. Revocations are now by request id at `/v2/revoked/{request_id}`, and the service refuses to start on an older `revocations.jsonl`.
