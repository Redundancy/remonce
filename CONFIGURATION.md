# Configuration Guide

This document identifies the configuration options available for Remonce, including authentication, authorization, and security settings.

## Configuration File (`config.toml`)

Both `remonce web` (the signer) and `remonce agent` (the executor) read the same `config.toml` from the current working directory. Each binary only uses the sections relevant to it.

Unknown keys are rejected at startup: a misspelled setting (say `max_validity` instead of `approver_max_validity`) fails loudly instead of silently falling back to a default.

### Deployment model

Remonce is designed around a split:

- **`remonce web`** — the **signer** runs on the operator's own workstation, always on loopback. It hosts the OIDC login + command-signing UI. Because nothing crosses the network, TLS on this tier is unnecessary and the server **refuses to bind anything other than `127.0.0.1` / `::1`**.
- **`remonce agent`** — the **executor** runs on the remote target server and accepts signed commands over the network. It is the one network-facing component, so **TLS is mandatory**. There is no plaintext mode.

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
| `commands[].operator_max_validity > 1h` | Effectively turns off the at-execution-time freshness bound |
| `opa_url` is `http://` and non-loopback | OPA's answer *is* the authorization decision; a MITM could return `allow` |
| `agent.cors_allowed_origins` contains `"*"` | Allows any browser origin to call the agent |

Loopback HTTP for OIDC (e.g., local Vault in dev) is **not** gated — it stays fine without the flag.

A few settings are refused outright, even with `--insecure`, because they are wrong rather than risky:

| Setting | Why it's refused |
|---------|------------------|
| `oidc.client_id` empty | There is no signing client |
| `oidc.viewer_client_id` equal to `oidc.client_id` (or empty) | Every signing token would also be a file/log viewing bearer token |
| `oidc.signing_max_age` above 5 minutes | Agents reject logins older than that, so no signature could verify |

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
# the signer proxies /api/agent/* and the /ws/* log streams to this URL over
# TLS, and submits revocations there. Must be https://.
# Default: "https://localhost:10022"
agent_url = "https://agent.example.com:10022"

# Other agents the UI may be pointed at. The agent box in the UI can only
# select agent_url or one of these; any other URL is refused, because the
# signer sends the user's viewer token and signatures to whichever agent is used.
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

- the **signing** client (`client_id`): every approval, cosign and revocation is a fresh login to it, with a new ephemeral key bound through the `nonce` and forced re-authentication. Agents accept its tokens only on the signing path.
- the **viewer** client (`viewer_client_id`): the ordinary login for browsing. Its tokens are bearer credentials that agents accept only on the read-only file and log endpoints.

```toml
[oidc]
# Base URL of the OIDC provider's issuer.
# Must match the 'iss' claim in your JWTs.
issuer_url = "http://127.0.0.1:8200/v1/identity/oidc/provider/vaultprovider"

# The signing client.
client_id = "your_signing_client_id"

# The viewer client. Must differ from client_id. Required by `remonce web`;
# an agent without it disables file and log viewing.
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
| `execute` | Running a signed command | approver/operator identities, `command`, `self_executed`, `host` |
| `revoke` | Someone other than the approver revokes an approval | approver identity, revoker as `operator` |
| `read_file` | Streaming an allowed file | `jwt`, `file` |
| `view_execution` | Streaming an execution's output log | `jwt`, `execution_id` |
| `view_docs` | Listing commands in the signer UI | `jwt` |

The agent's file and log-stream endpoints take the caller's **viewer** ID token as an `Authorization: Bearer` header (never a query parameter), and reject tokens for any other audience. The signer attaches it when proxying.

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

# Optional: delegation validity windows.
# approver_max_validity   — how long a pre-signed command remains usable
#                           after the approver signs. Default: 3d.
# operator_max_validity   — how fresh the *executing* signature (operator
#                           cosign, or approver sig when self-executing) must
#                           be at the moment of execution. Default: 10m.
approver_max_validity = "3d"
operator_max_validity = "10m"
```

### Command parameters (`[[commands.params]]`)

Args templates may contain `{{name}}` placeholders, filled from a `params`
object in the signed command payload. Because `params` sits inside the
command object, it is covered by the approver's signature — the operator
cannot alter values after approval.

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

### Delegation & signing validity

Remonce separates **authorization freshness** (approver) from **execution freshness** (operator):

| Setting | Default | Controls |
|---------|---------|----------|
| `approver_max_validity` | 3 days | How long a signed approval stays usable. A pre-authorized command can sit until the NOC picks it up, up to this limit. |
| `operator_max_validity` | 10 minutes | How recent the executor's signature must be. In a delegated flow this is the operator's cosign; in self-execute it's the approver's own. |

Both windows are measured from the signing login — the ID token's IdP-signed `iat` — as well as the TSA time. A TSA will timestamp any bytes, so a holder can always get a fresh timestamp over an old signature; the agent therefore also requires the TSA time to be within 5 minutes of `iat`, which a re-timestamp can't satisfy. A signature is usable until `iat + max_validity`, whatever lifetime the IdP gives its tokens, and the replay cache and revocation list keep their entries exactly that long.

**Self-execute vs delegated**: when the approver submits their own bundle immediately (no operator cosign), they must be within `operator_max_validity`. If you want longer self-execute windows, raise `operator_max_validity` — but remember this also lengthens the replay-cache window and the operator-side freshness bound.

### Operator constraints (`operator_requires`)

`operator_requires` is covered by the approver's signature and also decides the **delegation mode**:

| `operator_requires` | Meaning |
|---|---|
| absent / `null` | **Self-execute only.** The approver runs it within `operator_max_validity`; a co-sign is rejected. |
| `{ "any_of": [] }` | **Delegated to any operator** (subject to OPA). Self-execution is rejected. |
| `{ "any_of": [ ... ] }` | **Delegated with constraints.** The operator must match at least one predicate. |

In the web UI, choose **Delegate** when preparing a command (optionally adding requirements); `remonce cosign` refuses self-execute-only approvals up front.

The predicates are enforced by the agent *before* OPA:

```json
{
  "operator_requires": {
    "any_of": [
      { "op": "contains", "claim": "groups", "value": "noc-l2" },
      { "op": "equals",   "claim": "team",   "value": "webapp-oncall" }
    ]
  }
}
```

Semantics: if `any_of` is non-empty, at least one predicate must match the operator's OIDC token claims; an empty list means any authenticated operator in OPA's allow-set. Claims are evaluated at **execution time** against the operator's fresh token, so group changes propagate immediately. An approver co-signing their own delegation is reported to OPA as `self_executed: true`, so four-eyes rules still hold.

## Handing requests and approvals to someone

Requests, approvals and co-signed bundles travel as files (or as the same content pasted as base64), so they work across any path you already use: chat and ticket attachments, email, SCP, remote-desktop clipboard or file transfer. The web UI saves them as:

| File | Contains | Open it in |
|---|---|---|
| `remonce-<command>-<id>.request.json` | An unsigned request (`command` + `operator_requires`) | **Sign a request** |
| `remonce-<command>-<id>.approval.json` | A signed approval | **Execute** (self-execute) or **Sign a request** (delegated, to co-sign) |
| `remonce-<command>-<id>.cosigned.json` | An approval plus operator co-signature | **Execute** |

On those pages, drop the file onto the input panel, use **Open file…**, or paste anywhere on the page. Files are read in the browser and never uploaded. Approval files are the same JSON `remonce cosign` and `remonce revoke` read.

## CLI cosigning (`remonce cosign`)

Operators who receive a delegated approval can co-sign it without running the web UI:

```bash
# Co-sign a bundle (JSON file or base64 token; '-' reads stdin) and submit it
remonce cosign --bundle remonce-backup-db-1a2b3c4d.approval.json --submit

# Or just emit the cosigned ExecutionBundle for later submission
remonce cosign -b remonce-backup-db-1a2b3c4d.approval.json -o remonce-backup-db-1a2b3c4d.cosigned.json
```

The command reads `[oidc]` and `agent_url` / `agent_ca_path` from `config.toml`. It generates a fresh ephemeral keypair, runs a browser-based OIDC authorization-code flow against the signing client (PKCE, the nonce bound to the ephemeral key, and forced re-authentication — same pattern as the web UI), obtains an RFC 3161 timestamp on the cosignature, and produces an ExecutionBundle.

- `--agent <url>` overrides `agent_url` for `--submit`. Must be `https://`.
- The OIDC redirect listener binds the host/port from `oidc.redirect_uri`. If `remonce web` is already running on that port, co-sign from its "Sign a request" page instead.
- Note for CI: tokens minted by platform OIDC issuers (e.g. GitHub Actions) cannot carry a custom nonce, so they cannot bind an ephemeral key. CLI cosigning is for humans; machine flows need an issuer that honors the `nonce` parameter.

## Revoking an approval (`remonce revoke`)

An issued approval can be invalidated before it expires by submitting it to the agent's `POST /revoke` endpoint, together with a fresh, nonce-bound attestation from the revoker:

```bash
# Revoke a bundle (JSON file or base64 token; '-' reads stdin)
remonce revoke --bundle approval.json

# Target a specific agent
remonce revoke -b approval.json --agent https://agent.example.com:10022
```

The same flow is available from the web UI's Execute page ("Revoke Approval" button), which runs its own re-authenticating login and submits the revocation to the agent.

How it works:

- The revoker generates a fresh ephemeral keypair and runs the same nonce-bound, re-authenticating OIDC login as cosigning, then signs a domain-separated payload (`REMONCE-REVOKE:` prefix) over the approver's signature — so a cosignature can never be replayed as a revocation, or vice versa.
- The revocation is recorded against the approval's **key binding** (`SHA256` of the approver's public key, as attested in the token's `nonce`), not its signature bytes — so a malleated copy of the signature can't slip past it.
- The agent first re-verifies the approver bundle itself; only genuine approvals can be pinned to the revocation list (prevents cache poisoning).
- **Self-revocation** (revoker has the same OIDC `sub` as the approver) is always allowed. **Third-party revocation** requires an OPA decision with `input.action == "revoke"` (see `policy/authz.rego`).
- The revoker attestation must be fresh within `operator_max_validity`.
- A revoked approval is rejected by `/execute` until its natural expiry (`approver_max_validity`).

Without a central revocation service (below), the revocation list is **in-memory and per-agent**: submit the revocation to every agent the bundle targets, and note that an agent restart forgets it.

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

- The service exposes the same `POST /revoke` endpoint as the agent and performs the **same full verification** (approver bundle genuineness, revoker attestation, self-vs-third-party OPA check) — it cannot be poisoned with unverified entries. `remonce revoke --agent https://revocations...` can therefore target it directly.
- When `revocation_service_url` is set, the agent checks `GET /revoked/{key_binding}` (64 lowercase hex characters) before every execution and a revocation submitted to any agent is forwarded to the service.
- **Fail-closed**: if the service is configured but unreachable, the agent denies execution (`Revocation Check Failed`). A configured revocation service must be available — there is deliberately no fail-open mode.
- Revocations expire from the store when the underlying approval would have aged out of `approver_max_validity` anyway; expired entries are compacted out of the JSONL file on service restart.
- The service reads the same `config.toml` sections as the agent (`[oidc]`, `[timestamp_authority]`, `[[commands]]`, `opa_url`), since it performs the same verification. It also accepts revocations for commands missing from its own `[[commands]]` (verified with default windows; third parties judged by the default OPA rule), since it serves agents whose command sets it may not mirror.
- `retention` must be at least the longest `approver_max_validity` any agent allows; each revocation is kept until the revoked approval's `iat` plus the larger of the two.
- Writes are fsync'd before the service acknowledges them. A torn final line left by a crash is ignored at startup; corruption anywhere else refuses to start (agents then fail closed).

## Upgrading to per-signature logins

This release changes what agents accept, with no compatibility mode:

1. **Register two OIDC clients.** Create a new signing client (or reuse the old one) and a new viewer client, add both to the provider, and set `client_id` and `viewer_client_id`. See "IdP requirements" above; for Vault, [docs/idp/VAULT.md](docs/idp/VAULT.md).
2. **Upgrade the signer, CLI, agents and revocation service together.** Bundles signed by older signers lack the re-authentication evidence (and may carry high-S signatures), so agents reject them. Re-sign any outstanding approvals.
3. **Archive the revocation log.** The revocation service now records key bindings instead of signature hex, and refuses to start on an old `revocations.jsonl`. Move it aside; approvals it listed can't pass the new verification anyway.
