# Configuration Guide

This document identifies the configuration options available for Remonce, including authentication, authorization, and security settings.

## Configuration File (`config.toml`)

Both `remonce web` (the signer) and `remonce agent` (the executor) read the same `config.toml` from the current working directory. Each binary only uses the sections relevant to it.

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
| `agent.cors_allowed_origins` contains `"*"` | Allows any browser origin to call the agent |

Loopback HTTP for OIDC (e.g., local Vault in dev) is **not** gated — it stays fine without the flag.

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
# TLS. Must be https://. The UI lets the user override it per-session.
# Default: "https://localhost:10022"
agent_url = "https://agent.example.com:10022"

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
  -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
```

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

These settings connect the agent to your OIDC provider (Vault, Keycloak, etc.).

```toml
[oidc]
# Base URL of the OIDC provider's issuer.
# Must match the 'iss' claim in your JWTs.
issuer_url = "http://127.0.0.1:8200/v1/identity/oidc/provider/vaultprovider"

# The Client ID registered with the OIDC provider.
client_id = "your_client_id"

# Redirect URI for the OIDC callback.
# Ensure this matches exactly what is registered in your OIDC provider.
redirect_uri = "http://localhost:8080/oidc/callback"
```

### Authorization (OPA)

These settings determine how the agent checks permissions.

```toml
# URL of the Open Policy Agent service.
# If omitted, defaults to "http://localhost:8181".
opa_url = "http://127.0.0.1:8181"
```

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
| `operator_max_validity` | 10 minutes | How recent the executor's signature must be. In a delegated flow this is the operator's cosign TSA timestamp; in self-execute it's the approver's own. Also bounds the replay-cache TTL. |

**Self-execute vs delegated**: when the approver submits their own bundle immediately (no operator cosign), they must be within `operator_max_validity`. If you want longer self-execute windows, raise `operator_max_validity` — but remember this also lengthens the replay-cache window and the operator-side freshness bound.

### Operator constraints (`operator_requires`)

The approver can embed OIDC claim predicates that the executing operator must satisfy. These are enforced by the agent *before* OPA:

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

Semantics: if `any_of` is non-empty, at least one predicate must match the operator's OIDC token claims. Empty/absent = no constraint (any authenticated operator in OPA's allow-set may execute). Claims are evaluated at **execution time** against the operator's fresh token, so group changes propagate immediately.

## CLI cosigning (`remonce cosign`)

Operators who receive a delegated approval can co-sign it without running the web UI:

```bash
# Co-sign a bundle (JSON file or base64 token; '-' reads stdin) and submit it
remonce cosign --bundle approval.json --submit

# Or just emit the cosigned ExecutionBundle for later submission
remonce cosign -b approval.json -o execution-bundle.json
```

The command reads `[oidc]` and `agent_url` / `agent_ca_path` from `config.toml`. It generates a fresh ephemeral keypair, runs a browser-based OIDC authorization-code flow (PKCE, with the nonce bound to the ephemeral key — same pattern as the web UI), obtains an RFC 3161 timestamp on the cosignature, and produces an ExecutionBundle.

- `--agent <url>` overrides `agent_url` for `--submit`. Must be `https://`.
- The OIDC redirect listener binds the host/port from `oidc.redirect_uri`. If `remonce web` is already running on that port, use its Cosign page instead.
- Note for CI: tokens minted by platform OIDC issuers (e.g. GitHub Actions) cannot carry a custom nonce, so they cannot bind an ephemeral key. CLI cosigning is for humans; machine flows need an issuer that honors the `nonce` parameter.

## Revoking an approval (`remonce revoke`)

An issued approval can be invalidated before it expires by submitting it to the agent's `POST /revoke` endpoint, together with a fresh, nonce-bound attestation from the revoker:

```bash
# Revoke a bundle (JSON file or base64 token; '-' reads stdin)
remonce revoke --bundle approval.json

# Target a specific agent
remonce revoke -b approval.json --agent https://agent.example.com:10022
```

The same flow is available from the web UI's Execute page ("Revoke Approval" button) and via `POST /api/agent/revoke` on the web tier.

How it works:

- The revoker generates a fresh ephemeral keypair and runs the same nonce-bound OIDC login as cosigning, then signs a domain-separated payload (`REMONCE-REVOKE:` prefix) over the approver's signature — so a cosignature can never be replayed as a revocation, or vice versa.
- The agent first re-verifies the approver bundle itself; only genuine approvals can be pinned to the revocation list (prevents cache poisoning).
- **Self-revocation** (revoker has the same OIDC `sub` as the approver) is always allowed. **Third-party revocation** requires an OPA decision with `input.action == "revoke"` (see `policy/authz.rego`).
- The revoker attestation must be fresh within `operator_max_validity`.
- A revoked approval is rejected by `/execute` until its natural expiry (`approver_max_validity`).

Caveats: the revocation list is **in-memory and per-agent**. Submit the revocation to every agent the bundle targets, and note that an agent restart forgets it (see PRODUCTION_READINESS.md).