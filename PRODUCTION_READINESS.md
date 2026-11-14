# Production Readiness & Outstanding Items

This document tracks known security gaps, "TODO" items, and requirements for moving Remonce from a development prototype to a production-ready system.

## Resolved

### TSA Signature Verification
- **Status**: **Fixed**. Full CMS SignedData verification and trust chain validation (including intermediate certificates) are implemented in `src/tsa.rs` (`verify_timestamp`).
- Previously only the Message Imprint was verified; the agent now requires the timestamp token to chain to a trusted root.

### TLS / ACME Support
- **Status**: **Fixed**. The agent requires TLS (`src/tls.rs`); there is no plaintext mode.
- **Modes**: `files` (static certs with hot-reloading) and `acme` (automatic via `rustls-acme`, experimental), validated with TLS-ALPN-01 on port 443 or HTTP-01 on port 80. With HTTP-01, port 80 is open only while a certificate is being issued.

### Replay Attack Mitigation
- **Status**: **Fixed**. The agent keeps a replay cache (`src/replay.rs`) keyed by the request id (the hash of the signed request), so a request runs once however it is resubmitted. Entries live until every approval that could run the request has expired: `approval_validity` from the latest possible login. Every signature comes from its own re-authenticating login and must be timestamped within 5 minutes of it, so re-timestamping can't extend that, whatever the IdP's token lifetime.
- **Set `[agent] state_dir`**: with it the cache is an fsynced append log that survives a restart, and a run that can't be recorded doesn't start. Without it the cache is in memory, and a request could be replayed after a restart while its approvals are still valid; the agent warns about this at startup.

### Signature Malleability and Re-timestamping
- **Status**: **Fixed**. ECDSA's `s → n−s` twin of a valid signature, and fresh TSA timestamps over old signatures, previously let a holder resubmit a byte-different bundle — dodging the replay cache and the revocation list (which keyed on signature hex) — for as long as the ID token lived. Signers now normalize to low-S and verifiers reject high-S; both caches key on the request id, which no change to the signatures affects; and freshness is measured from the token's `iat`.

### Input Sanitization / Parameterized Commands
- **Status**: **Fixed**. `executable` and `args` come exclusively from `config.toml`. Signer-supplied values only enter argv through declared `[[commands.params]]`, validated fail-closed (`src/params.rs`): allow-list, integer range, or anchored regex, with a conservative default pattern that bars leading dashes (flag injection) and shell metacharacters. Commands are spawned without a shell and with a scrubbed environment.
- **Caveat**: a custom `pattern` that admits values starting with `-` re-opens argv flag injection. Review patterns accordingly.

### Multi-party Approval
- **Status**: **Implemented**. A request collects independent approvals (up to 16), each a different person. Policy publishes per-command requirement documents (approval slots and allowed executors) that the agent serves in its catalog and enforces through a shared Rego helper; the executor is identified by their login. See [ARCHITECTURE.md](ARCHITECTURE.md#requests-and-approvals).
- **Caveat**: the executor's credential is a viewer bearer token with no proof of possession. Keep viewer-token lifetimes short, and use `executors` to limit who can run what.

### Request Revocation
- **Status**: **Implemented**. `POST /revoke` on the agent accepts a `RevocationBundle` (the request with at least one genuine approval, plus a fresh, nonce-bound revoker attestation over a domain-separated payload). Any approver of the request may revoke it; anyone else needs an OPA `action = "revoke"` decision. Revocation is by request id, so it cancels the request whoever approved it. Available via the Execute page (its own re-authenticating login) and `remonce revoke`.
- **Estate-wide**: `remonce revocation-service` runs a central, persistent (JSONL) revocation store. Agents configured with `[agent] revocation_service_url` check it before every execution (**fail-closed** — if the service is set and unreachable, execution is denied) and forward locally-submitted revocations to it. The service performs the same full bundle verification as the agent, so it cannot be poisoned.
- **Caveat**: without the central service, the revocation list is per-agent: a revocation must be submitted to every agent. It survives an agent restart only with `[agent] state_dir` set.

## Recommended Improvements

### Hardening OIDC Provider
- **Current**: The dev setup uses a local Vault instance (`vault_setup.tf`) over HTTP (allowed for loopback only; anything else needs `--insecure`).
- **Production**: Use a production Vault cluster or managed OIDC provider (Auth0, Okta, etc.) with HTTPS enforced for the issuer URL.

### Machine Identity for CI Executors (planned)
- Executing needs no nonce-bound key, only an ID token for the viewer client from the configured issuer, so a machine can execute once it can get one. Workload tokens usually come from a different issuer (GitHub/GitLab OIDC) or, through Vault, as an [identity token](https://developer.hashicorp.com/vault/docs/secrets/identity/identity-token) for a role whose audience must match the viewer client.
- Planned shape: trust additional workload issuers for the executor role only, pinning issuer, audience and required claims per issuer — bearer-token semantics, mitigated by short token TTLs and tight claim pinning. Machines still can't approve: approving needs a key-bound, re-authenticated login.
- **Also missing for pipelines**: `remonce submit` always runs an interactive browser login, so a pipeline has to call `POST /execute` itself; and `/execute` returns once the command has started, so nothing waits for it or reports its exit status (that is in the run log and the `command_finished` audit record).

### Identity Providers Other Than Vault
- **Current**: the scopes requested at login (`openid groups user_profile`) and the claim used as the display name (`username`) are fixed, and only Vault has been tested. Other IdPs may reject those scopes or name things differently.
- **Improvement**: make both configurable and test against at least one other provider.

### Embedded Policy Engine
- **Status**: **Implemented**. Rego policy is evaluated in-process with Regorus by default (`policy_dir`), so no OPA server is needed; `opa_url` still selects an OPA server for its full builtin library and tooling. The two are checked against each other in tests.
- **Caveat**: the embedded engine omits `net.*`, `http.send`, `crypto.*` and `io.jwt.*` builtins; a policy using them is refused at startup and needs `opa_url`.

### IdP Key Rotation
- **Status**: **Fixed**. The agent, the revocation service and the signer used to fetch the IdP's signing keys once at startup, so a key rotation made them reject every new token until restarted. They now refetch when a token names an unknown key (at most once a minute) and hourly, and keep the last keys if the IdP is unreachable (`src/idp_keys.rs`).
- **Rule to follow**: the IdP is followed exactly, so an approval stops verifying once the IdP withdraws the key that signed its token. Keep each command's `approval_validity` within the time your IdP keeps a rotated key published (Vault: the key's `verification_ttl`).

### Persistent Replay Cache and Local Revocations
- **Status**: **Implemented** as `[agent] state_dir` (see Replay Attack Mitigation above). It is opt-in: set it on every agent you leave running.

### Kill the Whole Process Tree on Timeout
- **Status**: **Fixed**. Each command runs at the head of its own process group (Unix) or Job Object (Windows); a timeout, or the agent being stopped, kills all of it (`src/process_tree.rs`). A command that exits by itself and leaves something running on purpose keeps it.
- **Caveat**: an agent that is killed outright (SIGKILL, power loss) can't stop its commands; they run on unsupervised.

### Run Log Size
- **Status**: **Fixed**. A run log keeps at most `max_output_bytes` per command (64 MiB by default); the rest is discarded while the command runs on.
- **Still open**: `logs/` is never pruned, and there is no limit on how many commands run at once.

### TSA Policy and Signer Pinning
- **Current**: any certificate with the timeStamping EKU chaining to a trusted root is accepted; the TSA policy OID, the ESS signingCertificate attribute and `accuracy` are not checked. All of these still require a key under a trusted root, so they are defence in depth.
- **Improvement**: optionally pin the TSA policy OID / signer certificate, and verify signingCertificate(v2).

### Content Security Policy for the Signer UI
- **Status**: **Fixed**. The signer UI has no inline script or styles and no third-party assets, and every response carries `default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'` (plus `frame-ancestors 'none'`, `base-uri 'none'`, `form-action 'self'`), alongside `nosniff`, `X-Frame-Options: DENY` and `no-referrer`. Page templates HTML-escape every substituted value, and `/api/commands` no longer exposes executables, arguments or environment.

### Library-Based TSA Handling
- **Current**: custom RFC 3161 implementation in `src/tsa.rs`, written to control the verification chain precisely without heavy dependencies.
- **Recommendation**: **retain it** for now. The leading alternative (`sigstore-tsa`) brings heavy build dependencies (`cmake`, `aws-lc-rs`) and isn't upstream of the official `sigstore` crate; lighter pure-Rust clients such as `tsp_http_client` lack verification. Harden `src/tsa.rs` with more negative tests instead (imprint mismatch, untrusted root, missing EKU, cert outside validity at `gen_time`).

### Standard ACME Handler
- **Current**: `src/tls.rs` drives `rustls-acme` + hyper by hand (and recovers the peer address itself for audit logs).
- **Improvement**: use `rustls-acme`'s axum acceptor or `axum-server`, removing hand-written connection handling.

### Structured Audit Logging
- **Current**: `src/audit.rs` serializes each record with `serde_json` and prints it to stdout, and appends it to `[agent] audit_log_path` when that is set — a reliable, schema-first format, but outside the `tracing` pipeline, and on stdout it is interleaved with the agent's ordinary log lines. Records cover every execution attempt, how each run ended, revocations, and reads of the catalog, files and logs.
- **Improvement**: emit audit records as `tracing` events with a JSON subscriber so they flow into ELK, Splunk, etc. alongside other instrumentation. The records are not tamper-evident.

### Tests and Release
- **Tests**: `src/agent_tests.rs` runs the agent end to end (a fake IdP and TSA, the shipped policy, real commands). The signer's handlers and `src/tsa.rs`'s parsing have no tests of their own, and nothing is fuzzed.
- **Release**: no release has been published. The workflow builds Linux x86_64 and Windows only, with checksums but no signature or provenance, and CI doesn't yet run `cargo fmt --check`, `clippy -D warnings` or a dependency audit.
