# Production Readiness & Outstanding Items

This document tracks known security gaps, "TODO" items, and requirements for moving Remonce from a development prototype to a production-ready system.

## Resolved

### TSA Signature Verification
- **Status**: **Fixed**. Full CMS SignedData verification and trust chain validation (including intermediate certificates) are implemented in `src/tsa.rs` (`verify_timestamp`).
- Previously only the Message Imprint was verified; the agent now requires the timestamp token to chain to a trusted root.

### TLS / ACME Support
- **Status**: **Fixed**. The agent requires TLS (`src/tls.rs`); there is no plaintext mode.
- **Modes**: `files` (static certs with hot-reloading) and `acme` (automatic via `rustls-acme`, experimental).

### Replay Attack Mitigation
- **Status**: **Fixed**. The agent keeps an in-memory replay cache (`src/replay.rs`) keyed by the executor's key binding (the IdP-attested `nonce`, `SHA256(public_key_pem)`; operator if delegated, else approver). Entries live until the signature could no longer pass freshness — the executor's `iat` plus `operator_max_validity`. Every signature comes from its own re-authenticating login and must be timestamped within 5 minutes of it, so re-timestamping can't extend that, whatever the IdP's token lifetime.
- **Caveat**: the cache is per-process. An agent restart clears it, so a bundle could be replayed across a restart within `operator_max_validity` of its signing login. Persist the cache if this matters for your threat model.

### Signature Malleability and Re-timestamping
- **Status**: **Fixed**. ECDSA's `s → n−s` twin of a valid signature, and fresh TSA timestamps over old signatures, previously let a holder resubmit a byte-different bundle — dodging the replay cache and the revocation list (which keyed on signature hex) — for as long as the ID token lived. Signers now normalize to low-S and verifiers reject high-S; both caches key on the key binding; and freshness is measured from the token's `iat`.

### Input Sanitization / Parameterized Commands
- **Status**: **Fixed**. `executable` and `args` come exclusively from `config.toml`. Signer-supplied values only enter argv through declared `[[commands.params]]`, validated fail-closed (`src/params.rs`): allow-list, integer range, or anchored regex, with a conservative default pattern that bars leading dashes (flag injection) and shell metacharacters. Commands are spawned without a shell and with a scrubbed environment.
- **Caveat**: a custom `pattern` that admits values starting with `-` re-opens argv flag injection. Review patterns accordingly.

### Approval Revocation
- **Status**: **Implemented**. `POST /revoke` on the agent accepts a `RevocationBundle` (the approver bundle plus a fresh, nonce-bound revoker attestation over a domain-separated payload). Self-revocation (same OIDC `sub`) is always allowed; third-party revocation requires an OPA `action = "revoke"` decision. Revocations are recorded by the approval's key binding. Available via the Execute page (its own re-authenticating login) and `remonce revoke`.
- **Estate-wide**: `remonce revocation-service` runs a central, persistent (JSONL) revocation store. Agents configured with `[agent] revocation_service_url` check it before every execution (**fail-closed** — if the service is set and unreachable, execution is denied) and forward locally-submitted revocations to it. The service performs the same full bundle verification as the agent, so it cannot be poisoned.
- **Caveat**: without the central service, the revocation list is in-memory and per-agent: a revocation must be submitted to every agent and a restart forgets it.

## Recommended Improvements

### Hardening OIDC Provider
- **Current**: The dev setup uses a local Vault instance (`vault_setup.tf`) over HTTP (allowed for loopback only; anything else needs `--insecure`).
- **Production**: Use a production Vault cluster or managed OIDC provider (Auth0, Okta, etc.) with HTTPS enforced for the issuer URL.

### Machine Identity for CI Cosigning (planned)
- Workload JWTs generally cannot carry the custom nonce that binds tokens to ephemeral keys, so machines cannot currently act as operators. GitHub/GitLab OIDC tokens have fixed claims; a machine using Vault would mint an [identity token](https://developer.hashicorp.com/vault/docs/secrets/identity/identity-token), which likewise takes no nonce parameter (role templates can interpolate entity metadata, but dynamically updating metadata per ephemeral key is rarely practical).
- Planned shape: a machine-operator verification path that pins issuer/audience/required claims per trusted workload issuer, **without** the key-binding requirement — bearer-token semantics, mitigated by short token TTLs and tight claim pinning. Where a deployment *can* surface a key-binding claim, a configurable claim name re-enables the stronger check.

### Embedded OPA (planned)
- Authorization currently requires a running OPA server. Embedding policy evaluation (e.g. Regorus) would remove the last runtime dependency for single-binary deployments.

### Persistent Replay Cache
- The replay cache remains in-memory per-agent. Its window runs to the executor's `iat` plus `operator_max_validity`, so the exposure is an agent restart inside that window. Persist it if your threat model requires.

### Kill the Whole Process Tree on Timeout
- **Current**: on `command_timeout` the agent kills the direct child and stops draining output after 5 seconds, so the log trailer is always written. Grandchildren that ignore the parent's death keep running.
- **Improvement**: spawn into a process group (Unix) or Job Object (Windows) and kill the group.

### TSA Policy and Signer Pinning
- **Current**: any certificate with the timeStamping EKU chaining to a trusted root is accepted; the TSA policy OID, the ESS signingCertificate attribute and `accuracy` are not checked. All of these still require a key under a trusted root, so they are defence in depth.
- **Improvement**: optionally pin the TSA policy OID / signer certificate, and verify signingCertificate(v2).

### Content Security Policy for the Signer UI
- **Current**: the web tier sends `nosniff`, `X-Frame-Options: DENY` and `no-referrer`, and agent responses are always relayed as JSON. Data-driven inline handlers were removed, but a few static inline `onclick`/`<script>` blocks remain.
- **Improvement**: move the remaining inline script into `signing.js` and add a strict `script-src 'self'` CSP.

### Library-Based TSA Handling
- **Current**: custom RFC 3161 implementation in `src/tsa.rs`, written to control the verification chain precisely without heavy dependencies.
- **Recommendation**: **retain it** for now. The leading alternative (`sigstore-tsa`) brings heavy build dependencies (`cmake`, `aws-lc-rs`) and isn't upstream of the official `sigstore` crate; lighter pure-Rust clients such as `tsp_http_client` lack verification. Harden `src/tsa.rs` with more negative tests instead (imprint mismatch, untrusted root, missing EKU, cert outside validity at `gen_time`).

### Standard ACME Handler
- **Current**: `src/tls.rs` drives `rustls-acme` + hyper by hand (and recovers the peer address itself for audit logs).
- **Improvement**: use `rustls-acme`'s axum acceptor or `axum-server`, removing hand-written connection handling.

### Structured Audit Logging
- **Current**: `src/audit.rs` serializes each record with `serde_json` and prints it — a reliable, schema-first format, but outside the `tracing` pipeline.
- **Improvement**: emit audit records as `tracing` events with a JSON subscriber so they flow into ELK, Splunk, etc. alongside other instrumentation.
