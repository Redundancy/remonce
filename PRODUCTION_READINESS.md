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
- **Status**: **Fixed**. The agent keeps an in-memory replay cache (`src/replay.rs`) keyed by the executor signature (operator cosign if delegated, else approver signature). A second submission of the same bundle within the freshness window is rejected.
- **Caveat**: the cache is per-process. An agent restart clears it, so a bundle could be replayed across a restart while still within `operator_max_validity` (10 minutes by default). Persist the cache if this matters for your threat model.

### Input Sanitization / Parameterized Commands
- **Status**: **Fixed**. `executable` and `args` come exclusively from `config.toml`. Signer-supplied values only enter argv through declared `[[commands.params]]`, validated fail-closed (`src/params.rs`): allow-list, integer range, or anchored regex, with a conservative default pattern that bars leading dashes (flag injection) and shell metacharacters. Commands are spawned without a shell and with a scrubbed environment.
- **Caveat**: a custom `pattern` that admits values starting with `-` re-opens argv flag injection. Review patterns accordingly.

### Approval Revocation
- **Status**: **Implemented**. `POST /revoke` on the agent accepts a `RevocationBundle` (the approver bundle plus a fresh, nonce-bound revoker attestation over a domain-separated payload). Self-revocation (same OIDC `sub`) is always allowed; third-party revocation requires an OPA `action = "revoke"` decision. Available via the Execute page, `POST /api/agent/revoke` on the web tier, and `remonce revoke`.
- **Estate-wide**: `remonce revocation-service` runs a central, persistent (JSONL) revocation store. Agents configured with `[agent] revocation_service_url` check it before every execution (**fail-closed** — if the service is set and unreachable, execution is denied) and forward locally-submitted revocations to it. The service performs the same full bundle verification as the agent, so it cannot be poisoned.
- **Caveat**: without the central service, the revocation list is in-memory and per-agent: a revocation must be submitted to every agent and a restart forgets it.

## Recommended Improvements

### Hardening OIDC Provider
- **Current**: The dev setup uses a local Vault instance (`vault_setup.tf`) over HTTP (allowed for loopback only; anything else needs `--insecure`).
- **Production**: Use a production Vault cluster or managed OIDC provider (Auth0, Okta, etc.) with HTTPS enforced for the issuer URL.

### Machine Identity for CI Cosigning (planned)
- GitHub/GitLab OIDC tokens cannot carry the custom nonce that binds tokens to ephemeral keys, so CI jobs cannot currently act as operators. The same applies to Vault: its machine identity flows do not mint JWTs with a caller-selectable nonce either. A dedicated verification path for workload identity tokens (issuer/audience/claims pinning without the nonce binding) is on the roadmap.

### Embedded OPA (planned)
- Authorization currently requires a running OPA server. Embedding policy evaluation (e.g. Regorus) would remove the last runtime dependency for single-binary deployments.

### Persistent Replay Cache
- The replay cache remains in-memory per-agent. Its window is short (`operator_max_validity`, 10 minutes by default), so the exposure is an agent restart inside that window. Persist it if your threat model requires.
