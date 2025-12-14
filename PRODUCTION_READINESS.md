# Production Readiness & Outstanding Items

This document tracks known security gaps, "TODO" items, and requirements for moving Remonse from a development prototype to a production-ready system.

## Critical Security Gaps

### 1. TSA Signature Verification (RESOLVED)
- **Status**: **Fixed**. Full CMS SignedData verification and trust chain validation (including intermediate certificates) are implemented in `src/tsa.rs` as of `verify_timestamp`.
- **Issue**: Previously, only the Message Imprint was verified.
- **Risk**: Mitigated. The agent now verifies that the timestamp token is signed by a trusted root (or valid chain to a root).

### 2. TLS / ACME Support
- **Issue**: The Agent executes commands over plain HTTP/TCP (`10022`).
- **Risk**: Command payloads, tokens, and execution output are visible on the network.
- **Remediation**:
    - Add TLS support to the Agent listener (`src/agent.rs`).
    - Integrate `rustls` or native-tls.
    - (Optional) Add ACME (Let's Encrypt) support for automatic certificate management.

## Recommended Improvements

### Replay Attack Mitigation
- **Current**: Requests have a unique execution ID, but the Agent does not persist a "seen" list of IDs.
- **Risk**: A valid signed command bundle could theoretically be re-sent multiple times.
- **Mitigation**: The Agent should cache `execution_id`s (with a TTL) or persist them to deny duplicates.

### Hardening OIDC Provider
- **Current**: The setup uses a local development Vault instance (`vault_setup.tf`) with HTTP.
- **Production**:
    - Use a production Vault cluster or a managed OIDC provider (Auth0, Okta, etc.).
    - Ensure HTTPS is enforced for the Issuer URL.

### Input Sanitization
- **Current**: `executable` and `args` are taken from config, but `command` payload can influence logic.
- **Action**: Ensure all inputs passed to `std::process::Command` are strictly sanitized or strictly defined in `config.toml`.
