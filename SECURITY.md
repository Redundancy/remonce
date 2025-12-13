# Security Architecture

## Overview

Zitre is a remote command execution system designed with a security-first approach ("Zero Trust Remote Execution"). It ensures that any command executed on a target machine is individually authenticated, authorized, and time-bound.

The core security model relies on:
1.  **OIDC Authentication**: Users authenticate via an OIDC provider (HashiCorp Vault).
2.  **Digital Signatures**: Commands are signed by the user's private key.
3.  **Third-Party Timestamping**: A Timestamp Authority (TSA) safeguards against replay attacks and key compromise.
4.  **Policy-as-Code**: Authorization logic is decoupled into OPA (Open Policy Agent) Rego policies.

## Verification Flow

When the Agent receives a request, it performs the following strict verification sequence (see `src/security.rs`):

1.  **Signature Verification**: The Agent verifies that the Command payload was signed by the provided Public Key using ECDSA (P-256).
2.  **Timestamp Verification**:
    - The Agent validates the RFC 3161 Timestamp Token.
    - It ensures the timestamp was issued for the specific signature + ID token provided.
    - **Note**: Currently, the TSA signature itself is NOT strictly verified (see [PRODUCTION_READINESS.md](./PRODUCTION_READINESS.md)).
3.  **Identity Verification (JWT)**:
    - The ID Token (OIDC) is validated (signature, issuer, audience).
    - **Critical**: The JWT expiry (`exp`) is checked against the **Timestamp**, not the current wall-clock time. This allows valid commands to be executed even if the short-lived generic OIDC token has since expired, provided the command was signed and timestamped *during* the token's validity window.
4.  **Nonce Binding**:
    - The Agent calculates the SHA-256 hash of the Public Key used to sign the command.
    - It verifies that this hash matches the `nonce` claim in the ID Token. This cryptographically binds the ephemeral command signing key to the User's Identity.
5.  **Authorization (OPA)**:
    - If all cryptographic checks pass, the Agent queries OPA.
    - Input includes: `command` payload, `jwt` (raw), and `timestamp`.
    - OPA evaluates the policy (e.g., `data.remonse.authz.decision`) to Allow/Deny.

## Audit Logging

Every execution attempt (Allowed or Denied) generates a structured audit log entry.
- **Location**: `logs/<execution_id>.log` (and stdout for the agent service).
- **Contents**: Timestamp, User, Source IP, Decision, Reason, and the Full Command.

## Key Management

- **User Keys**: Ephemeral ECDSA keys are generated client-side (in the browser or CLI) for each session or command.
- **Identity Keys**: Managed by the OIDC Provider (Vault).
- **TSA Keys**: Managed by the Timestamp Authority.
