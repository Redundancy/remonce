# Security Architecture

## Overview

Remonse is a remote command execution system designed with a security-first approach ("Zero Trust Remote Execution"). It ensures that any command executed on a target machine is individually authenticated, authorized, and time-bound.

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
    - **Verified**: The TSA signature is verified against trusted roots (full chain validation).
    - **Implementation Note**: The system uses a custom TSA verification implementation intended to be compliant with RFC 3161 and RFC 5652. This may later be migrated to another library or implementation, but the current implementation is intended to be simple and self-contained without requiring cmake. 
3.  **Identity Verification (JWT) & Nonce Binding**:
    - The ID Token (OIDC) is validated (signature, issuer, audience).
    - **Nonce Binding**: The Agent calculates the SHA-256 hash of the Public Key used to sign the command and verifies that this hash matches the `nonce` claim in the ID Token.
    - **Why this is safe**: This cryptographically binds the ephemeral command signing key to the User's Identity. Even if the JWT is intercepted, it cannot be used by an attacker unless they *also* possess the corresponding private key used to sign the command.
    - **Delegation/Sharing**: This model explicitly supports *delegated execution*. An "Approver" can sign a command and share the full artifact (Command + Signature + JWT) with a "Runner" (e.g., a CI/CD job or another user). The Runner can trigger the execution on the Agent, but the Agent will log and authorize the action based on the *Approver's* identity (the one in the JWT), ensuring accountability without sharing private credentials.
    - Input includes: `command` payload, `jwt` (raw), and `timestamp`.
    - OPA evaluates the policy (e.g., `data.remonse.authz.decision`) with a deny by default posture.
4.  **Payload Constraint Verification**:
    - **Max Validity**: Ensures the token is not older than the configured `max_validity` (default 3 days).
    - **Target Machine**: If specified, ensures the current hostname matches the allowlist in the token.
    - **Time Window**: Enforces `not_before` and `not_after` constraints if present.

## Threat Model

1.  **Compromised Command Payload**
    *   *Attack*: Attacker modifies the command payload (e.g., changing the `command` field) after it was signed.
    *   *Mitigation*: **ECDSA Signature**. The signature covers the entire payload. Any modification invalidates it.
    *   *Note*: The payload `command` field is an **alias** (e.g., `backup-db`), not a raw shell command. The actual executable logic is defined and controlled on the Agent side. This prevents an attacker from injecting arbitrary code (like `rm -rf /`) even if they could forge a signature, as they are restricted to pre-defined allowed aliases.

2.  **Replay Attacks (Long-term)**
    *   *Attack*: Attacker captures a valid {Command + Signature + JWT} bundle and tries to execute it weeks later.
    *   *Mitigation*: **Timestamp Authority (TSA)**. The agent verifies the timestamp token. If the timestamp is too old (policy configurable, or if the signing key/cert is expired/revoked), it is rejected. Also, the OIDC token has a short expiry, though our specialized logic allows expired JWTs *if* the timestamp proves it was signed *during* the valid window.

3.  **Key Compromise (Ephemeral User Keys)**
    *   *Attack*: Attacker steals the user's private signing key.
    *   *Mitigation*: **Short-lived Keys & Tokens**. Keys are ephemeral (per session/command). The OIDC ID token bound to that key has a short lifespan (e.g., 5-15 mins). Once the ID token expires, the key is useless for *new* command generation unless the attacker can also re-authenticate to Vault to get a *new* ID token for that key.

4.  **Man-in-the-Middle (MitM)**
    *   *Attack*: Interception of traffic between Client and Agent.
    *   *Mitigation*: **TLS (Implemented)**. All communication can be secured via HTTPS using either static certificates or automated ACME (Let's Encrypt). Configuration is handled via `config.toml` (`[tls]` section).

5.  **Malicious Approver (Insider Threat)**
    *   *Attack*: A valid user with approval rights tries to run a malicious command.
    *   *Mitigation*: **OPA Policy & Audit Trails**. OPA policies can restrict *what* commands can be run (allowlisting). Even if authorized, the immutable Audit Log records the exact command and identity of the signer.

6.  **Shared Token Exposure**
    *   *Attack*: When delegating execution, the recipient of a signed artifact gains access to the approver's JWT claims (email, groups, etc.).
    *   *Scope*: This risk is **limited to systems using the same OIDC clientID**. The JWT cannot be used to authenticate to unrelated services.
    *   *Mitigation*: **Dedicated ClientID** (strongly recommended), **short-lived JWTs**, **nonce binding** (JWT unusable for new commands without private key), **command allowlisting**, and **claim minimization** (request only necessary claims from IdP).

## Audit Logging

Every execution attempt (Allowed or Denied) generates a structured audit log entry.
- **Location**: `logs/<execution_id>.log` (and stdout for the agent service).
- **Contents**: Timestamp, User, Source IP, Decision, Reason, and the Full Command.

## Key Management

- **User Keys**: Ephemeral ECDSA keys are generated client-side (in the browser or CLI) for each session or command.
- **Identity Keys**: Managed by the OIDC Provider (Vault).
- **TSA Keys**: Managed by the Timestamp Authority.

## JWT Exposure Considerations

When using the **delegation model** (where an Approver signs a command for a Runner to execute), the full JWT is visible to the recipient. This section outlines the risks and mitigations.

### What Is Exposed

The execution artifact includes the raw OIDC ID Token, which may contain:
-   User identity (`sub`, `email`, `name`)
-   Group memberships or roles
-   Token metadata (`iat`, `exp`, `aud`)

### Risk Scoping

> [!IMPORTANT]
> **Use a dedicated OIDC clientID for Remonse.** The JWT's `aud` (audience) claim limits its validity to services using that clientID. A dedicated clientID ensures the token cannot be replayed against other applications in your organization.

### Claim Minimization Best Practices

Reduce information exposure by configuring your IdP to issue minimal claims:

-   **Prefer `roles` over `groups`**: Roles expose less organizational structure than group names.
-   **Request minimal scopes**: Only request claims needed for OPA policy decisions.
-   **Avoid PII if possible**: If your policy doesn't need `email` or `name`, don't request them.

### Existing Mitigations

| Mitigation | Effect |
|------------|--------|
| Short-lived JWTs | Token expires in minutes, limiting reuse window |
| Nonce binding | JWT is cryptographically bound to the ephemeral key—unusable for new commands |
| TSA timestamping | Proves command was signed during valid window, enabling post-hoc audit |
| Command allowlisting | Even with a valid token, only pre-approved commands can execute |

## Comparison with OpenPubkey

Remonse uses the same core mechanism as [OpenPubkey](https://github.com/openpubkey/openpubkey): binding an ephemeral public key to an OIDC identity via the JWT `nonce` field.

### Shared Security Properties

-   **Ephemeral keys**: Generated per session, reducing key compromise window
-   **Nonce binding**: IdP implicitly attests to key ownership
-   **Proof-of-possession**: Upgrades bearer tokens to proof-of-possession
-   **No IdP changes required**: Works with standard OIDC providers

### Remonse's Additional Security

| Feature | Benefit |
|---------|---------|
| **RFC 3161 TSA** | Cryptographic non-repudiation and time-bounding |
| **OPA Integration** | Fine-grained, policy-as-code authorization |
| **Command Allowlisting** | Restricts execution to pre-defined aliases |

### OpenPubkey's MFA Cosigner

OpenPubkey optionally supports an **MFA Cosigner**—an independent party that provides a second attestation, eliminating the IdP as a single point of compromise. This is not currently implemented in Remonse but could be a future enhancement for high-security environments.

### Privacy Considerations

Both Remonse and OpenPubkey expose JWT claims when sharing signed artifacts. Mitigate this through:
-   **Dedicated clientID** (limits token scope)
-   **Claim minimization** (reduce exposed PII)
-   **Roles over groups** (less organizational exposure)

