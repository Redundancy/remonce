# Security Architecture

## Overview

Remonce is a remote command execution system designed with a security-first approach ("Zero Trust Remote Execution"). It ensures that any command executed on a target machine is individually authenticated, authorized, and time-bound.

The core security model relies on:
1.  **OIDC Authentication**: Users authenticate via an OIDC provider (HashiCorp Vault).
2.  **Digital Signatures**: Commands are signed by the user's private key.
3.  **Third-Party Timestamping**: A Timestamp Authority (TSA) safeguards against replay attacks and key compromise.
4.  **Policy-as-Code**: Authorization logic is decoupled into OPA (Open Policy Agent) Rego policies.

## Verification Flow

When the Agent receives an `ExecutionBundle`, it performs this strict sequence (see [src/security.rs](src/security.rs)):

1.  **Approver signature**: Verify the approver's ECDSA-P-256 signature over `canonical(command + operator_requires)`.
2.  **Approver TSA**: Validate the RFC 3161 timestamp token covering `(approver_signature || approver_id_token)`. Chain validation is delegated to `rustls-webpki` (see "TSA trust model" below) and enforces:
    -   signature verification up to a trusted root
    -   `notBefore` / `notAfter` at the TSA's own `gen_time` (historical validity — correct for timestamps)
    -   `id-kp-timeStamping` Extended Key Usage on the signer cert (RFC 3161 §2.3)
    -   signer cert identified by **issuer DN + serial**, not serial alone (RFC 5652 §5.1)
3.  **Approver JWT + nonce binding**: Validate OIDC signature/issuer/audience. Verify `nonce == SHA256(approver.public_key_pem)` — this binds the ephemeral command-signing key to the user's identity. Check `exp > approver_tsa_timestamp`.
4.  **Delegation branch**:
    *   **If operator cosign present**:
        -   Verify the operator's signature over `(approver_sig_hex || operator.public_key_pem)`. Because the operator signs *over the approver's signature hex*, the cosign is cryptographically bound to *this specific* approver signature. An attacker cannot staple an operator cosign from one authorized command onto a different approver's bundle.
        -   Verify operator TSA and JWT the same way as the approver (nonce binds operator's ephemeral key to their identity).
        -   **Freshness**: operator TSA must be within `operator_max_validity` (default 10 min); approver TSA must be within `approver_max_validity` (default 3 days).
        -   **Claim predicates**: if `operator_requires.any_of` is non-empty, at least one predicate must match the operator's JWT claims.
    *   **Else (self-execute)**: the approver's own TSA timestamp must be within the short (`operator_max_validity`) window — when acting as their own executor, freshness still applies. `operator_requires` is ignored in this branch.
5.  **Replay cache**: Check the executor signature (operator cosign if delegated, approver signature otherwise) against an in-memory TTL-bounded cache. First-seen wins; replays inside the freshness window are rejected.
6.  **Command-level constraints**:
    -   **Target machine**: approver's `target_machines` must include this agent's hostname.
    -   **Time window**: `not_before` / `not_after` enforced if present.
7.  **OPA authorization**: Input includes `input.approver` (username, full claims, signed_at), `input.operator` (same shape), `input.self_executed`, `input.command`, and `input.host`. Policy evaluates with a deny-by-default posture.

## Threat Model

1.  **Compromised Command Payload**
    *   *Attack*: Attacker modifies the command payload (e.g., changing the `command` field) after it was signed.
    *   *Mitigation*: **ECDSA Signature**. The signature covers the entire payload. Any modification invalidates it.
    *   *Note*: The payload `command` field is an **alias** (e.g., `backup-db`), not a raw shell command. The actual executable logic is defined and controlled on the Agent side. This prevents an attacker from injecting arbitrary code (like `rm -rf /`) even if they could forge a signature, as they are restricted to pre-defined allowed aliases.

2.  **Replay Attacks (Long-term)**
    *   *Attack*: Attacker captures a valid execution bundle and tries to execute it later.
    *   *Mitigation*: **Two-tier freshness + replay cache**. The executor signature (operator cosign in delegated flows, approver signature in self-execute) must be within `operator_max_validity` (default 10 min). The approver signature is separately bounded by `approver_max_validity` (default 3 days). The agent additionally caches executor signatures in memory; a second submission inside the freshness window is rejected as a replay.

3.  **Replay Attacks (Short-term, within freshness window)**
    *   *Attack*: Attacker observes a signed bundle in flight (or from logs) and resubmits it before the short window expires.
    *   *Mitigation*: **In-memory replay cache** keyed on the executor signature. First-seen wins; the TTL equals `operator_max_validity`. Cache is not persistent across agent restarts — the short window naturally bounds exposure after a restart.

4.  **Key Compromise (Ephemeral User Keys)**
    *   *Attack*: Attacker steals the user's private signing key.
    *   *Mitigation*: **Short-lived Keys & Tokens**. Keys are ephemeral (per session). The OIDC ID token bound to that key has a short lifespan (e.g., 5-15 mins). Once the ID token expires, the key is useless for *new* command generation unless the attacker can also re-authenticate to the IdP to get a *new* ID token for that key.

5.  **Man-in-the-Middle (MitM)**
    *   *Attack*: Interception of traffic between the signer, an operator, and the agent.
    *   *Mitigation*: **Mandatory TLS on the agent**. The agent refuses to serve without TLS configured (file-based cert or ACME). The signer runs on the operator's workstation bound to loopback only, so no MitM opportunity exists on the signing leg.

6.  **Operator Cosign Stapling**
    *   *Attack*: Attacker takes a valid operator cosign (authorizing command A) and staples it onto a different approver's bundle (authorizing command B), hoping to get B executed under the operator's attestation.
    *   *Mitigation*: **Binding operator sig to approver sig**. The operator signs `(approver_sig_hex || operator_pubkey_pem)`, so the cosign is only valid for the specific approver signature it was created against. Swapping approver bundles invalidates the cosign. The agent additionally checks that `operator.approver_sig` matches the bundle's approver signature before even attempting the cryptographic verification.

7.  **Compromised Operator**
    *   *Attack*: A legitimate NOC operator is compromised (credential phish, endpoint malware) and runs a pre-signed approver bundle for malicious purposes.
    *   *Mitigation (partial)*: **Approver-embedded `operator_requires`** restricts execution to operators with specific OIDC claims, which limits the set of compromisable accounts. **Audit log** records both approver and operator identities, so post-incident attribution is always possible. Full defense requires revocation (deferred) and IdP-side compromise detection.

8.  **Malicious Approver (Insider Threat)**
    *   *Attack*: A user with approval rights authorizes a malicious command.
    *   *Mitigation*: **OPA Policy & Audit Trails**. OPA policies restrict *what* commands can be approved (allowlisting). The approver's identity is recorded on every execution. **Separation of duties** rules in OPA (`not input.self_executed`) can require a distinct operator to actually execute, so the malicious approver needs a second compromised or complicit account.

9.  **Shared Token Exposure**
    *   *Attack*: When delegating execution, the operator sees the approver's JWT claims (and vice versa). An attacker who steals a bundle from logs or transit sees both tokens.
    *   *Scope*: Limited to systems using the same OIDC clientID. The JWTs cannot be used to authenticate to unrelated services.
    *   *Mitigation*: **Dedicated clientID** (strongly recommended), **short-lived JWTs**, **nonce binding** (JWTs unusable for new commands without the corresponding private keys), **command allowlisting**, and **claim minimization** (request only necessary claims from the IdP).

## Audit Logging

Every execution attempt (Allowed or Denied) generates a structured audit log entry.
- **Location**: `logs/<execution_id>.log` (and stdout for the agent service).
- **Contents**: Timestamp, User, Source IP, Decision, Reason, and the Full Command.

## Key Management

- **User Keys**: Ephemeral ECDSA keys are generated server-side in each signer session. The private key never leaves the operator's workstation (the signer is loopback-only).
- **Identity Keys**: Managed by the OIDC Provider (Vault/Okta/etc.). Pinned at agent startup via a one-time discovery + JWKS fetch.
- **TSA Keys**: Managed by the Timestamp Authority.

## TSA trust model

The agent ships with **DigiCert Trusted Root G4** bundled into the binary (expires 2038-01-15). This is the default and only trust anchor for TSA signature verification unless operators add more.

Operators can extend trust in two ways:

| Mechanism | Scope | Gated by `--insecure`? |
|-----------|-------|------------------------|
| `timestamp_authority.ca_path = "./roots.pem"` | Adds specific roots (e.g., internal CA, non-DigiCert public TSA) | No — narrow, explicit |
| `timestamp_authority.trust_system_store = true` | Adds every CA in the OS native trust store (hundreds) | **Yes** — broad, requires `--insecure` |

The asymmetric treatment reflects blast radius: naming a specific CA to trust is an auditable, bounded act; "trust whatever the OS trusts" is a wildcard that lets any of hundreds of unrelated CAs forge a timestamp.

**Revocation is not checked.** Neither CRL nor OCSP. This is consistent with typical TSA deployment patterns and with the pre-hardening behavior, but it's a gap: a stolen or retired TSA cert that's still within its `notAfter` will still verify. For deployments that need revocation, the immediate workarounds are to keep `ca_path` pinned to a specific, closely-monitored CA, and to rotate that CA on revocation events. Proper CRL/OCSP integration is on the roadmap but not implemented.

## The `--insecure` flag

A single top-level flag (`remonce --insecure {web|agent}`) gates all settings that meaningfully degrade the default security posture. Without the flag, the agent refuses to start and names every violation.

With the flag set:

- A warning banner is logged at startup listing every active gate.
- Every audit log entry carries `"insecure": true` (a process-wide atomic flag set once at startup).
- Each specific gate logs its own `tracing::warn!` line so ops tooling can alert on it.

Currently gated: HTTP non-loopback OIDC issuer, `trust_system_store` for TSA, `operator_max_validity` above 1 hour, wildcard CORS. See [CONFIGURATION.md](CONFIGURATION.md) for the full table.

Design intent: the flag is blunt. It's meant to be visible in process listings, systemd units, and audit logs, not to be a routine knob. Operators who need one specific unsafe setting and *not* the others can still use `--insecure` — it turns on whatever the config already enables, not more.

## JWT Exposure Considerations

Delegated bundles contain **two** OIDC ID tokens (approver + operator). Each is visible to the other signer and to anyone with the final bundle. This section outlines the risks and mitigations.

### What Is Exposed

Each ID token in the execution artifact may contain:
-   User identity (`sub`, `email`, `name`)
-   Group memberships or roles
-   Token metadata (`iat`, `exp`, `aud`)

### Risk Scoping

> [!IMPORTANT]
> **Use a dedicated OIDC clientID for Remonce.** The JWT's `aud` (audience) claim limits its validity to services using that clientID. A dedicated clientID ensures the token cannot be replayed against other applications in your organization.

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

Remonce uses the same core mechanism as [OpenPubkey](https://github.com/openpubkey/openpubkey): binding an ephemeral public key to an OIDC identity via the JWT `nonce` field.

### Shared Security Properties

-   **Ephemeral keys**: Generated per session, reducing key compromise window
-   **Nonce binding**: IdP implicitly attests to key ownership
-   **Proof-of-possession**: Upgrades bearer tokens to proof-of-possession
-   **No IdP changes required**: Works with standard OIDC providers

### Remonce's Additional Security

| Feature | Benefit |
|---------|---------|
| **RFC 3161 TSA** | Cryptographic non-repudiation and time-bounding |
| **OPA Integration** | Fine-grained, policy-as-code authorization |
| **Command Allowlisting** | Restricts execution to pre-defined aliases |

### OpenPubkey's MFA Cosigner

OpenPubkey's **MFA Cosigner** is a second attestation intended to eliminate the IdP as a single point of compromise. Remonce's **operator cosign** serves a similar structural role — a second signature from a different identity — but with a different purpose: the operator attests to *freshness and attribution* at execution time, not to an independent MFA factor. Both patterns can coexist: a future enhancement could require the operator's IdP to be distinct from the approver's, or to include an MFA claim.

### Privacy Considerations

Both Remonce and OpenPubkey expose JWT claims when sharing signed artifacts. Mitigate this through:
-   **Dedicated clientID** (limits token scope)
-   **Claim minimization** (reduce exposed PII)
-   **Roles over groups** (less organizational exposure)

