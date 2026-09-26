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

0.  **Delegation mode**: `operator_requires` is signed and doubles as the mode — absent means self-execute only (a co-sign is rejected), present means delegated (self-execution is rejected). Signature hex must be canonical lowercase (`hex::decode` accepts case variants of the same bytes, and the operator payload signs the approver's hex string).
1.  **Approver signature**: Verify the approver's ECDSA-P-256 signature over `canonical(command + operator_requires)`. The signature must be **low-S**: its `s → n−s` twin is equally valid ECDSA, so accepting both would let anyone holding a bundle mint a byte-different copy.
2.  **Approver TSA**: Validate the RFC 3161 timestamp token covering `(approver_signature || approver_id_token)`. Chain validation is delegated to `rustls-webpki` (see "TSA trust model" below) and enforces:
    -   signature verification up to a trusted root
    -   `notBefore` / `notAfter` at the TSA's own `gen_time` (historical validity — correct for timestamps)
    -   `id-kp-timeStamping` Extended Key Usage on the signer cert (RFC 3161 §2.3)
    -   signer cert identified by **issuer DN + serial**, not serial alone (RFC 5652 §5.1)
3.  **Approver JWT + nonce binding**: Validate OIDC signature and issuer, and a **strict audience**: `aud` must be exactly the *signing* client (a string or one-element array) and `azp`, if present, must match — so a viewer token, or a token issued to several clients, never passes. Verify `nonce == SHA256(approver.public_key_pem)` — this binds the ephemeral command-signing key to the user's identity. Then the times, all IdP-attested:
    -   `exp > approver_tsa_timestamp`;
    -   `iat − skew ≤ tsa_timestamp ≤ iat + 5 min` — the signature was timestamped right after the login that produced it, so a later re-timestamp is rejected;
    -   `iat − auth_time ≤ 5 min` (and `auth_time` not after `iat`) — the login was a real re-authentication, not a silent SSO refresh. Missing `iat` or `auth_time` is rejected.
4.  **Delegation branch**:
    *   **If operator cosign present**:
        -   Verify the operator's signature over `(approver_sig_hex || operator.public_key_pem)`. Because the operator signs *over the approver's signature hex*, the cosign is cryptographically bound to *this specific* approver signature. An attacker cannot staple an operator cosign from one authorized command onto a different approver's bundle.
        -   Verify operator TSA and JWT the same way as the approver (nonce binds operator's ephemeral key to their identity).
        -   **Freshness**: the operator's `iat` and TSA time must be within `operator_max_validity` (default 10 min); the approver's within `approver_max_validity` (default 3 days).
        -   **Claim predicates**: if `operator_requires.any_of` is non-empty, at least one predicate must match the operator's JWT claims.
    *   **Else (self-execute)**: the approver's own `iat` and TSA time must be within the short (`operator_max_validity`) window — when acting as their own executor, freshness still applies.
    *   `self_executed` is true whenever approver and operator share an OIDC `sub`, so an approver co-signing their own delegation cannot satisfy a four-eyes rule.
    *   TSA timestamps or `iat` more than 5 minutes in the future are rejected.
5.  **Revocation**: the approval's **key binding** (`SHA256(approver.public_key_pem)`, the verified nonce) must not be on the agent's revocation list, nor (when configured) on the central revocation service's — an unreachable service denies execution.
6.  **Command-level constraints**:
    -   **Target machine**: approver's `target_machines` must include this agent's hostname.
    -   **Time window**: `not_before` / `not_after` enforced if present; a present but malformed bound denies.
    -   **Parameters**: signed `params` validated against `[[commands.params]]`, fail-closed.
7.  **OPA authorization**: Input includes `input.approver` (username, full claims, signed_at), `input.operator` (same shape), `input.self_executed`, `input.command`, and `input.host`. Policy evaluates with a deny-by-default posture.
8.  **Replay cache**: last, just before spawning. The executor's key binding (operator if delegated, approver otherwise) is recorded until the signature could no longer pass freshness — the executor's `iat` plus `operator_max_validity`. First-seen wins; if spawning fails the entry is released so the bundle can be retried.

## Threat Model

1.  **Compromised Command Payload**
    *   *Attack*: Attacker modifies the command payload (e.g., changing the `command` field) after it was signed.
    *   *Mitigation*: **ECDSA Signature**. The signature covers the entire payload. Any modification invalidates it.
    *   *Note*: The payload `command` field is an **alias** (e.g., `backup-db`), not a raw shell command. The actual executable logic is defined and controlled on the Agent side. This prevents an attacker from injecting arbitrary code (like `rm -rf /`) even if they could forge a signature, as they are restricted to pre-defined allowed aliases.

2.  **Replay Attacks (Long-term)**
    *   *Attack*: Attacker captures a valid execution bundle and tries to execute it later.
    *   *Mitigation*: **Two-tier freshness + replay cache**. The executor signature (operator cosign in delegated flows, approver signature in self-execute) must be within `operator_max_validity` (default 10 min) of its login. The approver signature is separately bounded by `approver_max_validity` (default 3 days). Both are measured from the token's IdP-signed `iat`, so neither can be stretched by re-timestamping or by a long IdP token lifetime. The agent additionally caches executor key bindings in memory; a second submission inside the freshness window is rejected as a replay.

3.  **Replay Attacks (Short-term, within freshness window)**
    *   *Attack*: Attacker observes a signed bundle in flight (or from logs) and resubmits it before the short window expires.
    *   *Mitigation*: **In-memory replay cache** keyed on the executor's key binding. First-seen wins; the entry lives until `iat + operator_max_validity`. Cache is not persistent across agent restarts — the short window, counted from the login, bounds exposure after a restart whatever the IdP's token lifetime.

4.  **Key Compromise (Ephemeral User Keys)**
    *   *Attack*: Attacker steals the user's private signing key.
    *   *Mitigation*: **One key per signature**. Every approval, cosign and revocation generates a fresh key and its own re-authenticating OIDC login; the key signs once and is discarded. Even while its token is unexpired, a stolen key can't sign anything new that verifies: a new signature needs a TSA time within 5 minutes of the token's `iat`. The local signer's session holds no signing capability at all — only a viewer token.

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
    *   *Scope*: Limited to systems accepting the *signing* client's audience. The agent's file and log endpoints accept only the separate *viewer* client, so a token lifted from a bundle can't be used to browse, and the JWTs cannot be used to authenticate to unrelated services.
    *   *Mitigation*: **Two dedicated clients** (signing and viewer, required to differ), **strict audience checks**, **nonce binding** (JWTs unusable for new commands without the corresponding private keys), **command allowlisting**, and **claim minimization** (request only necessary claims from the IdP).

10. **Subprocess Misbehavior (long-running, env exfiltration, stdin hang)**
    *   *Attack*: A configured command runs indefinitely, leaks parent-process env vars, or hangs reading stdin.
    *   *Mitigation*: Every spawned process has stdin closed (`Stdio::null`), a fully cleared environment (`env_clear()` plus only the operator-supplied `env` map from `[[commands]]`), and a wall-clock timeout (`command_timeout`, default 5 minutes). On timeout, the agent SIGKILLs the child and writes a TIMEOUT trailer into the execution log.

11. **Path Traversal via execution ID**
    *   *Attack*: Approver-signed payload includes `id: "../../etc/passwd"`; the agent uses it to construct the log file path.
    *   *Mitigation*: `execution_id` is parsed through `uuid::Uuid::parse_str` before any filesystem use. Non-UUID values are silently replaced with a freshly generated UUID. The `/stream/{id}` log-tailing endpoint applies the same UUID gate.

12. **File Resolver Symlink Traversal**
    *   *Attack*: Operator drops a symlink inside a configured `[[files]]` glob directory pointing at a sensitive file outside the allowlist.
    *   *Mitigation*: `safe_canonicalize` rejects any final component that is a symlink, then canonicalizes parent components for stable comparison. Path-mode requests are matched against canonicalized glob expansions, so `..` segments and relative-vs-absolute mismatches no longer bypass the allowlist.

13. **Unauthenticated File Listing**
    *   *Attack*: Anyone who can reach the agent's `/api/files` discovers the configured file allowlist (paths, names, descriptions).
    *   *Mitigation*: `/api/files` now requires the same bearer ID token as `/api/files/stream`. Token verification is shared via `verify_query_token` so the two endpoints can't drift apart. Only viewer-client tokens are accepted.

14. **Signature Malleability**
    *   *Attack*: ECDSA signatures come in pairs: if `(r, s)` is valid, so is `(r, n−s)`. A holder of any bundle derives the twin, obtains a fresh timestamp over it, and resubmits a byte-different but valid bundle — dodging a replay cache or revocation list keyed on signature bytes, and so re-running a revoked approval.
    *   *Mitigation*: signers normalize to low-S and the verifier rejects high-S signatures; independently, the replay and revocation caches key on the IdP-attested key binding, which the twin shares.

15. **Re-timestamping**
    *   *Attack*: A TSA timestamps any bytes, so a holder of a signature and its ID token can get a new timestamp at any time before the token's `exp` — making an old signature look fresh for as long as the IdP's token lifetime.
    *   *Mitigation*: freshness is measured from the token's `iat`; a TSA time more than 5 minutes after `iat` is rejected. The IdP's token lifetime no longer matters.

## Audit Logging

Every execution attempt (Allowed or Denied) generates a structured audit log entry.
- **Location**: `logs/<execution_id>.log` (and stdout for the agent service).
- **Contents**: Timestamp, User, Source IP, Decision, Reason, and the Full Command.

## Key Management

- **User Keys**: A fresh ECDSA key per signature, generated by the local signer (or CLI) for one OIDC login and discarded after one signature. The private key never leaves the operator's workstation (the signer is loopback-only); between the IdP redirect and the callback it sits in the signer's in-memory session.
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

Some settings are wrong rather than risky, and `--insecure` does **not** bypass them: an empty `oidc.client_id`, a `viewer_client_id` equal to `client_id` (it would make every signing token a file-viewing bearer credential), and a `signing_max_age` above 5 minutes (signatures made with it could never verify).

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
> **Use two dedicated OIDC clients for Remonce**: a *signing* client (`client_id`) and a *viewer* client (`viewer_client_id`). The JWT's `aud` (audience) claim limits each token to its client. Dedicated clients ensure tokens cannot be replayed against other applications in your organization, and separate ones ensure a signing token carried in a bundle is never a file/log viewing credential.

### Claim Minimization Best Practices

Reduce information exposure by configuring your IdP to issue minimal claims:

-   **Prefer `roles` over `groups`**: Roles expose less organizational structure than group names.
-   **Request minimal scopes**: Only request claims needed for OPA policy decisions.
-   **Avoid PII if possible**: If your policy doesn't need `email` or `name`, don't request them.

### Existing Mitigations

| Mitigation | Effect |
|------------|--------|
| `iat`-bounded freshness | A signature is usable only within its window of the login, whatever the token lifetime |
| Separate viewer audience | Signing tokens in bundles can't be used to browse files or logs |
| Nonce binding | JWT is cryptographically bound to the ephemeral key—unusable for new commands |
| TSA timestamping | Proves command was signed during valid window, enabling post-hoc audit |
| Command allowlisting | Even with a valid token, only pre-approved commands can execute |

## Comparison with OpenPubkey

Remonce uses the same core mechanism as [OpenPubkey](https://github.com/openpubkey/openpubkey): binding an ephemeral public key to an OIDC identity via the JWT `nonce` field.

### Shared Security Properties

-   **Ephemeral keys**: Generated per signature, reducing key compromise window
-   **Nonce binding**: IdP implicitly attests to key ownership
-   **Proof-of-possession**: Upgrades bearer tokens to proof-of-possession
-   **No IdP changes required**: Works with standard OIDC providers

### Remonce's Additional Security

| Feature | Benefit |
|---------|---------|
| **RFC 3161 TSA** | Cryptographic non-repudiation and time-bounding |
| **OPA Integration** | Fine-grained, policy-as-code authorization |
| **Command Allowlisting** | Restricts execution to pre-defined aliases |

### Sigstore & Transparency Logs

Remonce shares the "keyless" signing philosophy of [Sigstore](https://www.sigstore.dev/) but differs in implementation to suit private enterprise constraints:

1.  **Identity binding (nonce vs Fulcio)**:
    *   **Sigstore** uses a dedicated CA (Fulcio) to issue short-lived X.509 certificates based on OIDC identity.
    *   **Remonce** (like OpenPubkey) binds the ephemeral key directly into the OIDC ID token via the `nonce` claim — the standard OIDC field for binding client state — avoiding separate CA infrastructure. This is not the criticized practice of overloading `aud`.
    *   **Audience validation**: Remonce strictly checks that the token's `aud` is the configured client ID, so a token issued for another application is never accepted (no confused-deputy).
2.  **IdP as single point of trust**:
    *   **Risk**: without a public transparency log (Sigstore's Rekor), a compromised IdP could mint tokens binding its own keys and impersonate users.
    *   **Mitigation**: authorization is decoupled from identity. A forged identity is still confined by the agent's command allow-list and OPA policy, and every execution lands in the audit log.
3.  **Timestamping vs transparency**:
    *   An RFC 3161 TSA provides non-repudiation and time-bounding, similar to Rekor's role.
    *   **Privacy**: Remonce deliberately avoids a public transparency log so enterprise execution data (command names, user identities) isn't published.

### OpenPubkey's MFA Cosigner

OpenPubkey's **MFA Cosigner** is a second attestation intended to eliminate the IdP as a single point of compromise. Remonce's **operator cosign** serves a similar structural role — a second signature from a different identity — but with a different purpose: the operator attests to *freshness and attribution* at execution time, not to an independent MFA factor. Both patterns can coexist: a future enhancement could require the operator's IdP to be distinct from the approver's, or to include an MFA claim.

### Privacy Considerations

Both Remonce and OpenPubkey expose JWT claims when sharing signed artifacts. Mitigate this through:
-   **Dedicated clientID** (limits token scope)
-   **Claim minimization** (reduce exposed PII)
-   **Roles over groups** (less organizational exposure)

