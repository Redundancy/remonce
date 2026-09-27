# Security Architecture

## Overview

Remonce is a remote command execution system designed with a security-first approach ("Zero Trust Remote Execution"). It ensures that any command executed on a target machine is individually authenticated, authorized, and time-bound.

The core security model relies on:
1.  **OIDC Authentication**: Users authenticate via an OIDC provider (HashiCorp Vault).
2.  **Digital Signatures**: Each approval of a request is a signature by a one-time key, bound to the approver's identity.
3.  **Third-Party Timestamping**: A Timestamp Authority (TSA) safeguards against replay attacks and key compromise.
4.  **Policy-as-Code**: Authorization logic is decoupled into OPA (Open Policy Agent) Rego policies, which also publish what each command needs.

## Verification Flow

A request is a command plus any number of independent approvals, each one person's signature over the same payload (see [ARCHITECTURE.md](ARCHITECTURE.md#requests-and-approvals)). When the Agent receives one on `/execute`, it performs this strict sequence (see [src/security.rs](src/security.rs) and [src/agent.rs](src/agent.rs)):

1.  **Executor identity**: a viewer-client bearer token with a strict audience check. No token, no execution: whoever submits is always identified.
2.  **Shape**: the bundle parses as `{command, approvals}` (pre-v2 bundles are refused with an explanation), the command is configured on this agent, and its `id` is a UUID.
3.  **Each approval** (1–16), with errors naming the approval's index:
    -   **Signature**: ECDSA-P-256 over `{"command": …, "remonce": "request/v2"}` (compact, sorted keys). Hex must be canonical lowercase, and the signature **low-S**: its `s → n−s` twin is equally valid ECDSA, so accepting both would let anyone holding a bundle mint a byte-different copy.
    -   **TSA**: the RFC 3161 token covers `(signature || id_token)`. Chain validation is delegated to `rustls-webpki` (see "TSA trust model" below) and enforces:
        -   signature verification up to a trusted root
        -   `notBefore` / `notAfter` at the TSA's own `gen_time` (historical validity — correct for timestamps)
        -   `id-kp-timeStamping` Extended Key Usage on the signer cert (RFC 3161 §2.3)
        -   signer cert identified by **issuer DN + serial**, not serial alone (RFC 5652 §5.1)
    -   **JWT + nonce binding**: OIDC signature and issuer, and a **strict audience**: `aud` must be exactly the *signing* client (a string or one-element array) and `azp`, if present, must match — so a viewer token, or a token issued to several clients, never passes. `nonce == SHA256(public_key_pem)` binds the one-time key to the approver's identity, and `sub` must be present. Then the times, all IdP-attested:
        -   `exp > tsa_timestamp`;
        -   `iat − skew ≤ tsa_timestamp ≤ iat + 5 min` — the signature was timestamped right after the login that produced it, so a later re-timestamp is rejected;
        -   `iat − auth_time ≤ 5 min` (and `auth_time` not after `iat`) — the login was a real re-authentication, not a silent SSO refresh. Missing `iat` or `auth_time` is rejected;
        -   TSA time or `iat` more than 5 minutes in the future is rejected.
    -   **Freshness**: `iat` and the TSA time are both within the command's `approval_validity` (default 1 hour).
4.  **Distinct approvers**: no two approvals may share an OIDC `sub`. Compared only after every token is verified, since an unverified `sub` is attacker-controlled.
5.  **Command-level constraints**:
    -   **Target machine**: `target_machines` must include this agent's hostname.
    -   **Time window**: `not_before` / `not_after` enforced if present; a present but malformed bound denies.
    -   **Parameters**: signed `params` validated against `[[commands.params]]`, fail-closed.
6.  **Revocation**: the **request id** (hex SHA-256 of the signed payload) must not be on the agent's revocation list, nor (when configured) on the central revocation service's — an unreachable service denies execution.
7.  **OPA authorization**: input is the command, request id, every approver (`username`, full claims, `signed_at`), the executor (`username`, claims) and the host. The shipped policy allows when the command's published requirement document is satisfied — every slot filled by a different approver, and the executor accepted — and no extra rule denies. Deny-by-default.
8.  **Replay cache**: last, just before spawning. The request id is recorded until every approval that could run it has expired; first-seen wins, and if spawning fails the entry is released so the request can be retried.

## Threat Model

1.  **Compromised Command Payload**
    *   *Attack*: Attacker modifies the command payload (e.g., changing the `command` field) after it was signed.
    *   *Mitigation*: **ECDSA Signature**. The signature covers the entire payload. Any modification invalidates it.
    *   *Note*: The payload `command` field is an **alias** (e.g., `backup-db`), not a raw shell command. The actual executable logic is defined and controlled on the Agent side. This prevents an attacker from injecting arbitrary code (like `rm -rf /`) even if they could forge a signature, as they are restricted to pre-defined allowed aliases.

2.  **Replay Attacks (Long-term)**
    *   *Attack*: Attacker captures an approved request and tries to execute it later.
    *   *Mitigation*: **Freshness from the login + replay cache**. Every approval must be within the command's `approval_validity` (default 1 hour) of its login, measured from the token's IdP-signed `iat`, so it can't be stretched by re-timestamping or by a long IdP token lifetime. Within that window the replay cache refuses a second run.

3.  **Replay Attacks (Short-term, within the validity window)**
    *   *Attack*: Attacker obtains an approved bundle (in flight, from a shared folder, from logs) and resubmits it.
    *   *Mitigation*: **Replay cache keyed on the request id**. The first run wins; any resubmission of the same request is refused, whoever submits it and whichever of its approvals it carries. The cache is in memory: an agent restart forgets it, and exposure after a restart is bounded by `approval_validity`. Keep that short for sensitive commands, or make the request single-use by other means (the attacker also needs a viewer login that policy accepts as executor).

4.  **Key Compromise (Ephemeral User Keys)**
    *   *Attack*: Attacker steals the user's private signing key.
    *   *Mitigation*: **One key per signature**. Every approval and revocation generates a fresh key and its own re-authenticating OIDC login; the key signs once and is discarded. Even while its token is unexpired, a stolen key can't sign anything new that verifies: a new signature needs a TSA time within 5 minutes of the token's `iat`. The local signer's session holds no signing capability at all — only a viewer token.

5.  **Man-in-the-Middle (MitM)**
    *   *Attack*: Interception of traffic between the signer and the agent.
    *   *Mitigation*: **Mandatory TLS on the agent**. The agent refuses to serve without TLS configured (file-based cert or ACME). The signer is meant to run on the approver's workstation bound to loopback; when it serves a remote browser, give it TLS.

6.  **Approval Transplant**
    *   *Attack*: Attacker takes a genuine approval of request A and attaches it to request B (different parameters, target, or just a different `id`), hoping B runs with A's approvers.
    *   *Mitigation*: every approval signs the whole command, `id` included, under a domain tag. An approval of A never verifies for B, so each request needs its own approvals, and the agent names the approval that failed.

7.  **One Person, Two Approvals**
    *   *Attack*: A request needs two approvers; one person logs in twice and approves it twice.
    *   *Mitigation*: the agent rejects a bundle in which two approvals share a verified `sub`, and policy's slot check requires a *different* approver per slot. The signer also refuses to add an approval from someone who already approved (a convenience; the agent is the check). Where one person has several IdP accounts, that is an IdP-side control.

8.  **Compromised or Malicious Approver (Insider Threat)**
    *   *Attack*: A user with approval rights approves a malicious request, or their account is phished.
    *   *Mitigation*: **Requirements published by policy**. A command that matters needs several approvals from people in different roles, so one compromised account isn't enough. Only configured command aliases can run, every approver is recorded in the audit log and the run log, and any approver can revoke the request until it runs.

9.  **Stolen Viewer Session (Executor Credential)**
    *   *Attack*: Attacker steals someone's viewer token (the signer's session, or a bearer token in transit) and uses it to submit an approved bundle they have also obtained.
    *   *Mitigation (partial)*: the viewer token is the executor's credential, with no proof of possession. It can't approve or sign anything, and policy's `executors` rule limits whose token can run each command. The attacker needs both a complete, unexpired, unrun request and an accepted executor's token, and the run is attributed to that executor in the audit log. Keep viewer tokens short-lived at the IdP; policy can also require a recent login via `input.executor.claims.iat`.

10. **Shared Token Exposure**
    *   *Attack*: A bundle carries every approver's ID token, visible to the next approver, the executor, and anyone who obtains the file.
    *   *Scope*: Limited to systems accepting the *signing* client's audience. The agent's viewer endpoints and executor check accept only the separate *viewer* client, so a token lifted from a bundle can't browse files or logs, or run anything.
    *   *Mitigation*: **Two dedicated clients** (signing and viewer, required to differ), **strict audience checks**, **nonce binding** (JWTs unusable for new approvals without the one-time private keys), **command allowlisting**, and **claim minimization** (request only necessary claims from the IdP). A future ZK proof could keep the tokens with their owners (see [ARCHITECTURE.md](ARCHITECTURE.md#zero-knowledge-proofs-zk-jwt--proposal-not-implemented)).

11. **Subprocess Misbehavior (long-running, env exfiltration, stdin hang)**
    *   *Attack*: A configured command runs indefinitely, leaks parent-process env vars, or hangs reading stdin.
    *   *Mitigation*: Every spawned process has stdin closed (`Stdio::null`), a fully cleared environment (`env_clear()` plus only the operator-supplied `env` map from `[[commands]]`), and a wall-clock timeout (`command_timeout`, default 5 minutes). On timeout, the agent SIGKILLs the child and writes a TIMEOUT trailer into the execution log.

12. **Path Traversal via execution ID**
    *   *Attack*: A signed request includes `id: "../../etc/passwd"`; the agent uses it to construct the log file path.
    *   *Mitigation*: the agent refuses a request whose `id` isn't a UUID, before any filesystem use. The `/stream/{id}` log-tailing endpoint applies the same UUID gate.

13. **File Resolver Symlink Traversal**
    *   *Attack*: Operator drops a symlink inside a configured `[[files]]` glob directory pointing at a sensitive file outside the allowlist.
    *   *Mitigation*: `safe_canonicalize` rejects any final component that is a symlink, then canonicalizes parent components for stable comparison. Path-mode requests are matched against canonicalized glob expansions, so `..` segments and relative-vs-absolute mismatches no longer bypass the allowlist.

14. **Unauthenticated File Listing**
    *   *Attack*: Anyone who can reach the agent's `/api/files` discovers the configured file allowlist (paths, names, descriptions).
    *   *Mitigation*: `/api/files` now requires the same bearer ID token as `/api/files/stream`. Token verification is shared via `verify_query_token` so the two endpoints can't drift apart. Only viewer-client tokens are accepted.

15. **Signature Malleability**
    *   *Attack*: ECDSA signatures come in pairs: if `(r, s)` is valid, so is `(r, n−s)`. A holder of any bundle derives the twin, obtains a fresh timestamp over it, and resubmits a byte-different but valid bundle — dodging a replay cache or revocation list keyed on signature bytes.
    *   *Mitigation*: signers normalize to low-S and the verifier rejects high-S signatures; independently, the replay and revocation caches key on the request id — the hash of what was signed — which no change to the signatures affects.

16. **Re-timestamping**
    *   *Attack*: A TSA timestamps any bytes, so a holder of a signature and its ID token can get a new timestamp at any time before the token's `exp` — making an old signature look fresh for as long as the IdP's token lifetime.
    *   *Mitigation*: freshness is measured from the token's `iat`; a TSA time more than 5 minutes after `iat` is rejected. The IdP's token lifetime no longer matters.

## Audit Logging

Every execution attempt (Allowed or Denied) and every revocation generates a structured audit log entry on the agent's stdout.
- **Contents**: timestamp, event type, `user` (the executor, or the revoker), source IP, decision, reason, the full command, the `request_id`, and every approver (`username`, `sub`, signing time).
- **Run log**: `logs/<execution_id>.log` starts with a header naming the request id, each approver and when they signed, the executor, and the start time.

## Key Management

- **User Keys**: A fresh ECDSA key per signature, generated by the signer (or CLI) for one OIDC login and discarded after one signature. The private key never leaves the machine running the signer; between the IdP redirect and the callback it sits in the signer's in-memory session.
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

Currently gated: HTTP non-loopback OIDC issuer, `trust_system_store` for TSA, `approval_validity` above 7 days, wildcard CORS. See [CONFIGURATION.md](CONFIGURATION.md) for the full table.

Some settings are wrong rather than risky, and `--insecure` does **not** bypass them: an empty `oidc.client_id`, a `viewer_client_id` equal to `client_id` (it would make every signing token a viewing and executing bearer credential), a `signing_max_age` above 5 minutes (signatures made with it could never verify), and an `approval_validity` of 0.

Design intent: the flag is blunt. It's meant to be visible in process listings, systemd units, and audit logs, not to be a routine knob. Operators who need one specific unsafe setting and *not* the others can still use `--insecure` — it turns on whatever the config already enables, not more.

## JWT Exposure Considerations

A request carries one OIDC ID token per approval. Each is visible to later approvers, the executor, and anyone with the file. This section outlines the risks and mitigations.

### What Is Exposed

Each ID token in a request may contain:
-   User identity (`sub`, `email`, `name`)
-   Group memberships or roles
-   Token metadata (`iat`, `exp`, `aud`)

### Risk Scoping

> [!IMPORTANT]
> **Use two dedicated OIDC clients for Remonce**: a *signing* client (`client_id`) and a *viewer* client (`viewer_client_id`). The JWT's `aud` (audience) claim limits each token to its client. Dedicated clients ensure tokens cannot be replayed against other applications in your organization, and separate ones ensure a signing token carried in a request is never a viewing or executing credential.

### Claim Minimization Best Practices

Reduce information exposure by configuring your IdP to issue minimal claims:

-   **Prefer `roles` over `groups`**: Roles expose less organizational structure than group names.
-   **Request minimal scopes**: Only request claims needed for OPA policy decisions.
-   **Avoid PII if possible**: If your policy doesn't need `email` or `name`, don't request them.

### Existing Mitigations

| Mitigation | Effect |
|------------|--------|
| `iat`-bounded freshness | A signature is usable only within its window of the login, whatever the token lifetime |
| Separate viewer audience | Signing tokens in requests can't be used to browse files or logs, or to execute |
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

OpenPubkey's **MFA Cosigner** is a second attestation intended to eliminate the IdP as a single point of compromise. Remonce's multiple approvals are a different thing: several people, all vouched for by the same IdP, agree to one request. They limit what one compromised *account* can do, not a compromised IdP. A requirement document can ask for an MFA claim (e.g. `amr`) on an approval slot, and a future enhancement could accept approvals from several IdPs.

### Privacy Considerations

Both Remonce and OpenPubkey expose JWT claims when sharing signed artifacts. Mitigate this through:
-   **Dedicated clientID** (limits token scope)
-   **Claim minimization** (reduce exposed PII)
-   **Roles over groups** (less organizational exposure)

