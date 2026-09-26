# Architecture & Design

This document details the core architectural decisions, security mechanisms, and design philosophy behind Remonce.

## Core Problem Statement

Many organizations struggle with executing privileged actions on remote systems securely. Common patterns involve:
- **Persistent Credentials**: Leaving SSH keys or high-privilege IAM roles on machines.
- **VPNs/Bastions**: Complex network requirements that don't scale well across diverse clouds.
- **Lack of Non-Repudiation**: Hard to prove *who* executed a command and *when* it was approved.

Remonce aims to solve this by enabling **Signed Commands** that are verified cryptographically, time-bounded, and policy-driven.

## Signed Commands

A fundamental building block of this system is to enable users to sign a command (a JSON payload) such that we can verify that the individual approved it and did so during the period in which it was valid.

### Mechanisms Considered
1.  **Public Key Cryptography**: Users have a private key. (Problem: Management of persistent keys).
2.  **Trusted Signing Service**: Central service (e.g., Vault Transit) signs payloads. (Problem: Centralized dependency).
3.  **JWT-Based Ephemeral Signing (Chosen Approach)**: Leverage OIDC Identity to anchor ephemeral keys.

### The Chosen Approach: OIDC + Ephemeral Keys

This architecture uses the same core mechanism as [OpenPubkey](https://github.com/openpubkey/openpubkey): leveraging the **nonce** of an OIDC ID Token to bind an ephemeral public key to an identity.

1.  **Ephemeral Key Generation**: The client generates a random key pair for **one signature**.
2.  **Identity Binding**: The client runs a fresh OIDC login to the *signing* client, putting the hash of the Public Key into the JWT `nonce` and forcing re-authentication (`max_age`, optionally `prompt=login`).
3.  **Command Signing**: The client signs the command payload with the private key (normalized to low-S), then discards the key.
4.  **Verification Chain**:
    -   The **Signature** validates the command was signed by the Private Key.
    -   The **JWT** (signed by IdP) validates that the Public Key (in `nonce`) belongs to the User (in `sub`).
    -   The **IdP** (via JWKS) is trusted by the Agent.

### Comparison with OpenPubkey

OpenPubkey is an open-source protocol that augments OIDC with proof-of-possession—precisely what Remonce does. Both systems share the same foundational mechanism:

| Aspect | Remonce & OpenPubkey |
|--------|---------------------|
| Core Binding | Embed public key hash in OIDC `nonce` |
| Key Lifecycle | Ephemeral keys (one per signature) |
| IdP Role | Transforms IdP into implicit CA |
| No IdP Changes | Works with unmodified OIDC providers |

**Key Differences:**

| Aspect | Remonce | OpenPubkey |
|--------|---------|------------|
| **Use Case** | Remote command execution | General identity signing |
| **Timestamping** | RFC 3161 TSA for non-repudiation | Not standard |
| **Policy Engine** | Built-in OPA integration | Application-specific |
| **MFA Cosigner** | Not implemented | Optional (reduces single IdP trust) |

Remonce extends the OpenPubkey concept with **integrated authorization** (OPA) and **cryptographic timestamping** (TSA), making it purpose-built for auditable command execution rather than general-purpose signing.

### Time-Bounding & Non-Repudiation

JWTs are short-lived, but we may want to execute commands slightly later. However, we must prove the command was signed *while the user was present*.

-   **Solution**: **Timestamping Authority (TSA)**.
-   We send the signature to an RFC 3161 TSA.
-   The TSA returns a signed timestamp proving the signature existed at time $T$.
-   **Validation**: The Agent checks that $T$ is within the validity period of the User's ID Token.
-   **Freshness is measured from the login, not the timestamp.** A TSA will timestamp any bytes, so whoever holds a signature and its ID token can obtain a *fresh* timestamp over them. The timestamp alone therefore can't bound freshness. Because every signature gets its own login, the token's IdP-signed `iat` is effectively the signing time, and the agent requires:
    -   `iat − skew ≤ T ≤ iat + MAX_SIGN_DELAY` (5 minutes): a signature can't be re-timestamped long after the login that produced it;
    -   `iat − auth_time ≤ MAX_AUTH_AGE` (5 minutes): the login was a real re-authentication, not a silent SSO refresh;
    -   the role's freshness window (`operator_max_validity` / `approver_max_validity`) measured from **both** `iat` and $T$.

    The token's `exp` only has to be after $T$. Its lifetime is the IdP's choice and no longer extends how long a signature is usable: a signature is usable until `iat + window`, whatever the IdP issues.

## Delegated Signing (Approver + Operator)

Real-world operations rarely have the person authorizing an action also executing it. A senior engineer wants to approve a maintenance runbook in advance so the on-call NOC operator can execute it at 3am without waking the approver. Remonce models this directly with a two-signature protocol.

### Roles

-   **Approver**: authorizes an action. Signs the command + constraints with a **long** validity (default: 3 days). Can optionally restrict *who* may execute via OIDC claim predicates.
-   **Operator**: executes the action. Adds a co-signature with a **short** validity (default: 10 minutes). Provides at-execution-time freshness and attribution.
-   **Approver self-execute**: when the approver's own TSA timestamp is within the short (operator) window, no co-signature is required — they are acting as both roles. This is the common path for synchronous operations.

### Delegation mode is signed

Whether a bundle is meant for self-execution or for delegation is part of what the approver signs: the `operator_requires` field doubles as the mode.

| `operator_requires` | Mode | Self-execute | Co-sign |
|---|---|---|---|
| absent / `null` | Self-execute only | allowed (within the short window) | **rejected** |
| `{ "any_of": [] }` | Delegated to any operator | **rejected** | allowed (OPA still applies) |
| `{ "any_of": [ ... ] }` | Delegated with constraints | **rejected** | allowed if a predicate matches |

Without this, the unsigned `operator` field alone would decide the path: anyone holding a bundle meant for a `noc-l2` operator could drop the field and run it as the approver, and any self-execute bundle could be co-signed by anyone for days.

### Bundle shape

```
ExecutionBundle
├── approver: ApproverBundle
│     command                    // the JSON the approver authorized
│     operator_requires?         // null = self-execute only; present = delegated (+ predicates)
│     signature                  // over canonical(command + operator_requires)
│     id_token, public_key, timestamp_token
└── operator: OperatorCosign?    // absent when the approver self-executes
      approver_sig               // hex of the approver's signature — binds this cosign
      signature                  // over (approver_sig || operator.public_key_pem)
      id_token, public_key, timestamp_token
```

### Verification (agent)

0.  Enforce the signed delegation mode: reject a co-sign on a self-execute-only bundle, and a missing co-sign on a delegated one. All signature hex must be canonical lowercase, and every signature must be **low-S** (the `s → n−s` twin of a valid ECDSA signature is rejected).
1.  Verify the approver signature over `canonical(command + operator_requires)`.
2.  Verify the approver's TSA token covers `(approver_signature || approver_id_token)`.
3.  Verify the approver's OIDC JWT: signature, issuer, **strict audience** (`aud` is exactly the signing client — a string or one-element array — and `azp`, if present, matches), `nonce == SHA256(approver.public_key_pem)`, `exp > approver_tsa_timestamp`, and the `iat` / `auth_time` rules above.
4.  **If operator cosign present**:
    -   Verify the operator signature covers `(approver_sig_hex || operator.public_key_pem)` — this binds the cosign to *this specific* approver signature (prevents stapling).
    -   Verify the operator's TSA token and JWT the same way as the approver's.
    -   **Freshness**: the operator's `iat` and TSA time must be within `operator_max_validity`; the approver's within `approver_max_validity`.
    -   **Claim predicates**: if `operator_requires.any_of` is non-empty, at least one predicate must match the operator's JWT claims.
5.  **Else (self-execute)**: the approver's own `iat` and TSA time must be within the short (`operator_max_validity`) window.
6.  `self_executed` is true whenever approver and operator share the same OIDC `sub` — including an approver co-signing their own delegated bundle — so four-eyes policies (`not input.self_executed`) can't be satisfied by one person.

Only after these checks does the agent hand control to OPA, which sees both identities as `input.approver` and `input.operator` plus an `input.self_executed` flag. Most policy rules will be approver-centric; operator attestation is a fixed agent-level control.

### Claim predicates

The predicate language is deliberately small — if you need more expressive logic, put it in OPA rather than growing the predicate grammar:

| Op | Shape | Matches when |
|----|-------|-------------|
| `equals`    | `{ "op": "equals", "claim": "team", "value": "webapp" }` | Claim scalar equals `value` |
| `contains`  | `{ "op": "contains", "claim": "groups", "value": "noc-l2" }` | Claim array contains `value` |

`any_of` semantics: if any predicate in the list matches, the operator passes. Empty list means no claim restriction. Evaluation happens at **execution time** against the operator's freshly-issued OIDC token — so personnel changes (someone leaving a group) take effect immediately, not at approval time.

### Replay protection

The agent keeps an in-memory cache keyed on the *executor's key binding* (operator if delegated, approver if self-executing): the verified `nonce`, `SHA256(public_key_pem)`. It sits inside the IdP-signed token, so unlike signature bytes it can't be mauled into a fresh-looking variant, and with one key per signature it identifies the signature uniquely. The first submission succeeds; later submissions are rejected for as long as the signature could still pass freshness — until the executor's `iat` plus `operator_max_validity`. The entry is recorded as the last check before the process spawns (and released if spawning fails), so a bundle rejected for an unrelated reason can be retried.

Revocations key on the approver's key binding the same way, on every agent and on the central revocation service.

This complements — doesn't replace — the freshness windows: freshness bounds exposure, replay cache prevents double-execution within that window.

## Policy Engine (OPA)

Authentication proves *who* you are. Authorization proves *what* you can do.

Remonce integrates **Open Policy Agent (OPA)** to evaluate every request. OPA receives both the approver and operator identities (claims, username, signed_at) plus `self_executed`. Rules can:

-   Allow based on the approver's group (`input.approver.claims.groups`).
-   Require distinct identities via `not input.self_executed` (four-eyes).
-   Layer additional operator-side restrictions beyond the approver-embedded `operator_requires`.

A deny-by-default posture is the default. Example rules in [policy/authz.rego](policy/authz.rego).

## Future Considerations

### Revocation
Implemented: approvers (or, with OPA's consent, others) can revoke an approval before it expires, per agent or estate-wide through a central revocation service that agents consult fail-closed. See [CONFIGURATION.md](CONFIGURATION.md#revoking-an-approval-remonce-revoke).

### Multi-party approval chains
The current design accepts exactly one approver + one optional operator. For workflows that need $N$ approvers, the approver bundle would generalize to a list, with the verification extending naturally. Not currently implemented.

### Zero Knowledge Proofs (ZK-JWT) with SP1 — proposal, not implemented
Delegation currently exposes the approver's full ID token to whoever executes the bundle. The token is useless for signing new commands (it is nonce-bound to the approver's ephemeral key), and its audience is the *signing* client, which the agent's viewer endpoints reject — so it can't be used to browse files or logs either. It still discloses every claim the IdP put in it, and it remains a valid bearer token for any *other* service that accepts that audience without checking the binding.

A general-purpose zkVM such as [SP1](https://github.com/succinctlabs/sp1) could remove that exposure. The goal is not to hide *who* approved, but to keep the raw JWT (and its signature) away from the executor:

*   **Mechanism**: the approver runs a Rust program inside the zkVM with the JWT and ephemeral public key as private inputs.
*   **Circuit logic**: verify the ID token's signature against the IdP key (public input), and extract `sub`, `iss`, `aud`, `exp`, `nonce` and `groups`/`roles`.
*   **Public outputs**: the identity claims, the ephemeral public key the nonce binds, and the `kid` that verified the token.
*   **Agent flow**: verify the command signature against the public key, verify the proof, check the `kid` against the IdP's JWKS, and check the proof binds that same public key.
*   **Trade-offs**: logic is plain Rust rather than a circuit DSL, but proving takes seconds to minutes versus microseconds for native checks.

Earlier we also looked at zkSNARKs such as [Spartan](https://github.com/Microsoft/Spartan) for privacy-preserving signatures; standard OIDC was judged sufficient without the proving overhead.

#### Why keep ephemeral keys?
Each login now signs exactly one thing, so the command hash could go straight into the nonce. The key stays because:

-   cosign and revocation payloads include the signer's public key, and the TSA timestamp covers a proof-of-possession signature;
-   the wire format and verifier are the same for approve, cosign and revoke;
-   the key binding is a stable, non-malleable identity for the replay and revocation caches.
