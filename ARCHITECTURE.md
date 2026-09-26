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

1.  **Ephemeral Key Generation**: The client generates a random key pair for the session.
2.  **Identity Binding**: The client authenticates with the IdP (Vault/OIDC), putting the hash of the Public Key into the JWT `nonce`.
3.  **Command Signing**: The client signs the command payload with the private key.
4.  **Verification Chain**:
    -   The **Signature** validates the command was signed by the Private Key.
    -   The **JWT** (signed by IdP) validates that the Public Key (in `nonce`) belongs to the User (in `sub`).
    -   The **IdP** (via JWKS) is trusted by the Agent.

### Comparison with OpenPubkey

OpenPubkey is an open-source protocol that augments OIDC with proof-of-possession—precisely what Remonce does. Both systems share the same foundational mechanism:

| Aspect | Remonce & OpenPubkey |
|--------|---------------------|
| Core Binding | Embed public key hash in OIDC `nonce` |
| Key Lifecycle | Ephemeral keys (per-session/command) |
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
-   **Caveat — re-timestamping**: a TSA will timestamp any bytes, so whoever holds a signature and its ID token can obtain a *fresh* timestamp over them until the token's `exp`. Freshness windows therefore effectively run until `token_exp + window`, not `first_timestamp + window`. The replay cache and revocation list size their retention accordingly; keep ID token lifetimes short.

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

0.  Enforce the signed delegation mode: reject a co-sign on a self-execute-only bundle, and a missing co-sign on a delegated one. All signature hex must be canonical lowercase (the replay and revocation caches key on it).
1.  Verify the approver signature over `canonical(command + operator_requires)`.
2.  Verify the approver's TSA token covers `(approver_signature || approver_id_token)`.
3.  Verify the approver's OIDC JWT: signature, issuer, audience, `nonce == SHA256(approver.public_key_pem)`, and `exp > approver_tsa_timestamp`.
4.  **If operator cosign present**:
    -   Verify the operator signature covers `(approver_sig_hex || operator.public_key_pem)` — this binds the cosign to *this specific* approver signature (prevents stapling).
    -   Verify the operator's TSA token and JWT the same way as the approver's.
    -   **Freshness**: operator TSA timestamp must be within `operator_max_validity`; approver TSA must be within `approver_max_validity`.
    -   **Claim predicates**: if `operator_requires.any_of` is non-empty, at least one predicate must match the operator's JWT claims.
5.  **Else (self-execute)**: the approver's own TSA timestamp must be within the short (`operator_max_validity`) window.
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

The agent keeps an in-memory cache keyed on the *executor* signature (operator cosign if delegated, approver signature if self-executing). The first submission succeeds; later submissions are rejected for as long as the signature could still pass freshness — until the executor's token expiry plus `operator_max_validity`, since the signature can be re-timestamped up to token expiry. The entry is recorded as the last check before the process spawns (and released if spawning fails), so a bundle rejected for an unrelated reason can be retried.

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
Delegation currently exposes the approver's full ID token to whoever executes the bundle. The token is useless for signing new commands (it is nonce-bound to the approver's ephemeral key), but it is still a valid bearer token for any service that accepts it without checking the binding — which is why Remonce needs a dedicated OIDC client ID.

A general-purpose zkVM such as [SP1](https://github.com/succinctlabs/sp1) could remove that exposure. The goal is not to hide *who* approved, but to keep the raw JWT (and its signature) away from the executor:

*   **Mechanism**: the approver runs a Rust program inside the zkVM with the JWT and ephemeral public key as private inputs.
*   **Circuit logic**: verify the ID token's signature against the IdP key (public input), and extract `sub`, `iss`, `aud`, `exp`, `nonce` and `groups`/`roles`.
*   **Public outputs**: the identity claims, the ephemeral public key the nonce binds, and the `kid` that verified the token.
*   **Agent flow**: verify the command signature against the public key, verify the proof, check the `kid` against the IdP's JWKS, and check the proof binds that same public key.
*   **Trade-offs**: logic is plain Rust rather than a circuit DSL, but proving takes seconds to minutes versus microseconds for native checks.

Earlier we also looked at zkSNARKs such as [Spartan](https://github.com/Microsoft/Spartan) for privacy-preserving signatures; standard OIDC was judged sufficient without the proving overhead.

#### Why keep ephemeral keys?
Binding the command hash directly into the nonce would skip the ephemeral key, but the nonce is fixed once the token is issued: one login could authorize exactly one command. Binding a key instead (`nonce == hash(key)`) lets one login sign many commands for the token's lifetime — the session UX the CLI and web UI rely on.
