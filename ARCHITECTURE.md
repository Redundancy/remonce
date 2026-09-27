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
3.  **Request Signing**: The client signs the request payload with the private key (normalized to low-S), then discards the key.
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
| **Policy Engine** | Rego, embedded or on an OPA server | Application-specific |
| **Multi-party approval** | N independent approvals, requirements set by policy | Optional MFA cosigner (reduces single IdP trust) |

Remonce extends the OpenPubkey concept with **integrated authorization** (OPA) and **cryptographic timestamping** (TSA), making it purpose-built for auditable command execution rather than general-purpose signing.

### Time-Bounding & Non-Repudiation

JWTs are short-lived, but a request may run some time after it is approved. We must still prove each approval was made *while the approver was present*.

-   **Solution**: **Timestamping Authority (TSA)**.
-   We send the signature to an RFC 3161 TSA.
-   The TSA returns a signed timestamp proving the signature existed at time $T$.
-   **Validation**: The Agent checks that $T$ is within the validity period of the approver's ID Token.
-   **Freshness is measured from the login, not the timestamp.** A TSA will timestamp any bytes, so whoever holds a signature and its ID token can obtain a *fresh* timestamp over them. The timestamp alone therefore can't bound freshness. Because every signature gets its own login, the token's IdP-signed `iat` is effectively the signing time, and the agent requires:
    -   `iat − skew ≤ T ≤ iat + MAX_SIGN_DELAY` (5 minutes): a signature can't be re-timestamped long after the login that produced it;
    -   `iat − auth_time ≤ MAX_AUTH_AGE` (5 minutes): the login was a real re-authentication, not a silent SSO refresh;
    -   the command's `approval_validity` (default 1 hour) measured from **both** `iat` and $T$.

    The token's `exp` only has to be after $T$. Its lifetime is the IdP's choice and doesn't extend how long an approval is usable: an approval is usable until `iat + approval_validity`, whatever the IdP issues.

## Requests and Approvals

Signing *is* approving. A **request** is a command — what to run, where, with which parameters, and a unique `id` — and each **approval** is one person's independent signature over it, made with their own fresh login and one-time key. Approvals can be added in any order, on any machine; nobody signs "for" anyone else.

How many approvals a command needs, from whom, and who may run it is **policy's** decision, not the requester's: nothing in a request says what it needs. Policy publishes that as a *requirement document* per command, which the agent serves in its catalog so anyone looking at a command can see what it takes.

### Bundle shape

```
RequestBundle
├── command                      // the JSON being approved: command, id, target_machines, params, not_before/not_after
└── approvals: [Approval]        // 0 while it's still a bare request; at most 16
      signature                  // over canonical({"command": …, "remonce": "request/v2"})
      id_token, public_key, timestamp_token
```

Every approval signs the same bytes: the command wrapped with a domain tag, as compact JSON with sorted keys. The **request id** is the hex SHA-256 of those bytes. It names the request for replay protection and revocation, and it is the same however many approvals the bundle carries. A bundle is plain JSON, so it travels as a file (`.request.json` with no approvals, `.approval.json` with some) over whatever channel reaches the next person.

### The executor

Whoever submits a complete bundle to an agent is the **executor**. Submitting needs an ordinary login to the *viewer* client, whose token goes with the request as a bearer credential. The executor is never anonymous: they are recorded in the audit log and the run log, and passed to policy as `input.executor`, where the requirement document's `executors` rule (and any other policy) restricts them like any other identity. An executor doesn't need to be an approver and doesn't sign anything; their viewer token can't sign or approve, and approvals' tokens (signing client) are rejected as executor credentials.

### Verification (agent)

In this order; each step's failure is audited and stops the request.

1.  **Executor**: a viewer-client bearer token, strictly audience-checked. Missing or invalid → 401.
2.  **Parse** the bundle (a pre-v2 approver/operator bundle gets a clear "made by an older version" error), find the command in this agent's config, and require a UUID `id`.
3.  **Approvals** (`verify_request`): 1–16 of them. For each, in bundle order:
    -   canonical lowercase signature hex, **low-S** (the `s → n−s` twin of a valid ECDSA signature is rejected), and a valid signature over the canonical request payload;
    -   the TSA token covers `(signature || id_token)`;
    -   the OIDC JWT: signature, issuer, **strict audience** (`aud` is exactly the signing client — a string or one-element array — and `azp`, if present, matches), `nonce == SHA256(public_key_pem)`, `exp > T`, a non-empty `sub`, and the `iat` / `auth_time` rules above;
    -   fresh within the command's `approval_validity`.

    Then **no two approvals may share a `sub`**: two approvals are always two people. Errors name the approval's index.
4.  **Command checks**: this host is in `target_machines`, `not_before` / `not_after` hold, and parameters validate against the config.
5.  **Revocation**: the request id against the local revocation set, then the central service if one is configured (fail-closed).
6.  **Policy**: OPA gets `action = "execute"`, the command, the request id, every approver (`username`, `claims`, `signed_at`), the executor and the host.
7.  **Replay**: the request id is recorded, and a second submission is refused. This is last, so a request refused for another reason isn't used up.

### Requirement documents

Policy data at `data.remonce.requirements[<command>]` (shipped in [policy/requirements.json](policy/requirements.json)):

```json
{
  "description": "Two people must agree before this runs",
  "approvals": [
    { "description": "a DBA",       "any_of": [ { "op": "contains", "claim": "groups", "value": "dba" } ] },
    { "description": "security",    "any_of": [ { "op": "contains", "claim": "groups", "value": "security" } ] }
  ],
  "executors": { "description": "on-call SRE", "any_of": [ { "op": "contains", "claim": "groups", "value": "sre-oncall" } ] },
  "additional_policy": "Not during the Friday change freeze"
}
```

-   Each entry in `approvals` is a **slot** that needs its own approver: the request is satisfied when every slot can be given a *different* approver whose claims it accepts. This is checked with Hall's condition over subsets of slots (at most 8), not greedily, so a valid assignment is always found if one exists. With no slots, one approval from anyone is enough (an agent never runs a request without at least one).
-   `executors` says who may submit it.
-   `any_of: []` means anyone; a missing `any_of` means no one.
-   `additional_policy` is a description, shown to people, of rules the policy adds beyond the document.

The shared Rego helper [policy/lib.rego](policy/lib.rego) evaluates a document (`lib.satisfied(requirement, input)`), so what the catalog shows and what policy enforces come from the same data. [policy/authz.rego](policy/authz.rego) denies a command with no published document; a test in `policy_test/` checks that meeting a document is enough to be allowed unless the document declares `additional_policy`, so the two can't silently drift apart.

The predicate language is deliberately small; put anything more expressive in Rego and describe it in `additional_policy`:

| Op | Shape | Matches when |
|----|-------|-------------|
| `equals`    | `{ "op": "equals", "claim": "team", "value": "webapp" }` | Claim equals `value` |
| `contains`  | `{ "op": "contains", "claim": "groups", "value": "noc-l2" }` | Claim array contains `value` |

Predicates are evaluated at **execution time** against the approvers' and executor's verified claims, so a group change takes effect for requests not yet run.

### The catalog

`GET /api/commands` on the agent (viewer bearer; policy's `view_docs` decides who may see it) lists what can be requested there: each command's name, description, parameters, `approval_validity`, and its requirement document fetched from OPA, plus the agent's hostname. It never includes how a command runs (executable, arguments, working directory, environment, policy rule). The signer's UI reads the catalog of whichever agent is selected.

### Replay protection

The agent keeps an in-memory cache keyed on the **request id**. The hash of the signed request can't be re-encoded or re-signed into a different key: a request carries a unique `id`, and any change to the command is a different request that needs new approvals. The first submission runs; later ones are refused, whoever approved or submits them. An entry lasts until every approval that could have run the request has expired (`now + skew + approval_validity`, or later if an approval in the bundle lasts longer). It is recorded as the last check before the process spawns, and released if spawning fails.

## Revocation

Revoking cancels a **whole request**, whoever approved it: the revocation list is keyed on the request id, so neither these approvals nor any later ones can run it. The revoker presents the request with at least one genuine approval (so nobody can fill the list with invented requests; the approvals needn't still be fresh) and their own fresh signature, at most 10 minutes old, over a domain-separated payload that is never valid as an approval:

```
"REMONCE-REVOKE/v2:" || request_id || revoker_public_key_pem
```

Any of the request's approvers may revoke it. Anyone else needs policy's permission (`action = "revoke"`, with the approvers and `input.revoker`). A revocation is kept until no approval of the request could still be valid, or for the central service's retention period if that's longer. Agents consult a central revocation service fail-closed (`GET /v2/revoked/{request_id}`), and pin every revocation locally too. See [CONFIGURATION.md](CONFIGURATION.md#revoking-a-request-remonce-revoke).

## Policy Engine (Rego)

Authentication proves *who* you are. Authorization proves *what* you can do.

Every execution, revocation by a non-approver, and read of files, logs and the catalog is decided by [Rego](https://www.openpolicyagent.org/docs/latest/policy-language/) policy. By default the agent evaluates it in-process with [Regorus](https://github.com/microsoft/regorus), so a single binary is the whole deployment; with `opa_url` set, it asks an **Open Policy Agent (OPA)** server instead, for the full builtin library and OPA's bundle and logging tooling. Both backends get the same input and are asked the same paths, and a test checks they agree. Policy only ever sees verified identities (claims), never raw tokens. For an execution, it sees the command, request id, every verified approver, the executor and the host. The shipped policy allows a run when the command's requirement document is satisfied and no extra rule denies it; add rules in `extra_denials` (and describe them in the document's `additional_policy`).

Deny-by-default is the posture. Example rules in [policy/authz.rego](policy/authz.rego); tests in `policy_test/`.

## Future Considerations

### Zero Knowledge Proofs (ZK-JWT) — proposal, not implemented
A request exposes each approver's full ID token to whoever holds the bundle. The token is useless for signing new commands (it is nonce-bound to a one-time key), and its audience is the *signing* client, which the agent's viewer endpoints and executor check reject. It still discloses every claim the IdP put in it, and it remains a valid bearer token for any *other* service that accepts that audience without checking the binding.

A zero-knowledge proof could keep the raw JWT (and its signature) with the approver, disclosing only the claims policy needs:

*   **Mechanism**: the approver proves, with the JWT and ephemeral public key as private inputs, that the token verifies against the IdP key (public input) and binds that public key.
*   **Public outputs**: the claims policy needs (`sub`, `iss`, `aud`, `iat`, `auth_time`, groups/roles), the bound public key, and the `kid` that verified the token.
*   **Agent flow**: verify the request signature against the public key, verify the proof, check the `kid` against the IdP's JWKS.
*   **Where proving runs**: in the approver's browser, so the signing token never has to leave it. [Noir](https://noir-lang.org/) compiled to a circuit and proved with Barretenberg's WebAssembly prover is the candidate: its proofs are small and it can prove a JWT check in seconds in a browser. A general-purpose zkVM ([SP1](https://github.com/succinctlabs/sp1)) was set aside: its STARK proofs aren't zero-knowledge (they would leak the private inputs), and wrapping them in Groth16 or PLONK needs far more memory, and a multi-gigabyte proving-key download, than a workstation should.

#### Why keep ephemeral keys?
Each login signs exactly one thing, so the request hash could go straight into the nonce. The key stays because:

-   the revocation payload includes the signer's public key, and the TSA timestamp covers a proof-of-possession signature;
-   the wire format and verifier are the same for approving and revoking;
-   a ZK proof would bind the public key rather than a particular payload.
