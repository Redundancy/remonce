# Architecture & Design

This document details the core architectural decisions, security mechanisms, and design philosophy behind Remonse.

## Core Problem Statement

Many organizations struggle with executing privileged actions on remote systems securely. Common patterns involve:
- **Persistent Credentials**: Leaving SSH keys or high-privilege IAM roles on machines.
- **VPNs/Bastions**: Complex network requirements that don't scale well across diverse clouds.
- **Lack of Non-Repudiation**: Hard to prove *who* executed a command and *when* it was approved.

Remonse aims to solve this by enabling **Signed Commands** that are verified cryptographically, time-bounded, and policy-driven.

## Signed Commands

A fundamental building block of this system is to enable users to sign a command (a JSON payload) such that we can verify that the individual approved it and did so during the period in which it was valid.

### Mechanisms Considered
1.  **Public Key Cryptography**: Users have a private key. (Problem: Management of persistent keys).
2.  **Trusted Signing Service**: Central service (e.g., Vault Transit) signs payloads. (Problem: Centralized dependency).
3.  **JWT-Based Ephemeral Signing (Chosen Approach)**: Leverage OIDC Identity to anchor ephemeral keys.

### The Chosen Approach: OIDC + Ephemeral Keys

Similar to concepts like [zkLogin](https://docs.sui.io/concepts/cryptography/zklogin), we leverage the **nonce** of an OIDC ID Token to bind a public key to an identity.

1.  **Ephemeral Key Generation**: The client generates a random key pair for the session.
2.  **Identity Binding**: The client authenticates with the IdP (Vault/OIDC), putting the hash of the Public Key into the JWT `nonce`.
3.  **Command Signing**: The client signs the command payload with the private key.
4.  **Verification Chain**:
    -   The **Signature** validates the command was signed by the Private Key.
    -   The **JWT** (signed by IdP) validates that the Public Key (in `nonce`) belongs to the User (in `sub`).
    -   The **IdP** (via JWKS) is trusted by the Agent.

### Time-Bounding & Non-Repudiation

JWTs are short-lived, but we may want to execute commands slightly later. However, we must prove the command was signed *while the user was present*.

-   **Solution**: **Timestamping Authority (TSA)**.
-   We send the signature to an RFC 3161 TSA.
-   The TSA returns a signed timestamp proving the signature existed at time $T$.
-   **Validation**: The Agent checks that $T$ is within the validity period of the User's ID Token.

## Policy Engine (OPA)

Authentication proves *who* you are. Authorization proves *what* you can do.

Remonse integrates **Open Policy Agent (OPA)** to evaluate every request.
-   **Input**: Command, User Claims (Groups), Context.
-   **Policy**: Rego rules define access (e.g., "Only `webapp-users` can run `test`").
-   **Result**: Allow/Deny decisions are decoupled from the code.

## Future Considerations

### Multi-step Workflows
Complex workflows where Entity A initiates an action that Entity B must execute (involving C and D) can be modeled as a chain of signed approvals.
Borrowing from Certificate Signing Requests (CSRs), we can chain permissions anchored to the root of trust (JWKS).

### Zero Knowledge Proofs
We explored using zkSNARKs (e.g., [Spartan](https://github.com/Microsoft/Spartan)) for privacy-preserving signatures. While powerful, standard OIDC provides sufficient security for the current enterprise context without the computational overhead of ZKP.
