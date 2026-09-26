# Remonce - *Remote Monitoring and Secure Execution*

> **Secure, Identity-Aware, JIT Command Execution.**

Remonce provides a secure, cloud-agnostic way to execute privileged commands on remote fleets without managing persistent SSH keys or complex VPNs. It leverages **OIDC Identities** and **Ephemeral Cryptography** to ensure every action is authenticated, authorized, and non-repudiable.

Making it easy to execute a controlled menu of actions on a remote machine, or eventually directly read a log file, makes it very easy and accessible to teams to do things like check the results of **cloud-init**, or request **NOC runbooks** without giving out SSH access.

![License](https://img.shields.io/badge/license-MIT-blue.svg) ![Rust](https://img.shields.io/badge/built_with-Rust-orange.svg)

---

## Why Remonce?

Remonce is built to be an easily configured, lightweight system that lowers the operational burden on teams while meeting their diverse needs using standard, well-documented tools. It aims to support every option that enhances security and flexibility, starting with sensible, secure defaults to encourage adoption across varied environments. We believe that if security is hard, users will drift towards insecurity, so we prioritize a friction-free path to being secure.

*   **Zero Persistent Credentials**: No SSH keys or long-lived secrets on your servers.
*   **Identity First**: Users authenticate with their corporate identity (OIDC).
*   **Policy Driven**: Fine-grained access control via **Open Policy Agent (OPA)**.
*   **Audit Ready**: Every command is cryptographically signed and timestamped.
*   **Low Touch**: Lightweight deployment with minimal configuration.
*   **Flexible Centralization**: Teams decide their own trade-offs—run fully decentralized or enforce global policies centrally.
*   **Secure Defaults**: Architecture enforces a **deny-by-default** posture, ensuring **least-privileged access**.
*   **Delegated Permissions**: Two-signature protocol where a senior approver authorizes commands with a long validity (days) and an on-call operator adds a fresh co-signature (minutes) at execution time. The approver can restrict *who* may execute via OIDC claim predicates.
*   **Cloud Agnostic**: Works on AWS, Azure, GCP, or On-Prem.

---

## How It Works

The process begins when a user authenticates via their corporate Identity Provider (e.g., Vault, Okta, Azure AD). The local client generates a **Signed Command** bundled with a short-lived Proof-of-Identity (JWT) and an RFC 3161 timestamp.

For synchronous work, the same user submits the bundle directly to the Agent — a "self-execute" path where freshness is enforced at the short (minutes) window. For delegated work (e.g., overnight NOC maintenance), the approver's bundle is handed off to an operator who adds a fresh co-signature under their own identity before submitting; the approver's authorization can remain valid for days while the operator's attestation proves the command was actually sent in the current moment.

The Agent cryptographically verifies signatures, timestamps, nonce-bound identities, and any approver-embedded constraints on *who* may execute, then consults **Open Policy Agent (OPA)** for the final business-logic allow/deny. Authorized commands run immediately with stdout and stderr streamed back in real-time; an in-memory replay cache prevents duplicate executions within the freshness window.

---

## Capabilities

Remonce supports **Cryptographic Non-Repudiation** by leveraging RFC 3161 Timestamping Authorities to create verifiable audit trails. Access control is **Attribute-Based**, allowing policies to be defined on any user claim, membership (e.g., `webapp-users`), or context.

From a usability standpoint, the system offers a **Secure UI** with a modern dark mode for ease of use, while the underlying **Real-time Monitoring** ensures operators have immediate visibility into execution results. **TLS Support** is available for securing communications, offering both file-based and (experimental) ACME automated certificate management. Built in **Rust**, the agent is a lightweight, cross-platform binary that brings performance and safety to both Linux and Windows environments.

---

## Configuration

The system is configured via `config.toml`. A complete reference is available in [CONFIGURATION.md](CONFIGURATION.md).

Key options include:

-   `[oidc]`: Identity Provider settings.
-   `[tls]`: HTTPS configuration (Files or manual ACME).
-   `[timestamp_authority]`: TSA URL and CA.
-   `agent_url` / `agent_ca_path`: the agent the signer UI proxies to, and extra CA roots for its TLS cert.
-   `[[commands]]`: Whitelisted commands.
    -   `max_validity`: Maximum duration a token is valid for (e.g., "1h", "3d"). Defaults to "3d" if not specified.

### Command Constraints
Signed tokens can embed strict constraints enforced by the Agent. These are inputs at generation time:
-   **Target Machines**: Restrict execution to specific hostnames.
-   **Not Before / Not After**: Absolute time windows for execution.

### File Access
Read-only access to files can be configured via `[[files]]` entries.
-   `path`: The absolute path or glob pattern (e.g., `/var/log/*.log`).
-   `name`: Optional alias for easier reference (e.g., `app-logs`).
-   OPA Action: `read_file`.
-   OPA Input: `input.file.name` or `input.file.path`.

---

## Documentation

*   [**Getting Started (Dev Guide)**](DEVELOPMENT.md): Spin up the environment locally.
*   [**Use Cases**](USECASES.md): Concrete scenarios — solo VM ops, CI workflows, NOC delegation, cross-team authorization.
*   [**Architecture Deep Dive**](ARCHITECTURE.md): The cryptographic protocols and design decisions.
*   [**Security Model**](SECURITY.md): How we secure the chain of trust.
*   [**Production Readiness**](PRODUCTION_READINESS.md): Roadmap to going live.
*   [**Alternatives**](alternatives.md): Why not JEA, SSH, or SSM?
*   **IdP Configuration Guides**:
    *   [HashiCorp Vault](docs/idp/VAULT.md): Configure Vault as your OIDC provider.

---

## Deployment Model

Remonce is split into two processes that usually live on different machines:

- **`remonce web`** — the **signer**, runs on the operator's workstation. Always binds to loopback (`127.0.0.1` / `::1`); no TLS needed. The browser never talks to the agent directly: the signer proxies execution, file reads, and log streams to the agent over TLS (`agent_url`, with `agent_ca_path` for self-signed/private-CA agent certs).
- **`remonce agent`** — the **executor**, runs on the remote target server. TLS is mandatory (file-based cert or ACME); there is no plaintext mode.

There is also **`remonce cosign`** — a headless CLI for operators who receive a delegated approval bundle: it runs its own OIDC login, co-signs the bundle, and optionally submits it to the agent (see [CONFIGURATION.md](CONFIGURATION.md)).

## Quick Start (Local)

1.  **Prerequisites**: Rust, Vault, OPA, Terraform (see [Dev Guide](DEVELOPMENT.md)).
2.  **Generate a self-signed cert for the agent** (first time only):
    ```powershell
    mkdir certs
    openssl req -x509 -newkey rsa:2048 -nodes -days 365 `
      -keyout certs/agent-key.pem -out certs/agent-fullchain.pem `
      -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" `
      -addext "basicConstraints=critical,CA:FALSE"
    ```
    Then uncomment the `[agent]` / `[agent.tls]` block in [config.toml](config.toml).
3.  **Start Services**:
    ```powershell
    ./start_services.bat
    ```
4.  **Run Web Interface** (signer, on your workstation):
    ```powershell
    cargo run -- web
    ```
5.  **Run Agent** (executor, on the target host):
    ```powershell
    cargo run -- agent
    ```
6.  **Open**: [http://localhost:8080](http://localhost:8080)

---

## License

This project is licensed under the MIT License.