# Remonse - *Remote Monitoring and Secure Execution*

> **Secure, Identity-Aware, JIT Command Execution.**

Remonse provides a secure, cloud-agnostic way to execute privileged commands on remote fleets without managing persistent SSH keys or complex VPNs. It leverages **OIDC Identities** and **Ephemeral Cryptography** to ensure every action is authenticated, authorized, and non-repudiable.

Making it easy to execute a controlled menu of actions on a remote machine, or eventually directly read a log file, makes it very easy and accessible to teams to do things like check the results of **cloud-init**, or request **NOC runbooks** without giving out SSH access.

![License](https://img.shields.io/badge/license-MIT-blue.svg) ![Rust](https://img.shields.io/badge/built_with-Rust-orange.svg)

---

## Why Remonse?

Managing remote access is hard. VPNs are brittle, SSH keys get lost or stolen, and audit logs are often scattered.
Remonse flips the model: **Don't trust the network, trust the identity.**

*   **Zero Persistent Credentials**: No SSH keys or long-lived secrets on your servers.
*   **Identity First**: Users authenticate with their corporate identity (OIDC).
*   **Policy Driven**: Fine-grained access control via **Open Policy Agent (OPA)**.
*   **Audit Ready**: Every command is cryptographically signed and timestamped.
*   **Low Touch**: Lightweight deployment with minimal configuration.
*   **Flexible Centralization**: Teams decide their own trade-offs—run fully decentralized or enforce global policies centrally.
*   **Secure Defaults**: Architecture enforces a **deny-by-default** posture, ensuring **least-privileged access**.
*   **Delegated Permissions**: Architecture supports multi-approver workflows where approvers authorize actions without needing direct access to the target.
*   **Cloud Agnostic**: Works on AWS, Azure, GCP, or On-Prem.

---

## How It Works

The process begins when a user authenticates via their corporate Identity Provider (e.g., Vault, Okta, Azure AD). The local client then generates a **Signed Command** bundled with a short-lived Proof-of-Identity (JWT). This payload is sent to the target machine (Agent), which cryptographically verifies both the signature and the identity.

Once verified, the Agent consults the **Open Policy Agent (OPA)** to determine if *this specific user* is authorized to execute *this specific command* based on fine-grained logic. If authorized, the command runs immediately, with stdout and stderr streamed securely back to the user in real-time.

---

## Capabilities

Remonse is designed for the rigorous demands of modern operations. It ensures **Cryptographic Non-Repudiation** by leveraging RFC 3161 Timestamping Authorities, making every action legally auditable. Access control is highly flexible and **Attribute-Based**, allowing policies to be defined on any user claim, membership (e.g., `webapp-users`), or context.

From a usability standpoint, the system offers a **Secure UI** with a modern dark mode for ease of use, while the underlying **Real-time Monitoring** ensures operators have immediate visibility into execution results. Built in **Rust**, the agent is a lightweight, cross-platform binary that brings performance and safety to both Linux and Windows environments.

---

## Configuration

The system is configured via `config.toml`. Key options include:

-   `[oidc]`: Identity Provider settings.
-   `[timestamp_authority]`: TSA URL and CA.
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
*   [**Architecture Deep Dive**](ARCHITECTURE.md): The cryptographic protocols and design decisions.
*   [**Security Model**](SECURITY.md): How we secure the chain of trust.
*   [**Production Readiness**](PRODUCTION_READINESS.md): Roadmap to going live.
*   [**Alternatives**](alternatives.md): Why not JEA, SSH, or SSM?

---

## Quick Start (Local)

1.  **Prerequisites**: Rust, Vault, OPA, Terraform (see [Dev Guide](DEVELOPMENT.md)).
2.  **Start Services**:
    ```powershell
    ./start_services.bat
    ```
3.  **Run Web Interface**:
    ```powershell
    cargo run -- web
    ```
4.  **Run Agent**:
    ```powershell
    cargo run -- agent
    ```
5.  **Open**: [http://localhost:8080](http://localhost:8080)

---

## License

This project is licensed under the MIT License.