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
*   **Multi-party Approval**: A request collects independent approvals from different people; policy publishes, per command, how many are needed, from whom, and who may run it, and the UI shows it next to each command.
*   **Cloud Agnostic**: Works on AWS, Azure, GCP, or On-Prem.

---

## How It Works

A user picks a command from the agent's catalog, which also shows what the command needs. They prepare a **request** and **approve** it: a fresh login to their Identity Provider (e.g., Vault, Okta, Azure AD) binds a one-time key, which signs the request, and an RFC 3161 timestamp proves when.

If the command needs more approvals, the request goes to the next approver as a file — chat, ticket, SCP, remote desktop — and each adds their own. Once it has enough, anyone policy allows can submit it from any machine; they are identified by their login and recorded as the executor. A command that needs one approval is simply approve, then execute.

The Agent cryptographically verifies every approval's signature, timestamp and nonce-bound identity, requires them to be from different people, then consults **Open Policy Agent (OPA)**, which checks the approvals and the executor against the command's published requirements. Authorized commands run immediately with stdout and stderr streamed back in real-time; an in-memory replay cache makes each request run once.

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
*   [**Use Cases**](USECASES.md): Concrete scenarios — solo VM ops, CI workflows, NOC handoff, cross-team authorization, two-person rules.
*   [**Architecture Deep Dive**](ARCHITECTURE.md): The cryptographic protocols and design decisions.
*   [**Security Model**](SECURITY.md): How we secure the chain of trust.
*   [**Production Readiness**](PRODUCTION_READINESS.md): Roadmap to going live.
*   [**Alternatives**](alternatives.md): Why not JEA, SSH, or SSM?
*   **IdP Configuration Guides**:
    *   [HashiCorp Vault](docs/idp/VAULT.md): Configure Vault as your OIDC provider.

---

## Deployment Model

Remonce is split into two processes that usually live on different machines:

- **`remonce web`** — the **signer**, runs on each user's workstation. Always binds to loopback (`127.0.0.1` / `::1`); no TLS needed. The browser never talks to the agent directly: the signer proxies the catalog, execution, file reads, and log streams to the agent over TLS (`agent_url`, with `agent_ca_path` for self-signed/private-CA agent certs).
- **`remonce agent`** — runs on the remote target server: serves its command catalog and runs approved requests. TLS is mandatory (file-based cert or ACME); there is no plaintext mode.

There is also a headless CLI: **`remonce approve`** adds your approval to a request file, **`remonce submit`** runs an approved request as you, and **`remonce revoke`** cancels one (see [CONFIGURATION.md](CONFIGURATION.md)).

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