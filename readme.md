# remonce

***re**mote **mon**itor · **c**ommand **e**xecution*

**Run specific commands on a host, and read its logs, without handing out SSH.** Every run is approved by the right people, checked against policy, and recorded. Approving happens on your own machine, so it works even where your desktop can't reach the host.

![License](https://img.shields.io/badge/license-MIT-blue.svg) ![Rust](https://img.shields.io/badge/built_with-Rust-orange.svg)

> [!TIP]
> **Nothing central to run.** There is no remonce server, database or control plane. Each agent stands alone with its own commands and policy, and each person's signer runs on their own machine. The only shared pieces are ones you already have: your identity provider, and a timestamp authority (a public one by default). **You can run remonce by itself on a single machine** — the agent and your signer side by side, with policy built in — and grow from there. A central revocation service exists if you want one; nothing requires it.

---

## Why remonce?

Checking a VM's cloud-init result, restarting a service at 3am, or tailing an application log shouldn't need a shell on the box, a VPN, or a standing credential. It should be easy and safe.

> [!IMPORTANT]
> **Each machine's owner decides what it exposes, and to whom.** Every agent carries its own menu of commands, its own list of files it will show, and its own policy for who may approve and who may run what. Nothing outside the machine can add a command, widen access or push a rule to it. The only outside trust is your identity provider (for *who* someone is) and a timestamp authority (for *when* they signed). Central pieces — a shared OPA server with policy bundles, an estate-wide revocation service — are there for teams that want them, and only if they want them.

- **Specific commands, not a shell.** Each host offers a menu of named commands with validated parameters. Nobody can run anything that isn't on it, and nothing runs through a shell.
- **Look without touching.** Stream allowed log files, and watch command output live, read-only.
- **Little to configure, little to install.** One binary with modes: the agent on each host, the signer on your workstation. One `config.toml`. Policy is [Rego](https://www.openpolicyagent.org/docs/latest/policy-language/), evaluated inside the agent, so there is no policy server to run either. Beyond that it uses the OIDC identity provider you already have (Vault, Okta, Keycloak and the like; see the [IdP requirements](CONFIGURATION.md#idp-requirements)) and a public timestamp authority by default.
- **Real policy, and more than one person when it matters.** Simple rules are a few lines of data per command: "any engineer", or "a DBA *and* someone from security, run by the on-call SRE", shown next to each command so nobody has to guess. When you need more, it's ordinary Rego, and power users can point remonce at a full [OPA](https://www.openpolicyagent.org/) server for its complete builtin library, bundles and decision logs.
- **Sign locally, run remotely.** An approval is a signature made on your machine with a one-time key and a fresh login. Requests are plain files, so they go wherever a file can: [into networks your desktop can't reach](#works-where-your-desktop-cant-reach-the-host), across remote desktops, into tickets and chat.

## How it works

```
  your workstation                                     target host
 ┌──────────────────────────┐                   ┌──────────────────────────┐
 │  remonce web  (signer)   │      HTTPS        │  remonce agent           │
 │  browser UI · approvals  │ ────────────────▶ │  catalog · run · stream  │
 └────────────┬─────────────┘                   └────────────┬─────────────┘
              │ fresh login per signature                    │ every decision
      your OIDC identity provider              Rego policy (built in, or OPA)
```

1. **Pick** a command from the host's catalog. It shows what the command needs: how many approvals, from whom, and who may run it.
2. **Approve.** Each approval is its own login and one-time key, timestamped. If more people need to agree, send them the request file; each adds their own approval.
3. **Execute.** Anyone policy allows submits the approved request, identified by their login. The agent verifies every signature, checks policy, runs the command once, and streams the output back. The audit log records every approver and who ran it.

Anyone who approved can revoke a request before it runs, on one agent or across all of them through an optional central revocation service.

## Works where your desktop can't reach the host

Plenty of hosts live in networks your desktop has no route into; you get there over remote desktop, a jump host, or a file drop. remonce fits that without opening anything up:

1. **Get the request** — prepare it from inside, where the host's catalog is reachable, or take a request file someone sent you.
2. **Approve it on your desktop.** That needs your identity provider and the timestamp authority, not the host. Save the approved request as a file.
3. **Carry it in** over RDP, SCP or a ticket attachment, and **run it from inside** with the UI or `remonce submit`, logged in as yourself.

The approved file can't be altered on the way (any change breaks the signatures), it expires, and it runs once. Your desktop never connects to the agent, and the agent never connects to your desktop.

## A command, start to finish

On the host, `config.toml` says what the command runs — callers never see this part:

```toml
[[commands]]
name = "restart-service"
opa_rule = "data.remonce.authz.decision"
executable = "systemctl"
args = ["restart", "{{service}}"]

[[commands.params]]
name = "service"
allowed = ["nginx", "postgres"]
```

In policy, a requirement document says what it takes, and the UI shows it to anyone looking at the command:

```json
"restart-service": {
  "approvals": [ { "description": "an SRE", "any_of": [ { "op": "contains", "claim": "groups", "value": "sre" } ] } ],
  "executors":   { "description": "an SRE", "any_of": [ { "op": "contains", "claim": "groups", "value": "sre" } ] }
}
```

That's the whole setup for one command. See [USECASES.md](USECASES.md) for delegation to a NOC, CI pipelines, cross-team access and two-person rules.

## Security at a glance

- No SSH keys or long-lived secrets on hosts; the agent only accepts signed, approved requests over TLS. It can get and renew its own certificate over ACME (Let's Encrypt or any ACME CA), so there are no certificate files to manage. The CA checks it on port 443, or on port 80, which the agent opens only for the few minutes a certificate is being issued.
- Every signature needs its own re-authenticating login and a one-time key bound to the identity token (the [OpenPubkey](https://github.com/openpubkey/openpubkey) technique), plus an RFC 3161 timestamp.
- Approvals expire (one hour by default), each request runs once, and two approvals must be two different people.
- Deny by default: with the shipped policy, a command with no published requirements doesn't run.

The details are in [SECURITY.md](SECURITY.md) and [ARCHITECTURE.md](ARCHITECTURE.md).

## Quick start (local)

1.  **Prerequisites**: Rust, Vault, Terraform (see the [Dev Guide](DEVELOPMENT.md)).
2.  **Generate a self-signed cert for the agent** (first time only):
    ```powershell
    mkdir certs
    openssl req -x509 -newkey rsa:2048 -nodes -days 365 `
      -keyout certs/agent-key.pem -out certs/agent-fullchain.pem `
      -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" `
      -addext "basicConstraints=critical,CA:FALSE"
    ```
    Then uncomment the `[agent]` / `[agent.tls]` block in [config.toml](config.toml).
3.  **Start Vault**, and configure its dev users and OIDC clients:
    ```powershell
    ./start_services.bat
    ```
4.  **Run the signer** (your workstation) and **the agent** (the target host; here, the same machine):
    ```powershell
    cargo run -- web
    cargo run -- agent
    ```
5.  **Open** [http://localhost:8080](http://localhost:8080) and log in as `webapp`. A second user, `webapp2`, lets you try `ping-pair`, which needs two approvals.

Prefer a terminal? `remonce approve`, `remonce submit` and `remonce revoke` do the same with request files.

## Documentation

*   [**Dev Guide**](DEVELOPMENT.md): run everything locally.
*   [**Configuration**](CONFIGURATION.md): every setting, requirement documents, the CLI, revocation.
*   [**Use Cases**](USECASES.md): solo VM checks, CI pipelines, NOC handoff, cross-team access, two-person rules.
*   [**Architecture**](ARCHITECTURE.md): the signing protocol and design decisions.
*   [**Security Model**](SECURITY.md): the verification chain and threat model.
*   [**Production Readiness**](PRODUCTION_READINESS.md): what's done and what's next.
*   [**Alternatives**](alternatives.md): why not JEA, SSH, or SSM?
*   **Identity providers**: [HashiCorp Vault](docs/idp/VAULT.md).

## License

MIT.
