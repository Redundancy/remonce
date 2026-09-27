# Getting started

This walks through setting up remonce on one machine, from nothing to:

1. a command of your own, offered by an agent;
2. a rule saying who may approve it and who may run it;
3. a command that needs two people;
4. a rule of your own, written in Rego;
5. people reading a log file.

Everything runs locally: a development Vault stands in for your identity provider, and the agent and the signer run side by side. The same configuration carries over to real hosts; [Next steps](#next-steps) covers what changes.

> [!WARNING]
> remonce is a proof-of-concept demonstrator. It hasn't been hardened, refactored through close code review, or security audited. Use it at your own risk.

## How the pieces fit

Each host's owner controls three things, all in files on that host:

| File | Says | Changes apply |
|---|---|---|
| `config.toml` | **What this machine offers**: the commands it can run (and exactly how), their parameters, the files it will show, and its TLS. | On agent restart |
| `policy/requirements.json` | **Who must approve each command, and who may run it**, as plain data. Most setups only ever edit this. | On the next request |
| `policy/*.rego` | **The decisions themselves**, in [Rego](https://www.openpolicyagent.org/docs/latest/policy-language/). The shipped `authz.rego` turns requirement documents into decisions; add your own rules here when data isn't enough. | On the next request |

When someone submits an approved request, the agent:

1. checks every approval's signature, login and timestamp, and that the approvers are different people;
2. checks the request is for this machine and its parameters are valid (from `config.toml`);
3. asks the policy for a decision: it evaluates the command's `opa_rule` — `data.remonce.authz.decision` for all the shipped commands — with the request, the approvers' verified claims and the executor's as `input`;
4. runs the command if the decision is `{"allow": true}`, and otherwise returns the decision's `reason`.

The shipped decision is: *allow if the command's requirement document is satisfied, unless an extra rule denies it*. A command with no requirement document is denied. So a new command does nothing until you say who may use it — which is the point.

Policy is evaluated inside the agent (the embedded [Regorus](https://github.com/microsoft/regorus) engine); nothing else needs to run. If you'd rather use an [OPA](https://www.openpolicyagent.org/) server, point `opa_url` at it: the same files work unchanged. See [CONFIGURATION.md](CONFIGURATION.md#authorization-policy).

## 1. Prerequisites

This works on Linux, macOS and Windows. Where a step differs, both versions are shown.

- **Rust** ([install](https://www.rust-lang.org/tools/install)), to build remonce. Or skip it and use a release build from the project's GitHub Releases page: unpack it and run `remonce` from the unpacked folder wherever this guide says `cargo run --`.
- **HashiCorp Vault** and **Terraform**, for the local identity provider only (a real deployment uses your own identity provider). Install them however suits you — they only need to be on your `PATH`, or placed in the project's `bin/` folder:
  - macOS: `brew tap hashicorp/tap && brew install hashicorp/tap/vault hashicorp/tap/terraform`
  - Linux: HashiCorp's [package repositories](https://developer.hashicorp.com/vault/install) for apt, dnf and others, or the zip downloads
  - Windows: the zip downloads for [Vault](https://developer.hashicorp.com/vault/install) and [Terraform](https://developer.hashicorp.com/terraform/install); unzip `vault.exe` and `terraform.exe` into `bin\`
- **OpenSSL**, to make a certificate for the agent. Linux and macOS have it; on Windows, Git for Windows includes it (run it from Git Bash).

Check them with `vault version` and `terraform version`. Then build once:

```sh
cargo build
```

## 2. Start the identity provider

From the project folder:

```sh
./start_services.sh          # Linux and macOS
```

```powershell
.\start_services.bat         # Windows
```

This starts Vault in development mode and configures it with Terraform (`vault_setup.tf`):

- two OIDC clients: the *viewer* client (`remonce-viewer` in Vault, `viewer_client_id` in `config.toml`) for ordinary logins, and the *signing* client (`remonce-signing`, `signing_client_id`) used for a fresh login on every approval;
- two users, `webapp` and `webapp2`, both in the group `webapp-users`. Their password is the `APP_USER_PASSWORD` default in the start scripts; set that environment variable first to choose your own.

It writes the client IDs into `config.toml`. Leave Vault running: on Linux and macOS in that terminal (Ctrl+C stops it), on Windows in the window it opens. Development mode keeps nothing on disk, so each restart starts fresh and rewrites the IDs.

> Your users' **claims** — here `groups: ["webapp-users"]` — are what policy decides on. With a real identity provider they're whatever it puts in the ID token: groups, roles, email, department.

## 3. Give the agent a certificate

The agent only speaks HTTPS. For a machine without a public name, make a self-signed certificate (on Windows, in Git Bash):

```sh
mkdir -p certs
openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
  -keyout certs/agent-key.pem -out certs/agent-fullchain.pem \
  -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
  -addext "basicConstraints=critical,CA:FALSE"
```

Then in `config.toml`:

- At the top, above `[oidc]`, tell the signer to trust it:

  ```toml
  agent_url = "https://localhost:10022"
  agent_ca_path = "certs/agent-fullchain.pem"
  ```

- At the bottom, turn on the agent:

  ```toml
  [agent]
  listen_address = "127.0.0.1:10022"

  [agent.tls]
  mode = "files"
  chain = "certs/agent-fullchain.pem"
  key = "certs/agent-key.pem"
  ```

(For hosts with a public name, the agent can get its own certificate over ACME instead; see [CONFIGURATION.md](CONFIGURATION.md#mode-acme-production).)

## 4. Start the agent and the signer

In two terminals, from the project folder:

```sh
cargo run -- agent
```

```sh
cargo run -- web
```

The agent logs `Policy ready backend=embedded, from policy`. Open [http://localhost:8080](http://localhost:8080) and log in as `webapp`. The **Commands** page lists what the agent offers, each with what it needs; the Agent bar reads **This machine**, because the signer calls the agent itself and `localhost` is its own machine.

## 5. Offer a command of your own

Add to `config.toml`, alongside the other `[[commands]]`:

```toml
[[commands]]
name = "show-host"
description = "Print this machine's name."
opa_rule = "data.remonce.authz.decision"
executable = "hostname"
```

`name` is all a request ever mentions; `executable` and `args` stay on the host, so nobody can make it run anything else. (Commands start with an empty environment; on Linux or macOS, if `hostname` isn't found, add `env = { PATH = "/usr/bin:/bin" }`.)

Restart the agent (`config.toml` is read at startup) and reload the Commands page. `show-host` appears with **No published requirements**, and approving and running it would be refused with `No published requirements for 'show-host'`. The machine offers it, but nobody has said who may use it.

**Parameters** work the same way: declared in `config.toml`, validated before anything runs, substituted into `args`. The sample `ping-test` shows one (it's written for Windows `ping`; on Linux and macOS use `-c` instead of `-n`):

```toml
args = ["-n", "{{count}}", "127.0.0.1"]

[[commands.params]]
name = "count"
default = "10"
min = 1
max = 100
```

## 6. Say who may approve it, and who may run it

Open `policy/requirements.json` and add an entry for `show-host` under `requirements`:

```json
"show-host": {
  "description": "Anyone on the team can check which machine this is",
  "approvals": [
    { "description": "a Remonce user",
      "any_of": [ { "op": "contains", "claim": "groups", "value": "webapp-users" } ] }
  ],
  "executors": { "description": "a Remonce user",
    "any_of": [ { "op": "contains", "claim": "groups", "value": "webapp-users" } ] }
}
```

- **`approvals`** is a list of slots. Each slot needs its own approver — a different person per slot — whose claims match one of its `any_of` predicates.
- **`executors`** says who may submit the approved request.
- **Predicates** are `{"op": "contains", "claim", "value"}` (the claim is a list containing the value) or `{"op": "equals", "claim", "value"}`. `"any_of": []` means anyone.
- **`description`** is what people see instead of the raw predicates.

Save, and reload the Commands page — no restart. `show-host` now reads *Needs a Remonce user · run by a Remonce user*.

## 7. Approve it and run it

1. On **Commands**, click `show-host`, then **Prepare**. The dialog shows the exact payload your approval signs.
2. Click **Approve**. You're sent to log in again: every signature gets its own login and a one-time key. Log in as `webapp`.
3. Back on the signer, click **Execute now**. The **Runs** page streams the output, with who approved it and who ran it.

The same request can't run twice, and the approval expires after an hour (`approval_validity` in `config.toml` changes that).

## 8. Require two people

Change `show-host`'s `approvals` to two slots:

```json
"approvals": [
  { "description": "a Remonce user",
    "any_of": [ { "op": "contains", "claim": "groups", "value": "webapp-users" } ] },
  { "description": "another Remonce user",
    "any_of": [ { "op": "contains", "claim": "groups", "value": "webapp-users" } ] }
]
```

Now:

1. Prepare and approve `show-host` as `webapp`. The result says **1 of 2 needed** and names what's missing.
2. Click **Save file**. In real use you'd send this file to the second approver, by any route a file can take.
3. Open **Sign a request**, drop the file in, and click **Approve** — logging in as `webapp2` this time. (Try `webapp` again: it's refused, because two approvals must be two people.)
4. Click **Execute now**.

Slots can ask for different things — `"a DBA"` plus `"someone from security"` — and policy finds a fair assignment whatever order the approvals arrive in.

## 9. Write a rule of your own

Requirement documents cover *who*. For anything else — parameter values, hosts, times, combinations of claims — write Rego. Add this to `policy/authz.rego`:

```rego
# More than 20 pings needs an approval from someone in the "sre" group.
extra_denials contains "More than 20 pings needs an approval from the SRE team" if {
	input.action == "execute"
	input.command.command == "ping-test"
	to_number(input.command.params.count) > 20
	not sre_approved
}

sre_approved if {
	some approver in input.approvers
	"sre" in object.get(approver.claims, "groups", [])
}
```

Each `extra_denials` entry is a message: when a rule adds one, the request is denied and that message is the reason people see. Save, then try `ping-test` with `count` set to 30: it's refused with *More than 20 pings needs an approval from the SRE team*. With 20 or fewer it runs as before.

What a rule can use (`input` for an execution):

| Field | Holds |
|---|---|
| `input.command` | The signed request: `command`, `id`, `target_machines`, `params`, `not_before`/`not_after` |
| `input.approvers` | One entry per approval: `username`, `claims` (verified ID token claims), `signed_at` |
| `input.executor` | Who's submitting it: `username`, `claims` |
| `input.host` | This agent's hostname |
| `input.request_id` | The request's id |

Two habits worth keeping:

- **Say so in the requirement document.** Add `"additional_policy": "More than 20 pings needs an SRE approval"` to `ping-test`'s document, so the Commands page tells people there's more to it than the slots.
- **Test your rules.** `policy_test/` has the tests for the shipped policy; `cargo test` runs them on the embedded engine (and `opa test policy policy_test` on OPA). Add yours alongside.

When one command needs a decision entirely its own, write a rule that returns `{"allow": …, "reason": …}` in your own package and point the command's `opa_rule` at it.

## 10. Let people read a log

Files are offered the same way as commands: listed in `config.toml`, decided by policy.

```toml
[[files]]
path = "logs/*.log"
name = "execution-logs"
description = "Output of every run on this machine"
```

The shipped policy lets anyone in `webapp-users` read offered files:

```rego
allow if {
	input.action == "read_file"
	"webapp-users" in viewer_groups
}
```

`input.viewer.claims` holds the reader's verified claims, and `input.file` the `name` or `path` asked for, so you can narrow it — say, one team per file. Open **Files** in the signer and click **View**: the log streams live, with a filter and follow/pause.

## Next steps

- **A real identity provider**: register two OIDC clients (signing and viewer) with it; see [CONFIGURATION.md](CONFIGURATION.md#identity-oidc) and, for Vault, [docs/idp/VAULT.md](docs/idp/VAULT.md).
- **Real hosts**: install the agent with its own `config.toml` and `policy/`. Each host decides for itself; nothing central is required. For a certificate without files to manage, use [ACME](CONFIGURATION.md#mode-acme-production).
- **Other people's machines and networks**: approvals are files, so they can be approved on a desktop that can't reach the host, and run from inside ([readme](readme.md#works-where-your-desktop-cant-reach-the-host)).
- **From a terminal**: `remonce approve`, `remonce submit` and `remonce revoke` work with the same files ([CONFIGURATION.md](CONFIGURATION.md#cli-remonce-approve-remonce-submit)).
- **More examples**: [USECASES.md](USECASES.md) — NOC handoff, CI pipelines, cross-team access, two-person rules.
