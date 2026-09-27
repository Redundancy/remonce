# Alternatives

There are established ways to run a controlled action on a remote machine. Each is good at something, and if one already fits your estate you may not need remonce. This page compares them honestly, and says where remonce is different.

What remonce optimizes for, in one line: **a named command, approved by the right people, run on one host whose owner decided what it offers — with nothing central to run and no network path needed from the approver to the host.**

## At a glance

|  | remonce | SSH + ForceCommand | PowerShell JEA | AWS SSM Run Command | Azure Run Command / Automation |
|---|---|---|---|---|---|
| **Platforms** | Linux, Windows (one binary) | Anything with sshd | Windows (WinRM) | AWS, plus on-prem via hybrid activation | Azure, plus Arc-enabled machines |
| **What can run** | Named commands with validated parameters | Whatever the forced command allows | Allow-listed cmdlets, functions and parameters | Any script in an SSM document | Any script |
| **Credentials on the host** | None | Keys or a trusted CA | Domain or local accounts | Instance role / activation | Managed identity / VM agent |
| **Network path needed** | To the agent, from whoever *runs* it; approvers need none | Inbound SSH (or a bastion) | Inbound WinRM | Outbound from host to AWS | Outbound from host to Azure |
| **Central service** | None required | None (a CA or broker if you add one) | None (AD in practice) | AWS | Azure |
| **Who decides what a host offers** | The host's config | The host's sshd config | The host's JEA configuration | The account's IAM and documents | The subscription's RBAC and scripts |
| **Multi-person approval** | Built in, per command, from policy | No | No | Via Change Manager | No (build it in the pipeline) |
| **Policy language** | Rego, embedded or on OPA | sshd options | Role capability files | IAM | Azure RBAC |

## SSH + ForceCommand

The standard answer on Linux: a key (or `sshd_config`) forces a specific program to run instead of a shell, and that program inspects `$SSH_ORIGINAL_COMMAND` to decide what to do.

- **Good at:** ubiquity. sshd is everywhere and well understood.
- **The hard part:** the forced program must parse and vet an arbitrary string safely. Done well, it ends up as a small menu of fixed commands; done badly, it's a shell with extra steps.
- **Credentials:** plain SSH keys are standing credentials on every host. Short-lived access fixes that but adds moving parts, each to secure and run:
  - HashiCorp Vault's SSH secrets engine signs short-lived certificates, which can carry a forced command.
  - HashiCorp Boundary brokers sessions with dynamic credentials.
  - OpenPubkey SSH (`opkssh`) logs in with your OIDC identity.
- **Reachability:** needs an inbound SSH path, or a bastion. Agent forwarding avoids copying keys to jump hosts, but anyone with root on the jump host can use your forwarded agent while you're connected.
- **Approvals:** none; whoever holds a valid credential runs the command.

remonce keeps the good part (a fixed menu, decided on the host) and drops the rest: no string parsing, no keys on hosts, and approvals are part of the request.

## PowerShell JEA (Just Enough Administration)

JEA exposes a constrained PowerShell remoting endpoint: role capability files list the cmdlets, functions and parameter values each role may use, and commands can run under a temporary virtual account.

- **Good at:** fine-grained, per-parameter constraints on Windows, with transcripts for audit.
- **Limits:** Windows and WinRM only, so it needs inbound WinRM and usually Active Directory. There's no approval step; access is decided by group membership at connect time.

## AWS Systems Manager Run Command

`ssm:SendCommand` runs an SSM document on instances through the SSM agent, which connects out to AWS — no inbound ports.

- **Good at:** fleets on AWS, IAM-controlled, no inbound access, output to S3 or CloudWatch.
- **Limits:** everything runs through the AWS control plane. On-prem machines need a hybrid activation, and what a host will run is decided centrally in IAM and documents, not on the host. Approvals exist through Systems Manager Change Manager, as a separate AWS workflow.

## Azure Run Command and Automation runbooks

**Run Command** runs a script on an Azure VM through the VM agent. **Automation** runbooks keep scripts centrally and run them on Azure or on hybrid workers, including Azure Arc-enabled machines.

- **Good at:** no inbound access on Azure, Azure RBAC, central scheduling and monitoring for runbooks.
- **Limits:** the original ("action") Run Command runs one command at a time, keeps only the tail of the output, and a command stuck pending blocks the ones after it, which makes it hard to use for debugging. Managed Run Command addresses much of this. Like SSM, it's cloud-control-plane based, and there's no approval step without building one around it.

## When to pick something else

remonce is deliberately narrow. Reach for something else when you need:

- **An interactive shell** for exploratory work — use SSH, ideally with short-lived certificates.
- **Fleet-wide orchestration or configuration management** — Ansible, Salt, SSM or your cloud's equivalent run the same change across hundreds of hosts; remonce runs one approved command on the hosts a request names.
- **Everything already on one cloud, with its identity everywhere** — that cloud's run-command service integrates with what you have.

remonce fits when a host's owner wants to offer a few specific actions or logs without handing out shell access, when some actions should need more than one person, and when the people approving can't — or shouldn't — reach the host directly.
