## Alternatives
### PowerShell JEA (Just Enough Administration)
JEA creates a constrained endpoint with an allowed set of commandlets, functions and commands that the role is allowed to use. 
However, JEA is only available when using WinRM on a Windows platform.

### SSH + ForceCommand
This is a standard approach on linux - force SSH to invoke a targeted command. The command you force to be run is responsible
for handling `$SSH_ORIGINAL_COMMAND` to determine what can be allowed. This is a powerful option, but fraught with danger in
terms of the quality of evaluating and executing the "original command". Safer options tend to only allow selection of existing
commands and provide little to no evaluation options.

SSH itself tends to encourage _persistent credentials_ on VMs, which comes with its own risks. 
The risk can be mitigated in a number of ways:
* Tools like Hashicorp Vault's SSH Secrets Engine can create short-lived certificates which can be locked down with ForceCommand
* Tools like Hashicorp Boundary can perform dynamic authentication
* OpenPubkey SSH for OIDC SSH / SSH for ldap

While there are many options for this, the security and setup of this system involves a lot of moving parts and each one
has to be securely configured and maintained. You will need SSH access, and you'll need to configure the settings for each
system.

`SSH Agent Forwarding` makes it easier to run a second SSH session from a server without installing your own credentials on that server.

### AWS SSM / Azure Runbook Automation
AWS Secure Systems Managemer (SSM) can be used to run `ssm:SendCommand` commands to machines.  
Azure has Runbook Automation, which is a centralized location to define, execute and monitor scripts that can be run against
Azure. Runbook Automation can be used against Azure Arc enabled resources. 

### RunCommand (Azure)
RunCommand has a number of limitations, but commands getting stuck in a pending state and then preventing all further commands,
is a major issue. Lack of concurrency, and limits on output length make various debugging usages difficult.
Note that some (many?) of these limitations may be addressed in managed run commands.