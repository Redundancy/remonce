package remonce.authz

import data.remonce.lib

default allow := false

# Input
# -----
# Executing a request (action "execute"):
#
#   input.command:    object  the signed command (command, id, target_machines, params, ...)
#   input.request_id: string  hex SHA-256 of the signed request
#   input.approvers:  array   one entry per approval, each a different person:
#                             { username, claims (OIDC claims), signed_at (RFC 3339) }
#   input.executor:   object  who is submitting it, from their login session:
#                             { username, claims }
#   input.host:       string  the agent's hostname
#
# Revoking a request (action "revoke") — asked only when the revoker is not
# one of the request's approvers (approvers may always revoke):
#
#   input.command, input.request_id, input.approvers, input.host as above
#   input.revoker:    object  { username, claims, signed_at }
#
# Viewing (actions "view_docs", "read_file", "view_execution"):
#
#   input.viewer:       object  who is looking, from their login session:
#                               { username, claims } (claims verified by the agent)
#   input.file:         object  (read_file) { name } or { path }
#   input.execution_id: string  (view_execution)
#
# The agent verifies every signature, token and freshness window before
# asking. Policy decides whether the approvals and the executor are enough.

# --- Executing: published requirements ---

# Each command's requirements are published in requirements.json. The same
# document is shown to people in the UI, so allowing through it keeps what
# they see and what is enforced the same.
requirement := data.remonce.requirements[input.command.command]

allow if {
	input.action == "execute"
	lib.satisfied(requirement, input)
	not denied
}

# Further restrictions go here as messages. When a command has one, set its
# "additional_policy" in requirements.json so the UI says so.
extra_denials contains "restart-db may only run on db-* hosts" if {
	input.action == "execute"
	input.command.command == "restart-db"
	not startswith(input.host, "db-")
}

denied if some _ in extra_denials

# --- Revoking someone else's request ---

allow if {
	input.action == "revoke"
	"webapp-users" in object.get(input.revoker.claims, "groups", [])
}

# --- Viewing ---

viewer_groups := object.get(input.viewer.claims, "groups", [])

allow if {
	input.action == "view_docs"
	"webapp-users" in viewer_groups
}

allow if {
	input.action == "read_file"
	"webapp-users" in viewer_groups
}

allow if {
	input.action == "view_execution"
	"webapp-users" in viewer_groups
}

# --- Decision ---

reason := "Authorized" if {
	allow
} else := msg if {
	input.action == "execute"
	not requirement
	msg := sprintf("No published requirements for '%s'", [input.command.command])
} else := "The approvals do not meet the published requirements" if {
	input.action == "execute"
	not lib.approvals_satisfied(requirement, input.approvers)
} else := "You are not allowed to execute this command" if {
	input.action == "execute"
	not lib.executor_allowed(requirement, input.executor)
} else := msg if {
	some msg in extra_denials
} else := "Denied by default"

decision := {
	"allow": allow,
	"reason": reason,
}
