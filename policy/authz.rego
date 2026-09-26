package remonce.authz
import future.keywords.if
import future.keywords.in

default allow = false
default reason = "Denied by default"

# Input Documentation
# -------------------
# For command execution requests, `input` contains:
#
#   input.action: string           - "execute" for command execution,
#                                    "revoke" for third-party revocation
#   input.command: object          - the approver's signed command payload
#   input.approver:                - the authorizing identity
#     .username: string
#     .claims:   object            - the approver's OIDC JWT claims (groups, etc.)
#     .signed_at: string           - RFC3339 approver TSA timestamp
#   input.operator:                - the executing identity (equals approver
#                                    when self-executing). For "revoke" this
#                                    is the revoker's identity.
#     .username: string
#     .claims:   object
#     .signed_at: string
#   input.self_executed: bool      - true iff approver == operator
#   input.host: string             - agent hostname
#
# Revocation note: an approver revoking their own bundle (same OIDC `sub`)
# is always allowed by the agent without consulting OPA. Policy is only
# asked when someone ELSE wants to revoke (action == "revoke").
#
# For file access / log streaming / command listing, a simpler shape is used:
#   input.action:       string  ("view_docs" | "read_file" | "view_execution")
#   input.jwt:          string  (the caller's bearer ID token)
#   input.file:         object  (when action == "read_file")
#   input.execution_id: string  (when action == "view_execution")
#
# The agent enforces cryptographic checks (signatures, TSA freshness, operator
# claim predicates) BEFORE calling OPA. Policy here encodes business-level
# authorization: who may authorize what, separation of duties, etc.

# --- Helpers ---

approver_groups := g if { g := input.approver.claims.groups } else := []
operator_groups := g if { g := input.operator.claims.groups } else := []

# --- File access / command listing ---
# These keep the legacy `jwt`-in-input shape for the file streaming handler.
claims := payload if {
    [_, payload, _] := io.jwt.decode(input.jwt)
}
legacy_user_groups := g if { g := claims.groups } else := []

allow if {
    input.action == "view_docs"
    "webapp-users" in legacy_user_groups
}

allow if {
    input.action == "read_file"
    "webapp-users" in legacy_user_groups
}

# Streaming an execution's output log.
allow if {
    input.action == "view_execution"
    "webapp-users" in legacy_user_groups
}

# --- Command execution rules ---

# test: any approver in `webapp-users` can authorize; no operator restriction.
allow if {
    input.action == "execute"
    input.command.command == "test"
    "webapp-users" in approver_groups
}

# ping-test: same.
allow if {
    input.action == "execute"
    input.command.command == "ping-test"
    "webapp-users" in approver_groups
}

# Third-party revocation: anyone in `webapp-users` may revoke another
# user's approval. Tighten this (e.g. to an admin group) in production.
allow if {
    input.action == "revoke"
    "webapp-users" in operator_groups
}

# Example (disabled — add your own rules below):
# Restrict a "restart-service" command to approvers in `oncall-managers`, and
# require a distinct operator (four-eyes).
#
# allow if {
#     input.action == "execute"
#     input.command.command == "restart-service"
#     "oncall-managers" in approver_groups
#     not input.self_executed
#     "noc-l2" in operator_groups
# }

reason = "Authorized" if {
    allow
}

decision = {
    "allow": allow,
    "reason": reason,
}
