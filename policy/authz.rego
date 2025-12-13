package remonse.authz
import future.keywords.if

default allow = false
default reason = "Denied by default"

# Input Documentation
# -------------------
# The 'input' object contains the following fields:
#
# input.command: object
#   The JSON payload of the command request.
#   Example: { "command": "test" }
#
# input.action: string
#   The action being requested (optional).
#   Example: "view_docs" used by the API to list commands.
#
# input.jwt: string
#   The raw encoded ID Token (JWT) of the authenticated user.
#   You can use `io.jwt.decode(input.jwt)` to inspect claims (e.g. groups, sub, iss).
#
# input.timestamp: string
#   The RFC3339 formatted verification timestamp from the TSA.
#   This represents when the command was signed.
#
# input.host: string
#   The hostname of the system where the agent is running.
#   Example: "agent-server-prod-01"
#

# Helper to extract claims
claims := payload if {
    [_, payload, _] := io.jwt.decode(input.jwt)
}

# Helper to get groups (default to empty list)
user_groups := claims.groups if {
    claims.groups
} else := []

# Action: View Docs
# Allow if the user is in the 'webapp-users' group
allow if {
    input.action == "view_docs"
    user_groups[_] == "webapp-users"
}

# Command: test
allow if {
    input.command.command == "test"
    user_groups[_] == "webapp-users"
}

# Command: ping-test
allow if {
    input.command.command == "ping-test"
    user_groups[_] == "webapp-users"
}

reason = "Authorized" if {
    allow
}

decision = {
    "allow": allow,
    "reason": reason
}
