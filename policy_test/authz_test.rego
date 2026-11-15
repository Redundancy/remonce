package remonce.authz_test

import data.remonce.authz

user(name) := {"username": name, "claims": {"sub": name, "groups": ["webapp-users"]}, "signed_at": "2026-01-01T00:00:00Z"}

outsider := {"username": "eve", "claims": {"sub": "eve", "groups": ["guests"]}}

users := {"groups_in": "webapp-users"}

# What the agent's config says each command needs. "fail" says nothing.
requirements := {
	"ping-test": {"approvals": [users], "executors": users},
	"ping-pair": {"approvals": [users, users], "executors": users},
	"restart-db": {"approvals": [], "executors": {"anyone": true}, "additional_policy": "Only on db-* hosts"},
}

base(command, approvers, executor) := {
	"action": "execute",
	"command": {"command": command, "id": "00000000-0000-0000-0000-000000000000"},
	"request_id": "0000",
	"approvers": approvers,
	"executor": executor,
	"host": "host-a",
}

# The input for an execution, with the command's requirement when it has one.
execute(command, approvers, executor) := object.union(
	base(command, approvers, executor),
	{"requirement": requirements[command]},
) if requirements[command]

execute(command, approvers, executor) := base(command, approvers, executor) if not requirements[command]

test_single_approval if {
	authz.allow with input as execute("ping-test", [user("alice")], user("alice"))
}

test_pair_needs_two_people if {
	not authz.allow with input as execute("ping-pair", [user("alice")], user("alice"))
	authz.decision.reason == "The approvals do not meet this command's requirements"
		with input as execute("ping-pair", [user("alice")], user("alice"))
	authz.allow with input as execute("ping-pair", [user("alice"), user("bob")], user("carol"))
}

test_executor_must_match if {
	not authz.allow with input as execute("ping-test", [user("alice")], outsider)
	authz.decision.reason == "You are not allowed to execute this command"
		with input as execute("ping-test", [user("alice")], outsider)
}

test_command_without_a_requirement_denied if {
	not authz.allow with input as execute("fail", [user("alice")], user("alice"))
	authz.decision.reason == "No approvals and executors are set for 'fail'"
		with input as execute("fail", [user("alice")], user("alice"))
}

# A null requirement is no requirement.
test_null_requirement_denied if {
	inp := object.union(base("fail", [user("alice")], user("alice")), {"requirement": null})
	not authz.allow with input as inp
}

test_extra_denial if {
	off_host := object.union(execute("restart-db", [user("alice")], user("alice")), {"host": "web-1"})
	not authz.allow with input as off_host
	authz.decision.reason == "restart-db may only run on db-* hosts" with input as off_host
	on_host := object.union(execute("restart-db", [user("alice")], user("alice")), {"host": "db-1"})
	authz.allow with input as on_host
}

# The requirement is the agent's, not the caller's: nothing in the signed
# command can stand in for it.
test_requirement_inside_the_command_is_ignored if {
	inp := base("fail", [user("alice")], user("alice"))
	smuggled := object.union(inp, {"command": object.union(inp.command, {"requirement": requirements["ping-test"]})})
	not authz.allow with input as smuggled
}

test_third_party_revoke if {
	authz.allow with input as {"action": "revoke", "revoker": user("bob"), "approvers": [user("alice")]}
	not authz.allow with input as {"action": "revoke", "revoker": outsider, "approvers": [user("alice")]}
}
