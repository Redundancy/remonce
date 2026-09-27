package remonce.authz_test

import data.remonce.authz

user(name) := {"username": name, "claims": {"sub": name, "groups": ["webapp-users"]}, "signed_at": "2026-01-01T00:00:00Z"}

outsider := {"username": "eve", "claims": {"sub": "eve", "groups": ["guests"]}}

execute(command, approvers, executor) := {
	"action": "execute",
	"command": {"command": command, "id": "00000000-0000-0000-0000-000000000000"},
	"request_id": "0000",
	"approvers": approvers,
	"executor": executor,
	"host": "host-a",
}

test_single_approval if {
	authz.allow with input as execute("ping-test", [user("alice")], user("alice"))
}

test_pair_needs_two_people if {
	not authz.allow with input as execute("ping-pair", [user("alice")], user("alice"))
	authz.decision.reason == "The approvals do not meet the published requirements"
		with input as execute("ping-pair", [user("alice")], user("alice"))
	authz.allow with input as execute("ping-pair", [user("alice"), user("bob")], user("carol"))
}

test_executor_must_match if {
	not authz.allow with input as execute("ping-test", [user("alice")], outsider)
	authz.decision.reason == "You are not allowed to execute this command"
		with input as execute("ping-test", [user("alice")], outsider)
}

test_unpublished_command_denied if {
	not authz.allow with input as execute("fail", [user("alice")], user("alice"))
	authz.decision.reason == "No published requirements for 'fail'"
		with input as execute("fail", [user("alice")], user("alice"))
}

test_extra_denial if {
	inp := object.union(execute("restart-db", [user("alice")], user("alice")), {"host": "web-1"})
	not authz.allow with input as inp
		with data.remonce.requirements as {"restart-db": {"approvals": [], "executors": {"any_of": []}}}
}

test_third_party_revoke if {
	authz.allow with input as {"action": "revoke", "revoker": user("bob"), "approvers": [user("alice")]}
	not authz.allow with input as {"action": "revoke", "revoker": outsider, "approvers": [user("alice")]}
}

# Every published document without "additional_policy" must be enough on
# its own: people matching its slots and executor rule are allowed. Catches
# policy drifting away from what the UI shows.
test_published_requirements_are_sufficient if {
	every name, doc in data.remonce.requirements {
		sufficient(name, doc)
	}
}

sufficient(_, doc) if doc.additional_policy

sufficient(name, doc) if {
	not doc.additional_policy
	approvers := [{"username": sprintf("u%d", [j]), "claims": synth(slot, j)} | some j, slot in doc.approvals]
	executor := {"username": "x", "claims": synth(doc.executors, 99)}
	authz.allow with input as {
		"action": "execute",
		"command": {"command": name},
		"approvers": approvers,
		"executor": executor,
		"host": "host-a",
	}
}

synth(slot, j) := {"sub": sprintf("u%d", [j])} if count(slot.any_of) == 0

synth(slot, j) := {"sub": sprintf("u%d", [j]), p.claim: [p.value]} if {
	p := slot.any_of[0]
	p.op == "contains"
}

synth(slot, j) := {"sub": sprintf("u%d", [j]), p.claim: p.value} if {
	p := slot.any_of[0]
	p.op == "equals"
}
