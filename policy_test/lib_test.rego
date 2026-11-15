package remonce.lib_test

import data.remonce.lib

dba := {"groups_in": "dba"}

sec := {"groups_in": "security"}

anyone := {"anyone": true}

person(name, groups) := {"username": name, "claims": {"sub": name, "groups": groups}}

with_claims(claims) := {"username": "x", "claims": claims}

req(slots) := {"approvals": slots, "executors": anyone}

# --- predicates ---

test_groups_in if lib.accepts(dba, person("alice", ["dba", "x"]))

test_groups_in_needs_the_group if not lib.accepts(dba, person("alice", ["web"]))

test_groups_in_needs_a_list_claim if not lib.accepts(dba, with_claims({"groups": "dba"}))

test_groups_in_any_of_several if lib.accepts({"groups_in": ["dba", "sre"]}, person("alice", ["sre"]))

test_groups_in_none_of_several if not lib.accepts({"groups_in": ["dba", "sre"]}, person("alice", ["web"]))

test_claim_equals if lib.accepts({"claim_equals": ["team", "db"]}, with_claims({"team": "db"}))

test_claim_equals_differs if not lib.accepts({"claim_equals": ["team", "db"]}, with_claims({"team": "web"}))

test_claim_contains if lib.accepts({"claim_contains": ["roles", "admin"]}, with_claims({"roles": ["admin", "x"]}))

test_claim_contains_needs_a_list if not lib.accepts({"claim_contains": ["roles", "admin"]}, with_claims({"roles": "admin"}))

test_anyone if lib.accepts(anyone, with_claims({}))

test_unknown_predicate_accepts_no_one if not lib.accepts({"groups_inn": "dba"}, person("alice", ["dba"]))

test_two_predicates_in_a_slot_accept_no_one if {
	not lib.accepts({"anyone": true, "groups_in": "dba"}, person("alice", ["dba"]))
}

test_empty_slot_accepts_no_one if not lib.accepts({}, person("alice", ["dba"]))

# --- descriptions ---

test_describe_group if lib.describe(dba) == "someone in the dba group"

test_describe_groups if lib.describe({"groups_in": ["dba", "sre"]}) == "someone in one of the groups dba, sre"

test_describe_claim if lib.describe({"claim_equals": ["workflow", "deploy-prod"]}) == "someone whose workflow is deploy-prod"

test_describe_anyone if lib.describe(anyone) == "anyone"

test_describe_unknown_is_empty if lib.describe({"nope": 1}) == ""

test_descriptions if {
	d := lib.descriptions with input as {"requirements": {"x": req([dba, sec]), "y": req([])}}
	d.x == {"approvals": ["someone in the dba group", "someone in the security group"], "executors": "anyone"}
	d.y == {"approvals": [], "executors": "anyone"}
}

test_accepted if {
	people := [person("alice", ["dba", "security"]), person("bob", ["dba"])]
	rows := lib.accepted with input as {"requirement": req([dba, sec]), "people": people}
	rows == [[true, true], [true, false]]
}

# --- slots ---

test_one_slot_one_match if {
	lib.approvals_satisfied(req([dba]), [person("alice", ["dba"])])
}

test_one_slot_no_match if {
	not lib.approvals_satisfied(req([dba]), [person("bob", ["web"])])
}

test_one_person_cannot_fill_two_slots if {
	not lib.approvals_satisfied(req([dba, sec]), [person("alice", ["dba", "security"])])
}

# alice fits both slots, bob only the first. A greedy match that gives alice
# the first slot would fail; a real assignment exists (bob dba, alice sec).
test_not_greedy if {
	lib.approvals_satisfied(
		req([dba, sec]),
		[person("alice", ["dba", "security"]), person("bob", ["dba"])],
	)
}

# Three slots, two people: two dba slots and one security slot cannot all
# be filled by alice {dba, security} and bob {dba}.
test_hall_violation if {
	not lib.approvals_satisfied(
		req([dba, dba, sec]),
		[person("alice", ["dba", "security"]), person("bob", ["dba"])],
	)
}

test_extra_approvers_fine if {
	lib.approvals_satisfied(req([dba]), [person("alice", ["dba"]), person("bob", ["web"])])
}

test_no_slots if lib.approvals_satisfied(req([]), [])

test_too_many_slots if {
	slots := [anyone | some _ in numbers.range(1, 9)]
	people := [person(sprintf("p%d", [i]), []) | some i in numbers.range(1, 9)]
	not lib.approvals_satisfied(req(slots), people)
}

# --- executor ---

test_executor_allowed if {
	lib.executor_allowed({"executors": dba}, person("carol", ["dba"]))
}

test_executor_denied if {
	not lib.executor_allowed({"executors": dba}, person("carol", ["web"]))
}
