package remonce.lib_test

import data.remonce.lib

dba := {"op": "contains", "claim": "groups", "value": "dba"}

sec := {"op": "contains", "claim": "groups", "value": "security"}

person(name, groups) := {"username": name, "claims": {"sub": name, "groups": groups}}

req(slots) := {"approvals": slots, "executors": {"any_of": []}}

# --- predicates ---

test_equals if lib.predicate_matches({"op": "equals", "claim": "team", "value": "db"}, {"team": "db"})

test_contains if lib.predicate_matches(dba, {"groups": ["dba", "x"]})

test_contains_needs_array if not lib.predicate_matches(dba, {"groups": "dba"})

test_empty_any_of_accepts_anyone if lib.accepts({"any_of": []}, {})

test_missing_any_of_accepts_no_one if not lib.accepts({"description": "typo"}, {"groups": ["dba"]})

# --- slots ---

test_one_slot_one_match if {
	lib.approvals_satisfied(req([{"any_of": [dba]}]), [person("alice", ["dba"])])
}

test_one_slot_no_match if {
	not lib.approvals_satisfied(req([{"any_of": [dba]}]), [person("bob", ["web"])])
}

test_one_person_cannot_fill_two_slots if {
	not lib.approvals_satisfied(
		req([{"any_of": [dba]}, {"any_of": [sec]}]),
		[person("alice", ["dba", "security"])],
	)
}

# alice fits both slots, bob only the first. A greedy match that gives alice
# the first slot would fail; a real assignment exists (bob dba, alice sec).
test_not_greedy if {
	lib.approvals_satisfied(
		req([{"any_of": [dba]}, {"any_of": [sec]}]),
		[person("alice", ["dba", "security"]), person("bob", ["dba"])],
	)
}

# Three slots, two people: two dba slots and one security slot cannot all
# be filled by alice {dba, security} and bob {dba}.
test_hall_violation if {
	not lib.approvals_satisfied(
		req([{"any_of": [dba]}, {"any_of": [dba]}, {"any_of": [sec]}]),
		[person("alice", ["dba", "security"]), person("bob", ["dba"])],
	)
}

test_extra_approvers_fine if {
	lib.approvals_satisfied(
		req([{"any_of": [dba]}]),
		[person("alice", ["dba"]), person("bob", ["web"])],
	)
}

test_no_slots if lib.approvals_satisfied(req([]), [])

test_too_many_slots if {
	slots := [{"any_of": []} | some _ in numbers.range(1, 9)]
	people := [person(sprintf("p%d", [i]), []) | some i in numbers.range(1, 9)]
	not lib.approvals_satisfied(req(slots), people)
}

# --- executor ---

test_executor_allowed if {
	lib.executor_allowed({"executors": {"any_of": [dba]}}, person("carol", ["dba"]))
}

test_executor_denied if {
	not lib.executor_allowed({"executors": {"any_of": [dba]}}, person("carol", ["web"]))
}
