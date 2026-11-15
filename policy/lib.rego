# Checks a request against a command's requirement.
#
# A requirement says which approvals a command needs — one per slot, each
# from a different person — and who may execute it:
#
#   {
#     "approvals": [ {"groups_in": "dba"}, {"groups_in": "security"} ],
#     "executors": {"groups_in": "sre-oncall"},
#     "additional_policy": "..."                 (optional: set when authz adds more rules)
#   }
#
# A slot is one predicate and its argument. Predicates are Rego functions,
# each with a description (see policy/predicates.rego), so what people are
# shown and what is enforced come from the same place.
package remonce.lib

import data.remonce.predicates

# Hall's-condition check below walks every subset of slots.
max_slots := 8

# person: { "username": ..., "claims": {...} }
accepts(slot, person) if {
	count(slot) == 1
	some name, argument in slot
	predicates.holds(name, argument, person)
}

# What a slot asks for, in words; "" for a predicate nobody has defined
# (which accepts no one).
describe(slot) := concat("", [text |
	count(slot) == 1
	some name, argument in slot
	text := predicates.describe(name, argument)
])

has_bit(mask, j) if bits.and(mask, bits.lsh(1, j)) != 0

popcount(mask, n) := count({j | some j in numbers.range(0, n - 1); has_bit(mask, j)})

# Approvers (by index) who could fill at least one of the slots in `mask`.
candidates(slots, approvers, mask) := {i |
	some i, approver in approvers
	some j, slot in slots
	has_bit(mask, j)
	accepts(slot, approver)
}

# Every slot can be given its own approver iff, for every set of slots, at
# least that many approvers could fill one of them (Hall's marriage
# theorem). Unlike a greedy assignment, this finds a fit when one exists.
# Approvers are distinct people: the agent rejects duplicate subjects.
approvals_satisfied(req, _) if count(req.approvals) == 0

approvals_satisfied(req, approvers) if {
	n := count(req.approvals)
	n > 0
	n <= max_slots
	every mask in numbers.range(1, bits.lsh(1, n) - 1) {
		count(candidates(req.approvals, approvers, mask)) >= popcount(mask, n)
	}
}

executor_allowed(req, executor) if accepts(req.executors, executor)

satisfied(req, inp) if {
	approvals_satisfied(req, inp.approvers)
	executor_allowed(req, inp.executor)
}

# --- For display ---
#
# The agent asks these two rules so the UI can show what a command needs
# and how far a request has got. Neither decides anything.

# input.requirements: { command: requirement }
# For each, the description of every approval slot and of the executors.
descriptions[name] := described if {
	some name, req in input.requirements
	described := {
		"approvals": [describe(slot) | some slot in req.approvals],
		"executors": describe(req.executors),
	}
}

# input.requirement: a requirement; input.people: [person]
# One row per approval slot: whether it would accept each person.
accepted := [row |
	some slot in input.requirement.approvals
	row := [ok |
		some person in input.people
		ok := count([1 | accepts(slot, person)]) == 1
	]
]
