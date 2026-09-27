# Checks a request against a published requirement document.
#
# A requirement document (data.remonce.requirements[<command>]) says which
# approvals a command needs — one per slot, each from a different person —
# and who may execute it. The agent serves the same document to the UI, so
# enforcing it through these rules keeps what people are shown and what is
# enforced the same.
#
#   {
#     "description": "...",                      (optional)
#     "approvals": [ { "description": "a DBA",   (optional)
#                      "any_of": [ {"op": "contains", "claim": "groups", "value": "dba"} ] } ],
#     "executors": { "description": "...", "any_of": [ ... ] },
#     "additional_policy": "..."                 (optional: set when authz adds more rules)
#   }
#
# "any_of": [] means anyone; a missing "any_of" matches no one.
package remonce.lib

# Hall's-condition check below walks every subset of slots.
max_slots := 8

predicate_matches(p, claims) if {
	p.op == "equals"
	claims[p.claim] == p.value
}

predicate_matches(p, claims) if {
	p.op == "contains"
	is_array(claims[p.claim])
	p.value in claims[p.claim]
}

accepts(slot, _) if slot.any_of == []

accepts(slot, claims) if {
	some p in slot.any_of
	predicate_matches(p, claims)
}

has_bit(mask, j) if bits.and(mask, bits.lsh(1, j)) != 0

popcount(mask, n) := count({j | some j in numbers.range(0, n - 1); has_bit(mask, j)})

# Approvers (by index) who could fill at least one of the slots in `mask`.
candidates(slots, approvers, mask) := {i |
	some i, a in approvers
	some j, slot in slots
	has_bit(mask, j)
	accepts(slot, a.claims)
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

executor_allowed(req, executor) if accepts(req.executors, executor.claims)

satisfied(req, inp) if {
	approvals_satisfied(req, inp.approvers)
	executor_allowed(req, inp.executor)
}
