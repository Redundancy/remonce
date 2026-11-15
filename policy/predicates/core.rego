# The predicates remonce ships with.
#
# A requirement names who can fill a slot with a predicate and an argument,
# such as {"groups_in": "dba"}. Each predicate is defined here twice over:
# a `holds` clause says who it accepts, and a `describe` clause says the
# same thing in words for the people looking at the command.
#
#   person: { "username": ..., "claims": { the person's verified ID token claims } }
#
# To add predicates of your own, put them in a package of their own (one
# file) and list it in policy/predicates.rego. Don't add clauses to this
# package from another file: the embedded engine can't resolve a function
# whose clauses are spread over several files.
package remonce.predicates.core

groups_of(person) := object.get(person.claims, "groups", [])

# {"anyone": true}: any logged-in person. The argument is ignored.
holds("anyone", _, _) := true

describe("anyone", _) := "anyone"

# {"groups_in": "dba"}: the person's `groups` claim includes the group.
# {"groups_in": ["dba", "sre"]}: it includes at least one of them.
holds("groups_in", group, person) if {
	is_string(group)
	group in groups_of(person)
}

holds("groups_in", groups, person) if {
	is_array(groups)
	some group in groups
	group in groups_of(person)
}

describe("groups_in", group) := sprintf("someone in the %s group", [group]) if is_string(group)

describe("groups_in", groups) := sprintf("someone in one of the groups %s", [concat(", ", groups)]) if is_array(groups)

# {"claim_equals": ["workflow", "deploy-prod"]}: the claim has exactly this value.
holds("claim_equals", [claim, value], person) if person.claims[claim] == value

describe("claim_equals", [claim, value]) := sprintf("someone whose %s is %v", [claim, value])

# {"claim_contains": ["roles", "admin"]}: the claim is a list that includes this value.
holds("claim_contains", [claim, value], person) if {
	is_array(person.claims[claim])
	value in person.claims[claim]
}

describe("claim_contains", [claim, value]) := sprintf("someone whose %s include %v", [claim, value])
