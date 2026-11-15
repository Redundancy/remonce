# The predicate libraries this agent uses.
#
# A library is a package with `holds(name, argument, person)` and
# `describe(name, argument)` functions; policy/predicates/core.rego is the
# one remonce ships. To use another, put its file under policy/, import it
# here, and add a `holds` and a `describe` line for it.
#
# A predicate that no listed library defines accepts no one.
package remonce.predicates

import data.remonce.predicates.core

holds(name, argument, person) if core.holds(name, argument, person)

describe(name, argument) := core.describe(name, argument)
