package jula.rules

import rego.v1

default allow := false

allow if {
	count(violations) == 0
}

violations contains {
	"resource": input.name,
	"message": "GCP IAM policy contains public access members (allUsers or allAuthenticatedUsers)",
	"field": "iam_policy_bindings_members"
} if {
	member := input.iam_policy_bindings_members[_]
	member == {"allUsers", "allAuthenticatedUsers"}[_]
}