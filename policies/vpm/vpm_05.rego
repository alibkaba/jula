package compliance.scf.vpm_05

import rego.v1

# Default compliance status
default compliant = false

# SCF metadata constants
scf_id := "VPM-05"
customer_control_id := "CC-VPM-5"

# VPM-05 checks that no open vulnerabilities of critical or high severity exist
# across evidence sources: E-VPM-10, E-VPM-05, E-MNT-03
compliant if {
	count(open_critical_issues) == 0
}

# Collect all open critical or high severity issues from mapped ERLs
open_critical_issues contains issue if {
	some erl_id in {"E-VPM-10", "E-VPM-05", "E-MNT-03"}
	some source_id
	entry := input.findings[erl_id][source_id]
	raw := entry.raw_data
	some i
	issue := raw[i]
	lower(issue.status) == "open"
	lower(issue.severity) in {"critical", "high"}
}

# Dynamic details
details := sprintf("Compliant: no open critical or high severity vulnerabilities detected across %d evidence sources", [count(evidence_sources)]) if {
	compliant
}

details := sprintf("Non-Compliant: %d open critical/high severity vulnerabilities detected", [count(open_critical_issues)]) if {
	not compliant
}

# Helper to count distinct evidence sources evaluated
evidence_sources contains source_id if {
	some erl_id in {"E-VPM-10", "E-VPM-05", "E-MNT-03"}
	some source_id
	input.findings[erl_id][source_id]
}
