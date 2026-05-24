package compliance.controls.vpm_10

import rego.v1

# Default compliance status
default compliant = false

control_id := "VPM-10"
customer_control_id := "CC-VPM-10"

# VPM-10 checks that no open vulnerabilities of critical or high severity exist
# across evidence sources: EVID-VPM-10, EVID-VPM-01, EVID-RSK-03, EVID-RSK-04
compliant if {
	count(open_critical_issues) == 0
}

# Collect all open critical or high severity issues from mapped Datasets
open_critical_issues contains issue if {
	some evidence_id in {"EVID-VPM-10", "EVID-VPM-01", "EVID-RSK-03", "EVID-RSK-04"}
	some source_id
	entry := input.findings[evidence_id][source_id]
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
	some evidence_id in {"EVID-VPM-10", "EVID-VPM-01", "EVID-RSK-03", "EVID-RSK-04"}
	some source_id
	input.findings[evidence_id][source_id]
}
