package aikido.repo_inventory

import rego.v1

default compliant = false
erl_id := "E-VPM-05"

compliant if {
	input.erl_id == erl_id
	raw_json := base64.decode(input.finding.raw_data.finding.raw_data)
	repos := json.unmarshal(raw_json)
	# Check that we have active scanned repositories in the inventory
	count(repos) > 0
	repos[0].active == true
}
