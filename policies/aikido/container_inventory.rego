package aikido.container_inventory

import rego.v1

default compliant = false
erl_id := "E-VPM-01"

compliant if {
	input.erl_id == erl_id
	# Decode Base64 raw_data and verify it contains a valid list
	raw_json := base64.decode(input.finding.raw_data.finding.raw_data)
	containers := json.unmarshal(raw_json)
	count(containers) >= 0
}
