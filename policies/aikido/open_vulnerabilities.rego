package aikido.open_vulnerabilities

import rego.v1

default compliant = false
erl_id := "E-VPM-11"

compliant if {
	input.erl_id == erl_id
	raw_json := base64.decode(input.finding.raw_data.finding.raw_data)
	issues := json.unmarshal(raw_json)
	count(issues) >= 0
}
