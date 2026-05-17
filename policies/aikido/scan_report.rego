package aikido.scan_report

import rego.v1

default compliant = false
erl_id := "E-VPM-02"

compliant if {
	input.erl_id == erl_id
	raw_json := base64.decode(input.finding.raw_data.finding.raw_data)
	scans := json.unmarshal(raw_json)
	count(scans) >= 0
}
