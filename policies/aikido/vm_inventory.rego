package aikido.vm_inventory

import rego.v1

default compliant = false
erl_id := "E-VPM-10"

compliant if {
	input.erl_id == erl_id
	raw_json := base64.decode(input.finding.raw_data.finding.raw_data)
	vms := json.unmarshal(raw_json)
	count(vms) >= 0
}
