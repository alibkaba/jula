package transformer.gcp.database
import rego.v1

normalized contains res if {
	some i
	raw_inst := input.findings["E-GCP-INVENTORY"]["gcp"][i]
	resource := object.get(raw_inst, "resource", {})
	res_data := object.get(resource, "data", {})
	settings := object.get(res_data, "settings", {})
	ipConfiguration := object.get(settings, "ipConfiguration", {})
	userLabels := object.get(settings, "userLabels", {})
	backupConfiguration := object.get(settings, "backupConfiguration", {})

	res := {
		"encrypted_at_rest": object.get(settings, "dataDiskEncryptionType", "") != "",
		"require_tls": object.get(ipConfiguration, "requireSsl", false) == true,
		"publicly_accessible": object.get(ipConfiguration, "ipv4Enabled", false) == true,
		"environment": object.get(userLabels, "environment", ""),
		"backups_enabled": object.get(backupConfiguration, "enabled", false) == true
	}
}
