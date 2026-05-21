package normalization.gcp.database
import rego.v1

normalize(inst) = normalized if {
	settings := object.get(inst, "settings", {})
	ipConfiguration := object.get(settings, "ipConfiguration", {})
	userLabels := object.get(settings, "userLabels", {})
	backupConfiguration := object.get(settings, "backupConfiguration", {})

	normalized := {
		"encrypted_at_rest": object.get(settings, "dataDiskEncryptionType", "") != "",
		"require_tls": object.get(ipConfiguration, "requireSsl", false) == true,
		"publicly_accessible": object.get(ipConfiguration, "ipv4Enabled", false) == true,
		"environment": object.get(userLabels, "environment", ""),
		"backups_enabled": object.get(backupConfiguration, "enabled", false) == true
	}
}

