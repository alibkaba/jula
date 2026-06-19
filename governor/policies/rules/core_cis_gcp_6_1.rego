package jula.rules

import rego.v1

default allow := false

allow if {
	input.provider == "gcp"
	input.resource.ipConfiguration.sslMode == "TRUSTED_CLIENT_CERTIFICATE_REQUIRED"
}

violation[{"msg": msg}] if {
	input.provider == "gcp"
	input.resource.ipConfiguration.sslMode != "TRUSTED_CLIENT_CERTIFICATE_REQUIRED"
	msg := "GCP resource must have ipConfiguration.sslMode set to TRUSTED_CLIENT_CERTIFICATE_REQUIRED"
}