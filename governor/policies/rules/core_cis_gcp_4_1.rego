package jula.rules

import rego.v1

deny contains {
	"id": "gcp_service_account_email_not_default",
	"title": "GCP Service Account Email Restriction",
	"description": "Service account email must not be set to default.",
	"severity": "high",
	"resource": input,
} if {
	input.service_accounts.email == "default"
}