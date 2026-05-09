package platform

import (
	"os"
	"strings"
)

// EnvironmentInfo holds metadata about the hosting cloud platform.
type EnvironmentInfo struct {
	ID   string
	Type string
}

// GetEnvironmentInfo attempts to dynamically identify the current environment.
func GetEnvironmentInfo() EnvironmentInfo {
	// 1. Manual Override / Explicit Context
	if envID := os.Getenv("JULA_ENVIRONMENT_ID"); envID != "" {
		return EnvironmentInfo{
			ID:   envID,
			Type: os.Getenv("JULA_PLATFORM_TYPE"), // Optional type hint
		}
	}

	// 2. GCP Context
	if projectID := os.Getenv("JULA_GCP_PROJECT_ID"); projectID != "" {
		return EnvironmentInfo{
			ID:   projectID,
			Type: "GCP",
		}
	}

	// 3. AWS Context (Attempt detection via standard env vars)
	// Note: In a full implementation, we might call STS GetCallerIdentity here.
	if awsRegion := os.Getenv("AWS_REGION"); awsRegion != "" || os.Getenv("AWS_ACCOUNT_ID") != "" {
		id := os.Getenv("AWS_ACCOUNT_ID")
		if id == "" {
			id = "unknown-aws-account"
		}
		return EnvironmentInfo{
			ID:   id,
			Type: "AWS",
		}
	}

	return EnvironmentInfo{
		ID:   "unknown",
		Type: "LOCAL",
	}
}

// DisplayName returns a human-readable string for the environment.
func (e EnvironmentInfo) DisplayName() string {
	if e.Type == "" {
		return e.ID
	}
	return e.ID + " (" + strings.ToUpper(e.Type) + ")"
}
