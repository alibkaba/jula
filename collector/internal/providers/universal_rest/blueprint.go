// Package universal_rest implements an integration-driven REST engine
// that fetches compliance evidence from SaaS endpoints using declarative YAML integrations.
package universal_rest

import (
	"encoding/json"
	"strings"
)

// RESTIntegration defines the declarative configuration for a SaaS REST
// integration, including vendor identity, base URL, auth flow, and endpoints.
type RESTIntegration struct {
	VendorName string                        `yaml:"vendor_name" json:"vendor_name"`
	BaseURL    string                        `yaml:"base_url" json:"base_url"`
	AuthFlow   AuthFlowConfig                `yaml:"auth_flow" json:"auth_flow"`
	Endpoints  map[string]RESTEndpointConfig `yaml:"endpoints" json:"endpoints"`
}

// String implements fmt.Stringer to prevent credential leakage in logging.
func (b RESTIntegration) String() string {
	res, _ := b.MarshalJSON()
	return string(res)
}

// MarshalJSON implements json.Marshaler to redact sensitive fields.
func (b RESTIntegration) MarshalJSON() ([]byte, error) {
	type Alias RESTIntegration
	redacted := Alias(b)
	redacted.AuthFlow = b.AuthFlow.Redacted()
	return json.Marshal(redacted)
}

// AuthFlowConfig structures the authentication configuration
// for both OAuth2 and static Bearer/API token strategies.
type AuthFlowConfig struct {
	Type            string `yaml:"type" json:"type"` // "oauth2" or "bearer"
	TokenURL        string `yaml:"token_url,omitempty" json:"token_url,omitempty"`
	ClientIDEnv     string `yaml:"client_id_env,omitempty" json:"client_id_env,omitempty"`
	ClientSecretEnv string `yaml:"client_secret_env,omitempty" json:"client_secret_env,omitempty"`
	TokenEnv        string `yaml:"token_env,omitempty" json:"token_env,omitempty"`
}

// Redacted returns a copy of AuthFlowConfig with credentials redacted.
func (a AuthFlowConfig) Redacted() AuthFlowConfig {
	copy := a
	if copy.ClientSecretEnv != "" {
		copy.ClientSecretEnv = "*REDACTED*"
	}
	if copy.TokenEnv != "" {
		copy.TokenEnv = "*REDACTED*"
	}
	return copy
}

// RESTEndpointConfig defines specific GET/POST routing details and Evidence mappings.
type RESTEndpointConfig struct {
	EvidenceID  string            `yaml:"evidence_id" json:"evidence_id"`
	Description string            `yaml:"description" json:"description"`
	Method      string            `yaml:"method,omitempty" json:"method,omitempty"`
	Body        map[string]any    `yaml:"body,omitempty" json:"body,omitempty"`
	Headers     map[string]string `yaml:"headers,omitempty" json:"headers,omitempty"`
	Pagination  *PaginationConfig `yaml:"pagination,omitempty" json:"pagination,omitempty"`
	Allow404    bool              `yaml:"allow_404,omitempty" json:"allow_404,omitempty"`
}

// PaginationConfig maps next link attributes for paginating.
type PaginationConfig struct {
	NextURLField string `yaml:"next_url_field" json:"next_url_field"` // e.g. "header.Link" or JSON path path
	MaxPages     int    `yaml:"max_pages" json:"max_pages"`
}

// CleanPath removes virtual query parameters like 'jula_evidence' from paths
// to guarantee clean upstream requests while keeping YAML keys unique.
func CleanPath(path string) string {
	if !strings.Contains(path, "jula_evidence=") {
		return path
	}
	// Split by ? to separate query params
	parts := strings.SplitN(path, "?", 2)
	if len(parts) < 2 {
		return path
	}
	queryParams := strings.Split(parts[1], "&")
	var cleanedParams []string
	for _, param := range queryParams {
		if !strings.HasPrefix(param, "jula_evidence=") {
			cleanedParams = append(cleanedParams, param)
		}
	}
	if len(cleanedParams) == 0 {
		return parts[0]
	}
	return parts[0] + "?" + strings.Join(cleanedParams, "&")
}
