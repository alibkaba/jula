package universal_rest

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRESTIntegration_String(t *testing.T) {
	integration := RESTIntegration{
		VendorName: "TestVendor",
		BaseURL:    "https://api.test.com",
		AuthFlow: AuthFlowConfig{
			Type:            "bearer",
			ClientSecretEnv: "SUPER_SECRET",
			TokenEnv:        "MY_TOKEN",
		},
	}

	result := integration.String()

	if strings.Contains(result, "SUPER_SECRET") {
		t.Errorf("String() leaked ClientSecretEnv: %s", result)
	}
	if strings.Contains(result, "MY_TOKEN") {
		t.Errorf("String() leaked TokenEnv: %s", result)
	}
	if !strings.Contains(result, "*REDACTED*") {
		t.Errorf("String() did not contain *REDACTED*: %s", result)
	}
	if !strings.Contains(result, "TestVendor") {
		t.Errorf("String() missing VendorName: %s", result)
	}
}

func TestRESTIntegration_MarshalJSON(t *testing.T) {
	integration := RESTIntegration{
		VendorName: "TestVendor",
		AuthFlow: AuthFlowConfig{
			Type:            "bearer",
			ClientSecretEnv: "SECRET1",
			TokenEnv:        "TOKEN1",
		},
	}

	data, err := json.Marshal(integration)
	if err != nil {
		t.Fatalf("MarshalJSON failed: %v", err)
	}

	result := string(data)
	if strings.Contains(result, "SECRET1") {
		t.Errorf("MarshalJSON leaked ClientSecretEnv: %s", result)
	}
	if strings.Contains(result, "TOKEN1") {
		t.Errorf("MarshalJSON leaked TokenEnv: %s", result)
	}
	if !strings.Contains(result, "*REDACTED*") {
		t.Errorf("MarshalJSON did not contain *REDACTED*: %s", result)
	}
}

func TestAuthFlowConfig_Redacted(t *testing.T) {
	tests := []struct {
		name     string
		input    AuthFlowConfig
		expected AuthFlowConfig
	}{
		{
			name: "redacts secrets and tokens",
			input: AuthFlowConfig{
				Type:            "oauth2",
				TokenURL:        "https://test.com/token",
				ClientIDEnv:     "CLIENT_ID",
				ClientSecretEnv: "SECRET",
				TokenEnv:        "TOKEN",
			},
			expected: AuthFlowConfig{
				Type:            "oauth2",
				TokenURL:        "https://test.com/token",
				ClientIDEnv:     "CLIENT_ID",
				ClientSecretEnv: "*REDACTED*",
				TokenEnv:        "*REDACTED*",
			},
		},
		{
			name: "no secrets to redact",
			input: AuthFlowConfig{
				Type:        "none",
				ClientIDEnv: "CLIENT_ID",
			},
			expected: AuthFlowConfig{
				Type:        "none",
				ClientIDEnv: "CLIENT_ID",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.input.Redacted()
			if result != tt.expected {
				t.Errorf("Redacted() = %v, want %v", result, tt.expected)
			}
		})
	}
}
