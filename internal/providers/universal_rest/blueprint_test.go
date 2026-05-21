package universal_rest

import (
	"strings"
	"testing"
)

func TestAuthFlowConfig_Redacted(t *testing.T) {
	tests := []struct {
		name     string
		authFlow AuthFlowConfig
		want     AuthFlowConfig
	}{
		{
			name: "no secrets",
			authFlow: AuthFlowConfig{
				Type:        "bearer",
				ClientIDEnv: "CLIENT_ID",
			},
			want: AuthFlowConfig{
				Type:        "bearer",
				ClientIDEnv: "CLIENT_ID",
			},
		},
		{
			name: "with client secret",
			authFlow: AuthFlowConfig{
				Type:            "oauth2",
				ClientIDEnv:     "CLIENT_ID",
				ClientSecretEnv: "SUPER_SECRET",
			},
			want: AuthFlowConfig{
				Type:            "oauth2",
				ClientIDEnv:     "CLIENT_ID",
				ClientSecretEnv: "*REDACTED*",
			},
		},
		{
			name: "with token env",
			authFlow: AuthFlowConfig{
				Type:     "bearer",
				TokenEnv: "MY_TOKEN",
			},
			want: AuthFlowConfig{
				Type:     "bearer",
				TokenEnv: "*REDACTED*",
			},
		},
		{
			name: "with both secrets",
			authFlow: AuthFlowConfig{
				Type:            "oauth2",
				ClientSecretEnv: "SUPER_SECRET",
				TokenEnv:        "MY_TOKEN",
			},
			want: AuthFlowConfig{
				Type:            "oauth2",
				ClientSecretEnv: "*REDACTED*",
				TokenEnv:        "*REDACTED*",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.authFlow.Redacted()
			if got != tt.want {
				t.Errorf("AuthFlowConfig.Redacted() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestOpenAPIBlueprint_MarshalJSON(t *testing.T) {
	tests := []struct {
		name      string
		blueprint OpenAPIBlueprint
		checkFunc func(t *testing.T, data []byte)
	}{
		{
			name: "redacts secrets in JSON",
			blueprint: OpenAPIBlueprint{
				VendorName: "TestVendor",
				BaseURL:    "https://api.test.com",
				AuthFlow: AuthFlowConfig{
					Type:            "oauth2",
					ClientSecretEnv: "ACTUAL_SECRET",
					TokenEnv:        "ACTUAL_TOKEN",
				},
			},
			checkFunc: func(t *testing.T, data []byte) {
				strData := string(data)
				if strings.Contains(strData, "ACTUAL_SECRET") || strings.Contains(strData, "ACTUAL_TOKEN") {
					t.Errorf("MarshalJSON() leaked secrets: %s", strData)
				}
				if !strings.Contains(strData, "*REDACTED*") {
					t.Errorf("MarshalJSON() missing redaction markers: %s", strData)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.blueprint.MarshalJSON()
			if err != nil {
				t.Fatalf("MarshalJSON() error = %v", err)
			}
			tt.checkFunc(t, got)
		})
	}
}

func TestOpenAPIBlueprint_String(t *testing.T) {
	blueprint := OpenAPIBlueprint{
		VendorName: "TestVendor",
		AuthFlow: AuthFlowConfig{
			ClientSecretEnv: "SHOULD_NOT_SEE_ME",
		},
	}
	str := blueprint.String()
	if strings.Contains(str, "SHOULD_NOT_SEE_ME") {
		t.Errorf("String() leaked secrets: %s", str)
	}
	if !strings.Contains(str, "*REDACTED*") {
		t.Errorf("String() missing redaction markers: %s", str)
	}
}
