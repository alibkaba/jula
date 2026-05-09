package platform

import (
	"testing"
)

func TestGetEnvironmentInfo(t *testing.T) {
	tests := []struct {
		name     string
		env      map[string]string
		wantID   string
		wantType string
	}{
		{
			name: "Manual override",
			env: map[string]string{
				"JULA_ENVIRONMENT_ID": "manual-id",
				"JULA_PLATFORM_TYPE":  "CUSTOM",
			},
			wantID:   "manual-id",
			wantType: "CUSTOM",
		},
		{
			name: "GCP fallback",
			env: map[string]string{
				"JULA_GCP_PROJECT_ID": "gcp-project",
			},
			wantID:   "gcp-project",
			wantType: "GCP",
		},
		{
			name: "AWS fallback with account ID",
			env: map[string]string{
				"AWS_ACCOUNT_ID": "123456789012",
			},
			wantID:   "123456789012",
			wantType: "AWS",
		},
		{
			name: "AWS fallback with only region",
			env: map[string]string{
				"AWS_REGION": "us-east-1",
			},
			wantID:   "unknown-aws-account",
			wantType: "AWS",
		},
		{
			name: "Local fallback",
			env:  map[string]string{},
			wantID:   "unknown",
			wantType: "LOCAL",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear all potential env vars first
			t.Setenv("JULA_ENVIRONMENT_ID", "")
			t.Setenv("JULA_PLATFORM_TYPE", "")
			t.Setenv("JULA_GCP_PROJECT_ID", "")
			t.Setenv("AWS_ACCOUNT_ID", "")
			t.Setenv("AWS_REGION", "")

			for k, v := range tt.env {
				t.Setenv(k, v)
			}

			info := GetEnvironmentInfo()
			if info.ID != tt.wantID {
				t.Errorf("GetEnvironmentInfo().ID = %v, want %v", info.ID, tt.wantID)
			}
			if info.Type != tt.wantType {
				t.Errorf("GetEnvironmentInfo().Type = %v, want %v", info.Type, tt.wantType)
			}
		})
	}
}

func TestEnvironmentInfo_DisplayName(t *testing.T) {
	tests := []struct {
		name string
		info EnvironmentInfo
		want string
	}{
		{
			name: "With type",
			info: EnvironmentInfo{ID: "my-id", Type: "aws"},
			want: "my-id (AWS)",
		},
		{
			name: "Without type",
			info: EnvironmentInfo{ID: "local-id", Type: ""},
			want: "local-id",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.info.DisplayName(); got != tt.want {
				t.Errorf("DisplayName() = %v, want %v", got, tt.want)
			}
		})
	}
}
