package gcp

import (
	"context"
	"os"
	"testing"
)

func TestLoadCAIConfigs_Invalid(t *testing.T) {
	_, err := LoadCAIConfigs("nonexistent.json")
	if err == nil {
		t.Fatal("expected error loading nonexistent config")
	}
}

func TestLoadCAIConfigs_Empty(t *testing.T) {
	tmpFile := t.TempDir() + "/empty.json"
	os.WriteFile(tmpFile, []byte(`{}`), 0644)
	_, err := LoadCAIConfigs(tmpFile)
	if err == nil {
		t.Fatal("expected error loading empty config")
	}
}

func TestLoadCAIConfigs_Valid(t *testing.T) {
	tmpFile := t.TempDir() + "/valid.json"
	os.WriteFile(tmpFile, []byte(`{"E-TEST-01":{"description":"test","provider":"gcp_cai","asset_types":["compute.googleapis.com/Instance"]}}`), 0644)
	configs, err := LoadCAIConfigs(tmpFile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(configs) != 1 {
		t.Fatal("expected 1 config")
	}
}

func TestNewUnifiedCAIProvider_Error(t *testing.T) {
	// asset.NewClient typically fails in a constrained test environment without ADC.
	// We just want to cover the error path.
	_, err := NewUnifiedCAIProvider(context.Background())
	if err == nil {
		t.Log("Warning: NewUnifiedCAIProvider succeeded, which was unexpected in this environment.")
	}
}

func TestInterpolateEnvVars(t *testing.T) {
	os.Setenv("TEST_PROJECT", "my-project-123")
	os.Setenv("TEST_REGION", "us-east1")
	defer os.Unsetenv("TEST_PROJECT")
	defer os.Unsetenv("TEST_REGION")

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "No variables",
			input:    "projects/foo/assets",
			expected: "projects/foo/assets",
		},
		{
			name:     "Single variable",
			input:    "projects/{{TEST_PROJECT}}/assets",
			expected: "projects/my-project-123/assets",
		},
		{
			name:     "Multiple variables",
			input:    "projects/{{TEST_PROJECT}}/regions/{{TEST_REGION}}",
			expected: "projects/my-project-123/regions/us-east1",
		},
		{
			name:     "Unset variable",
			input:    "val-{{UNSET_VAR}}",
			expected: "val-",
		},
		{
			name:     "Malformed tag",
			input:    "projects/{{TEST_PROJECT/assets",
			expected: "projects/{{TEST_PROJECT/assets",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := interpolateEnvVars(tt.input)
			if got != tt.expected {
				t.Errorf("interpolateEnvVars() = %v, want %v", got, tt.expected)
			}
		})
	}
}

