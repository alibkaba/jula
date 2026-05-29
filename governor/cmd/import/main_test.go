package main

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestGetEnvStr(t *testing.T) {
	tests := []struct {
		name     string
		envKey   string
		envValue string
		want     string
	}{
		{
			name:     "empty env var",
			envKey:   "TEST_ENV_STR_EMPTY",
			envValue: "",
			want:     "",
		},
		{
			name:     "standard string",
			envKey:   "TEST_ENV_STR_STD",
			envValue: "hello_world",
			want:     "hello_world",
		},
		{
			name:     "quoted string",
			envKey:   "TEST_ENV_STR_QUOTED",
			envValue: "\"hello_world\"",
			want:     "hello_world",
		},
		{
			name:     "mixed quotes string",
			envKey:   "TEST_ENV_STR_MIXED",
			envValue: "\"hello\"_world\"",
			want:     "hello\"_world",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(tt.envKey, tt.envValue)
			if got := getEnvStr(tt.envKey); got != tt.want {
				t.Errorf("getEnvStr() = %v, want %v", got, tt.want)
			}
		})
	}

	t.Run("unset env var", func(t *testing.T) {
		// Do not setenv, meaning it is empty
		if got := getEnvStr("TEST_ENV_UNSET"); got != "" {
			t.Errorf("getEnvStr() = %v, want empty string", got)
		}
	})
}

func TestGetEnvInt(t *testing.T) {
	tests := []struct {
		name       string
		envKey     string
		envValue   string
		defaultVal int
		want       int
	}{
		{
			name:       "empty env var",
			envKey:     "TEST_ENV_INT_EMPTY",
			envValue:   "",
			defaultVal: 42,
			want:       42,
		},
		{
			name:       "valid positive integer",
			envKey:     "TEST_ENV_INT_POS",
			envValue:   "100",
			defaultVal: 42,
			want:       100,
		},
		{
			name:       "valid negative integer",
			envKey:     "TEST_ENV_INT_NEG",
			envValue:   "-5",
			defaultVal: 42,
			want:       -5,
		},
		{
			name:       "invalid integer",
			envKey:     "TEST_ENV_INT_INVALID",
			envValue:   "not_a_number",
			defaultVal: 42,
			want:       42,
		},
		{
			name:       "quoted integer",
			envKey:     "TEST_ENV_INT_QUOTED",
			envValue:   "\"99\"",
			defaultVal: 42,
			want:       99,
		},
		{
			name:       "integer with whitespace",
			envKey:     "TEST_ENV_INT_SPACE",
			envValue:   "  88  ",
			defaultVal: 42,
			want:       88,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(tt.envKey, tt.envValue)
			if got := getEnvInt(tt.envKey, tt.defaultVal); got != tt.want {
				t.Errorf("getEnvInt() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseWorkspace(t *testing.T) {
	tests := []struct {
		name        string
		fileContent string
		wantErr     bool
		want        Workspace
	}{
		{
			name:        "empty file",
			fileContent: "",
			wantErr:     false,
			want: Workspace{
				ActiveProviders: make(map[string]ProviderConfig),
			},
		},
		{
			name:        "only comments",
			fileContent: "# This is a comment\n\n# Another comment\n",
			wantErr:     false,
			want: Workspace{
				ActiveProviders: make(map[string]ProviderConfig),
			},
		},
		{
			name: "organization only",
			fileContent: `
organization: "Acme Corp"
`,
			wantErr: false,
			want: Workspace{
				Organization:    "Acme Corp",
				ActiveProviders: make(map[string]ProviderConfig),
			},
		},
		{
			name: "single active provider",
			fileContent: `
organization: "Test Org"
active_providers:
  aws:
    doc_root: "https://aws.amazon.com/docs"
`,
			wantErr: false,
			want: Workspace{
				Organization: "Test Org",
				ActiveProviders: map[string]ProviderConfig{
					"aws": {DocRoot: "https://aws.amazon.com/docs"},
				},
			},
		},
		{
			name: "multiple active providers",
			fileContent: `
organization: "Multi Org"
active_providers:
  aws:
    doc_root: "https://aws.amazon.com"
  gcp:
    doc_root: "https://cloud.google.com"
`,
			wantErr: false,
			want: Workspace{
				Organization: "Multi Org",
				ActiveProviders: map[string]ProviderConfig{
					"aws": {DocRoot: "https://aws.amazon.com"},
					"gcp": {DocRoot: "https://cloud.google.com"},
				},
			},
		},
		{
			name: "active providers without doc root",
			fileContent: `
organization: "Test"
active_providers:
  aws:
`,
			wantErr: false,
			want: Workspace{
				Organization:    "Test",
				ActiveProviders: map[string]ProviderConfig{},
			},
		},
		{
			name: "provider exits section properly",
			fileContent: `
organization: "Test Org"
active_providers:
  aws:
    doc_root: "https://aws.amazon.com/docs"
other_section:
  foo: "bar"
`,
			wantErr: false,
			want: Workspace{
				Organization: "Test Org",
				ActiveProviders: map[string]ProviderConfig{
					"aws": {DocRoot: "https://aws.amazon.com/docs"},
				},
			},
		},
		{
			name: "unquoted organization",
			fileContent: `
organization: Test Org Unquoted
`,
			wantErr: false,
			want: Workspace{
				Organization:    "Test Org Unquoted",
				ActiveProviders: make(map[string]ProviderConfig),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Write temp file
			tmpDir := t.TempDir()
			tmpFile := filepath.Join(tmpDir, "workspace.yaml")
			err := os.WriteFile(tmpFile, []byte(tt.fileContent), 0644)
			if err != nil {
				t.Fatalf("Failed to write temp file: %v", err)
			}

			got, err := parseWorkspace(tmpFile)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseWorkspace() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseWorkspace() = %v, want %v", got, tt.want)
			}
		})
	}

	t.Run("missing file", func(t *testing.T) {
		_, err := parseWorkspace("non_existent_file.yaml")
		if err == nil {
			t.Errorf("parseWorkspace() expected error for missing file, got nil")
		}
	})
}
