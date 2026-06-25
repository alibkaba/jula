package aiutil

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestGetEnvStr(t *testing.T) {
	tests := []struct {
		name     string
		envKey   string
		envValue string
		want     string
	}{
		{"plain value", "TEST_AIUTIL_STR", "hello", "hello"},
		{"quoted value", "TEST_AIUTIL_STR_Q", "\"quoted\"", "quoted"},
		{"empty", "TEST_AIUTIL_STR_E", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(tt.envKey, tt.envValue)
			if got := GetEnvStr(tt.envKey); got != tt.want {
				t.Errorf("GetEnvStr(%q) = %q, want %q", tt.envKey, got, tt.want)
			}
		})
	}

	t.Run("unset", func(t *testing.T) {
		if got := GetEnvStr("AIUTIL_UNSET_KEY_12345"); got != "" {
			t.Errorf("GetEnvStr(unset) = %q, want empty", got)
		}
	})
}

func TestGetEnvInt(t *testing.T) {
	tests := []struct {
		name       string
		envValue   string
		defaultVal int
		want       int
	}{
		{"valid", "42", 0, 42},
		{"quoted", "\"99\"", 0, 99},
		{"negative", "-5", 0, -5},
		{"invalid", "abc", 10, 10},
		{"empty", "", 10, 10},
		{"whitespace", "  88  ", 0, 88},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := "TEST_AIUTIL_INT_" + tt.name
			t.Setenv(key, tt.envValue)
			if got := GetEnvInt(key, tt.defaultVal); got != tt.want {
				t.Errorf("GetEnvInt(%q, %d) = %d, want %d", key, tt.defaultVal, got, tt.want)
			}
		})
	}
}

func TestParseWorkspace(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    Workspace
	}{
		{
			name:    "empty",
			content: "",
			want:    Workspace{ActiveProviders: make(map[string]ProviderConfig)},
		},
		{
			name:    "org only",
			content: "organization: \"Acme Corp\"\n",
			want:    Workspace{Organization: "Acme Corp", ActiveProviders: make(map[string]ProviderConfig)},
		},
		{
			name: "single provider",
			content: `organization: "Test"
active_providers:
  aws:
    doc_root: "https://aws.amazon.com"
`,
			want: Workspace{
				Organization: "Test",
				ActiveProviders: map[string]ProviderConfig{
					"aws": {DocRoot: "https://aws.amazon.com"},
				},
			},
		},
		{
			name: "multiple providers",
			content: `organization: "Multi"
active_providers:
  aws:
    doc_root: "https://aws.amazon.com"
  gcp:
    doc_root: "https://cloud.google.com"
`,
			want: Workspace{
				Organization: "Multi",
				ActiveProviders: map[string]ProviderConfig{
					"aws": {DocRoot: "https://aws.amazon.com"},
					"gcp": {DocRoot: "https://cloud.google.com"},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "workspace.yaml")
			if err := os.WriteFile(path, []byte(tt.content), 0644); err != nil {
				t.Fatal(err)
			}
			got, err := ParseWorkspace(path)
			if err != nil {
				t.Fatalf("ParseWorkspace error: %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseWorkspace = %+v, want %+v", got, tt.want)
			}
		})
	}

	t.Run("missing file", func(t *testing.T) {
		_, err := ParseWorkspace("nonexistent.yaml")
		if err == nil {
			t.Error("expected error for missing file")
		}
	})
}

func TestLoadPrimaryConfig(t *testing.T) {
	t.Setenv("JULA_PRIMARY_ENDPOINT", "https://api.example.com/v1/chat")
	t.Setenv("JULA_PRIMARY_KEY", "sk-test")
	t.Setenv("JULA_PRIMARY_MODEL", "gpt-4")
	t.Setenv("JULA_PRIMARY_TIMEOUT_SEC", "30")

	cfg := LoadPrimaryConfig()
	if cfg.Endpoint != "https://api.example.com/v1/chat" {
		t.Errorf("unexpected endpoint: %s", cfg.Endpoint)
	}
	if cfg.Key != "sk-test" {
		t.Errorf("unexpected key: %s", cfg.Key)
	}
	if cfg.Model != "gpt-4" {
		t.Errorf("unexpected model: %s", cfg.Model)
	}
	if cfg.Timeout != 30*time.Second {
		t.Errorf("unexpected timeout: %v", cfg.Timeout)
	}
}

func TestLoadFallbackConfig(t *testing.T) {
	t.Setenv("JULA_FALLBACK_ENDPOINT", "https://fallback.example.com")
	t.Setenv("JULA_FALLBACK_KEY", "sk-fallback")
	t.Setenv("JULA_FALLBACK_MODEL", "gpt-3.5")
	t.Setenv("JULA_FALLBACK_TIMEOUT_SEC", "60")

	cfg := LoadFallbackConfig()
	if cfg.Endpoint != "https://fallback.example.com" {
		t.Errorf("unexpected endpoint: %s", cfg.Endpoint)
	}
	if cfg.Timeout != 60*time.Second {
		t.Errorf("unexpected timeout: %v", cfg.Timeout)
	}
}

func TestLoadMaxRetries(t *testing.T) {
	t.Run("default", func(t *testing.T) {
		os.Unsetenv("JULA_MAX_RETRIES_PER_TIER")
		if got := LoadMaxRetries(); got != 2 {
			t.Errorf("LoadMaxRetries default = %d, want 2", got)
		}
	})

	t.Run("custom", func(t *testing.T) {
		t.Setenv("JULA_MAX_RETRIES_PER_TIER", "5")
		if got := LoadMaxRetries(); got != 5 {
			t.Errorf("LoadMaxRetries = %d, want 5", got)
		}
	})
}
