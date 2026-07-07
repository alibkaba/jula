package aiutil

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
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

// ---------------------------------------------------------------------------
// CallAIEndpoint (httptest mock server)
// ---------------------------------------------------------------------------

func TestCallAIEndpoint_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-key" {
			t.Errorf("unexpected auth header: %s", r.Header.Get("Authorization"))
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("unexpected content-type: %s", r.Header.Get("Content-Type"))
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"choices":[{"message":{"content":"Hello from AI"}}]}`)
	}))
	defer srv.Close()

	cfg := AIConfig{Endpoint: srv.URL, Key: "test-key", Model: "test-model", Timeout: 5 * time.Second}
	req := ChatRequest{Model: "test-model", Messages: []ChatMessage{{Role: "user", Content: "test"}}}

	content, status, _, err := CallAIEndpoint(cfg, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status != 200 {
		t.Errorf("unexpected status: %d", status)
	}
	if content != "Hello from AI" {
		t.Errorf("unexpected content: %q", content)
	}
}

func TestCallAIEndpoint_NoAuthKey(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			t.Errorf("expected no auth header, got: %s", r.Header.Get("Authorization"))
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"choices":[{"message":{"content":"no-auth"}}]}`)
	}))
	defer srv.Close()

	cfg := AIConfig{Endpoint: srv.URL, Key: "", Model: "m", Timeout: 5 * time.Second}
	req := ChatRequest{Model: "m", Messages: []ChatMessage{{Role: "user", Content: "t"}}}

	content, _, _, err := CallAIEndpoint(cfg, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if content != "no-auth" {
		t.Errorf("unexpected content: %q", content)
	}
}

func TestCallAIEndpoint_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(429)
		fmt.Fprint(w, `{"error":"rate limited"}`)
	}))
	defer srv.Close()

	cfg := AIConfig{Endpoint: srv.URL, Key: "k", Model: "m", Timeout: 5 * time.Second}
	req := ChatRequest{Model: "m", Messages: []ChatMessage{{Role: "user", Content: "t"}}}

	_, status, _, err := CallAIEndpoint(cfg, req)
	if err == nil {
		t.Fatal("expected error for 429 response")
	}
	if status != 429 {
		t.Errorf("expected status 429, got %d", status)
	}
}

func TestCallAIEndpoint_EmptyChoices(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"choices":[]}`)
	}))
	defer srv.Close()

	cfg := AIConfig{Endpoint: srv.URL, Key: "k", Model: "m", Timeout: 5 * time.Second}
	req := ChatRequest{Model: "m", Messages: []ChatMessage{{Role: "user", Content: "t"}}}

	_, _, _, err := CallAIEndpoint(cfg, req)
	if err == nil {
		t.Fatal("expected error for empty choices")
	}
	if !strings.Contains(err.Error(), "empty response choices") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestCallAIEndpoint_MalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `not valid json`)
	}))
	defer srv.Close()

	cfg := AIConfig{Endpoint: srv.URL, Key: "k", Model: "m", Timeout: 5 * time.Second}
	req := ChatRequest{Model: "m", Messages: []ChatMessage{{Role: "user", Content: "t"}}}

	_, _, _, err := CallAIEndpoint(cfg, req)
	if err == nil {
		t.Fatal("expected error for malformed JSON")
	}
	if !strings.Contains(err.Error(), "parse API response") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestCallAIEndpoint_InvalidURL(t *testing.T) {
	cfg := AIConfig{Endpoint: "ftp://invalid-scheme.com", Key: "k", Model: "m", Timeout: 5 * time.Second}
	req := ChatRequest{Model: "m", Messages: []ChatMessage{{Role: "user", Content: "t"}}}

	_, _, _, err := CallAIEndpoint(cfg, req)
	if err == nil {
		t.Fatal("expected error for invalid URL scheme")
	}
	if !strings.Contains(err.Error(), "http or https") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestCallAIEndpoint_Timeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(500 * time.Millisecond)
		fmt.Fprint(w, `{"choices":[{"message":{"content":"slow"}}]}`)
	}))
	defer srv.Close()

	cfg := AIConfig{Endpoint: srv.URL, Key: "k", Model: "m", Timeout: 50 * time.Millisecond}
	req := ChatRequest{Model: "m", Messages: []ChatMessage{{Role: "user", Content: "t"}}}

	_, status, _, err := CallAIEndpoint(cfg, req)
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if status != 408 {
		t.Errorf("expected status 408 for timeout, got %d", status)
	}
}

// ---------------------------------------------------------------------------
// ProcessWithRetriesAndFailover
// ---------------------------------------------------------------------------

func TestProcessWithRetriesAndFailover_PrimarySuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"choices":[{"message":{"content":"primary ok"}}]}`)
	}))
	defer srv.Close()

	primary := AIConfig{Endpoint: srv.URL, Key: "k", Model: "m", Timeout: 5 * time.Second}
	fallback := AIConfig{} // empty, should not be used

	req := ChatRequest{Model: "m", Messages: []ChatMessage{{Role: "user", Content: "t"}}}
	content, tier, err := ProcessWithRetriesAndFailover(primary, fallback, 2, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tier != "Primary" {
		t.Errorf("expected tier Primary, got %s", tier)
	}
	if content != "primary ok" {
		t.Errorf("unexpected content: %q", content)
	}
}

func TestProcessWithRetriesAndFailover_FallbackOnPrimaryFailure(t *testing.T) {
	primarySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(503)
		fmt.Fprint(w, `{"error":"service unavailable"}`)
	}))
	defer primarySrv.Close()

	fallbackSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"choices":[{"message":{"content":"fallback ok"}}]}`)
	}))
	defer fallbackSrv.Close()

	primary := AIConfig{Endpoint: primarySrv.URL, Key: "k", Model: "m", Timeout: 5 * time.Second}
	fallback := AIConfig{Endpoint: fallbackSrv.URL, Key: "k2", Model: "m2", Timeout: 5 * time.Second}

	req := ChatRequest{Model: "m", Messages: []ChatMessage{{Role: "user", Content: "t"}}}
	content, tier, err := ProcessWithRetriesAndFailover(primary, fallback, 1, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tier != "Fallback" {
		t.Errorf("expected tier Fallback, got %s", tier)
	}
	if content != "fallback ok" {
		t.Errorf("unexpected content: %q", content)
	}
}

func TestProcessWithRetriesAndFailover_AllTiersFail(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
		fmt.Fprint(w, `{"error":"internal server error"}`)
	}))
	defer srv.Close()

	primary := AIConfig{Endpoint: srv.URL, Key: "k", Model: "m", Timeout: 5 * time.Second}
	fallback := AIConfig{Endpoint: srv.URL, Key: "k2", Model: "m2", Timeout: 5 * time.Second}

	req := ChatRequest{Model: "m", Messages: []ChatMessage{{Role: "user", Content: "t"}}}
	_, _, err := ProcessWithRetriesAndFailover(primary, fallback, 1, req)
	if err == nil {
		t.Fatal("expected error when all tiers fail")
	}
	if !strings.Contains(err.Error(), "all AI engine tiers failed") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestProcessWithRetriesAndFailover_BothEmpty(t *testing.T) {
	primary := AIConfig{}
	fallback := AIConfig{}

	req := ChatRequest{Model: "m", Messages: []ChatMessage{{Role: "user", Content: "t"}}}
	_, _, err := ProcessWithRetriesAndFailover(primary, fallback, 2, req)
	if err == nil {
		t.Fatal("expected error when both endpoints empty")
	}
}

func TestProcessWithRetriesAndFailover_RateLimitHeaders(t *testing.T) {
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("X-RateLimit-Remaining", "50")
		w.Header().Set("X-RateLimit-Limit", "100")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"choices":[{"message":{"content":"with headers"}}]}`)
	}))
	defer srv.Close()

	primary := AIConfig{Endpoint: srv.URL, Key: "k", Model: "m", Timeout: 5 * time.Second}
	req := ChatRequest{Model: "m", Messages: []ChatMessage{{Role: "user", Content: "t"}}}

	content, _, err := ProcessWithRetriesAndFailover(primary, AIConfig{}, 2, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if content != "with headers" {
		t.Errorf("unexpected content: %q", content)
	}
	if callCount != 1 {
		t.Errorf("expected 1 call, got %d", callCount)
	}
}

// ---------------------------------------------------------------------------
// Additional table-driven error path coverage tests
// ---------------------------------------------------------------------------

func TestParseWorkspace_TableDriven(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{"non_existent_file", "non_existent_file_that_does_not_exist.yaml", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseWorkspace(tt.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseWorkspace() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestCallAIEndpoint_TableDriven(t *testing.T) {
	tests := []struct {
		name        string
		cfg         AIConfig
		req         ChatRequest
		wantErr     bool
		errContains string
	}{
		{
			name:        "invalid url parse",
			cfg:         AIConfig{Endpoint: "http://example.com\x00/path", Key: "k", Model: "m", Timeout: 5 * time.Second},
			req:         ChatRequest{Model: "m", Messages: []ChatMessage{{Role: "user", Content: "t"}}},
			wantErr:     true,
			errContains: "invalid endpoint URL",
		},
		{
			name:        "network connection refused",
			cfg:         AIConfig{Endpoint: "http://127.0.0.1:0", Key: "k", Model: "m", Timeout: 5 * time.Second},
			req:         ChatRequest{Model: "m", Messages: []ChatMessage{{Role: "user", Content: "t"}}},
			wantErr:     true,
			errContains: "http request failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, _, err := CallAIEndpoint(tt.cfg, tt.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("CallAIEndpoint() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil && tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
				t.Errorf("CallAIEndpoint() error = %v, want err to contain %q", err, tt.errContains)
			}
		})
	}
}

func TestProcessWithRetriesAndFailover_TableDrivenHeaders(t *testing.T) {
	tests := []struct {
		name        string
		setupServer func(w http.ResponseWriter, r *http.Request)
		wantContent string
		wantErr     bool
	}{
		{
			name: "retry with rate limit headers without limit",
			setupServer: func() func(w http.ResponseWriter, r *http.Request) {
				callCount := 0
				return func(w http.ResponseWriter, r *http.Request) {
					callCount++
					if callCount == 1 {
						w.Header().Set("Retry-After", "0")
						w.WriteHeader(429)
						fmt.Fprint(w, `{"error":"rate limited"}`)
						return
					}
					w.Header().Set("X-RateLimit-Remaining", "50")
					w.Header().Set("X-RateLimit-Reset", "1234567")
					// intentionally missing X-RateLimit-Limit
					w.Header().Set("Content-Type", "application/json")
					fmt.Fprint(w, `{"choices":[{"message":{"content":"success on retry"}}]}`)
				}
			}(),
			wantContent: "success on retry",
			wantErr:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(tt.setupServer))
			defer srv.Close()

			primary := AIConfig{Endpoint: srv.URL, Key: "k", Model: "m", Timeout: 5 * time.Second}
			req := ChatRequest{Model: "m", Messages: []ChatMessage{{Role: "user", Content: "t"}}}

			content, _, err := ProcessWithRetriesAndFailover(primary, AIConfig{}, 2, req)
			if (err != nil) != tt.wantErr {
				t.Errorf("ProcessWithRetriesAndFailover() error = %v, wantErr %v", err, tt.wantErr)
			}
			if content != tt.wantContent {
				t.Errorf("ProcessWithRetriesAndFailover() content = %q, want %q", content, tt.wantContent)
			}
		})
	}
}
