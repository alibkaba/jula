package httpgeneric

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestInterpolateEnvVars_ReplacesKnownVars(t *testing.T) {
	os.Setenv("TEST_TOKEN_ABC", "my-secret-token")
	defer os.Unsetenv("TEST_TOKEN_ABC")

	input := "Bearer ${TEST_TOKEN_ABC}"
	got := InterpolateEnvVars(input)
	expected := "Bearer my-secret-token"

	if got != expected {
		t.Errorf("expected %q, got %q", expected, got)
	}
}

func TestInterpolateEnvVars_LeavesUnknownVars(t *testing.T) {
	input := "Bearer ${NONEXISTENT_VAR_XYZ}"
	got := InterpolateEnvVars(input)

	if got != input {
		t.Errorf("expected unresolved var to be preserved, got %q", got)
	}
}

func TestEngine_Extract_SinglePage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Errorf("expected auth header, got %q", r.Header.Get("Authorization"))
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "ok", "data": "hello"})
	}))
	defer server.Close()

	os.Setenv("TEST_HTTP_TOKEN", "test-token")
	defer os.Unsetenv("TEST_HTTP_TOKEN")

	engine := NewEngineWithClient(server.Client())

	cfg := ExtractionConfig{
		Description: "Test extraction",
		Provider:    "test_saas",
		Method:      "GET",
		URL:         server.URL + "/api/v1/data",
		Headers: map[string]string{
			"Authorization": "Bearer ${TEST_HTTP_TOKEN}",
		},
		JSONPath: "$",
	}

	finding, err := engine.Extract(context.Background(), "E-TEST-01", cfg, "test-run")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if finding.ErlID != "E-TEST-01" {
		t.Errorf("expected ERL ID E-TEST-01, got %s", finding.ErlID)
	}
	if finding.Provider != "test_saas" {
		t.Errorf("expected provider test_saas, got %s", finding.Provider)
	}
	if len(finding.RawData) == 0 {
		t.Error("expected non-empty raw data")
	}
}

func TestEngine_Extract_UnresolvedEnvVar(t *testing.T) {
	engine := NewEngine()

	cfg := ExtractionConfig{
		Description: "Should fail",
		Provider:    "test",
		Method:      "GET",
		URL:         "https://example.com/api",
		Headers: map[string]string{
			"Authorization": "Bearer ${DEFINITELY_NOT_SET_XYZ_123}",
		},
	}

	_, err := engine.Extract(context.Background(), "E-FAIL-01", cfg, "test-run")
	if err == nil {
		t.Fatal("expected error for unresolved env var in header")
	}
}

func TestEngine_Extract_HTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("access denied"))
	}))
	defer server.Close()

	engine := NewEngineWithClient(server.Client())

	cfg := ExtractionConfig{
		Provider: "test",
		Method:   "GET",
		URL:      server.URL + "/forbidden",
	}

	_, err := engine.Extract(context.Background(), "E-ERR-01", cfg, "test-run")
	if err == nil {
		t.Fatal("expected error for 403 response")
	}
}

func TestEngine_Extract_Paginated(t *testing.T) {
	page := 0
	var serverURL string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		page++
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		switch page {
		case 1:
			// First page: return items and a next URL.
			json.NewEncoder(w).Encode(map[string]any{
				"items": []map[string]string{{"id": "1"}, {"id": "2"}},
				"links": map[string]string{"next": serverURL + "/api?page=2"},
			})
		case 2:
			// Second page: return items, no next.
			json.NewEncoder(w).Encode(map[string]any{
				"items": []map[string]string{{"id": "3"}},
				"links": map[string]string{},
			})
		default:
			t.Errorf("unexpected page request: %d", page)
		}
	}))
	defer server.Close()
	serverURL = server.URL

	engine := NewEngineWithClient(server.Client())

	cfg := ExtractionConfig{
		Provider: "test",
		Method:   "GET",
		URL:      server.URL + "/api?page=1",
		Pagination: &PaginationConfig{
			NextURLField: "links.next",
			MaxPages:     10,
		},
	}

	finding, err := engine.Extract(context.Background(), "E-PAGE-01", cfg, "test-run")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(finding.RawData) == 0 {
		t.Fatal("expected non-empty raw data from paginated extraction")
	}

	// Should have collected 2 pages worth of data.
	if page != 2 {
		t.Errorf("expected 2 page fetches, got %d", page)
	}
}

func TestEngine_Extract_DefaultsToGET(t *testing.T) {
	var receivedMethod string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedMethod = r.Method
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{}`))
	}))
	defer server.Close()

	engine := NewEngineWithClient(server.Client())

	cfg := ExtractionConfig{
		Provider: "test",
		Method:   "", // Empty: should default to GET.
		URL:      server.URL,
	}

	_, err := engine.Extract(context.Background(), "E-DEF-01", cfg, "test-run")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if receivedMethod != "GET" {
		t.Errorf("expected GET, got %s", receivedMethod)
	}
}

func TestExtractNextURL_SimplePath(t *testing.T) {
	body := json.RawMessage(`{"next": "https://example.com/page2"}`)
	url, found := extractNextURL(body, "next")
	if !found {
		t.Fatal("expected to find next URL")
	}
	if url != "https://example.com/page2" {
		t.Errorf("expected https://example.com/page2, got %s", url)
	}
}

func TestExtractNextURL_NestedPath(t *testing.T) {
	body := json.RawMessage(`{"links": {"next": "https://example.com/page3"}}`)
	url, found := extractNextURL(body, "links.next")
	if !found {
		t.Fatal("expected to find nested next URL")
	}
	if url != "https://example.com/page3" {
		t.Errorf("expected https://example.com/page3, got %s", url)
	}
}

func TestExtractNextURL_MissingField(t *testing.T) {
	body := json.RawMessage(`{"data": "no next here"}`)
	_, found := extractNextURL(body, "next")
	if found {
		t.Error("expected not to find next URL in missing field")
	}
}

func TestExtractNextURL_EmptyString(t *testing.T) {
	body := json.RawMessage(`{"next": ""}`)
	_, found := extractNextURL(body, "next")
	if found {
		t.Error("expected not to find next URL when value is empty")
	}
}

func TestEngine_Extract_ContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	engine := NewEngineWithClient(server.Client())

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	cfg := ExtractionConfig{
		Provider: "test",
		Method:   "GET",
		URL:      server.URL + "/slow",
	}

	_, err := engine.Extract(ctx, "E-CTX-01", cfg, "test-run")
	if err == nil {
		t.Fatal("expected error for cancelled context")
	}
}

func TestEngine_Extract_PaginationMaxPages(t *testing.T) {
	pageCount := 0
	var serverURL string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pageCount++
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		// Always return a next URL to test the safety valve.
		json.NewEncoder(w).Encode(map[string]any{
			"data": []string{fmt.Sprintf("item-%d", pageCount)},
			"next": serverURL + fmt.Sprintf("/api?page=%d", pageCount+1),
		})
	}))
	defer server.Close()
	serverURL = server.URL

	engine := NewEngineWithClient(server.Client())

	cfg := ExtractionConfig{
		Provider: "test",
		Method:   "GET",
		URL:      server.URL + "/api?page=1",
		Pagination: &PaginationConfig{
			NextURLField: "next",
			MaxPages:     3, // Should stop after 3 pages.
		},
	}

	_, err := engine.Extract(context.Background(), "E-MAX-01", cfg, "test-run")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if pageCount != 3 {
		t.Errorf("expected exactly 3 page fetches (max_pages), got %d", pageCount)
	}
}

// ---------------------------------------------------------------------------
// OAuth 2.0 Client Credentials Tests
// ---------------------------------------------------------------------------

func TestExtract_OAuthClientCredentials_Success(t *testing.T) {
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		auth := r.Header.Get("Authorization")
		if auth == "" {
			t.Error("expected Authorization header on token request")
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"access_token":"mock-jwt-token-12345"}`))
	}))
	defer tokenServer.Close()

	apiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth != "Bearer mock-jwt-token-12345" {
			t.Errorf("expected 'Bearer mock-jwt-token-12345', got %q", auth)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	}))
	defer apiServer.Close()

	t.Setenv("TEST_AIK_ID", "test-client-id")
	t.Setenv("TEST_AIK_SECRET", "test-client-secret")

	engine := NewEngine()
	cfg := ExtractionConfig{
		Description: "OAuth Test",
		Provider:    "aikido",
		Method:      "GET",
		URL:         apiServer.URL,
		Auth: &AuthConfig{
			Type:            "oauth2_client_credentials",
			TokenURL:        tokenServer.URL,
			ClientIDEnv:     "TEST_AIK_ID",
			ClientSecretEnv: "TEST_AIK_SECRET",
		},
	}

	finding, err := engine.Extract(context.Background(), "E-OAUTH-01", cfg, "test-run")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(finding.RawData) != `{"status":"ok"}` {
		t.Errorf("unexpected raw data: %s", string(finding.RawData))
	}
}

func TestExtract_OAuthClientCredentials_MissingCreds(t *testing.T) {
	t.Setenv("TEST_AIK_ID", "")
	t.Setenv("TEST_AIK_SECRET", "")

	engine := NewEngine()
	cfg := ExtractionConfig{
		Description: "OAuth Missing Creds",
		Provider:    "aikido",
		Method:      "GET",
		URL:         "https://example.com",
		Auth: &AuthConfig{
			Type:            "oauth2_client_credentials",
			TokenURL:        "https://example.com/token",
			ClientIDEnv:     "TEST_AIK_ID",
			ClientSecretEnv: "TEST_AIK_SECRET",
		},
	}

	_, err := engine.Extract(context.Background(), "E-OAUTH-02", cfg, "test-run")
	if err == nil {
		t.Fatal("expected error for missing credentials")
	}
}

// ---------------------------------------------------------------------------
// DRY Ingestion, Safety & Advanced Security Test Assertions
// ---------------------------------------------------------------------------

func TestLoadSaaSConfigs_ValidDRYLayout(t *testing.T) {
	tmpDir := t.TempDir()
	providersFile := filepath.Join(tmpDir, "providers.json")
	saasFile := filepath.Join(tmpDir, "saas_http.json")

	providersData := `{
		"github": {
			"base_url": "https://api.github.com",
			"headers": {
				"Authorization": "Bearer ${TEST_GITHUB_TOKEN}",
				"Accept": "application/vnd.github.v3+json"
			}
		}
	}`
	saasData := `{
		"E-CHG-01": {
			"description": "GitHub Repository Metadata",
			"provider": "github",
			"path": "/repos/${TEST_GITHUB_ORG}/${TEST_GITHUB_REPO}",
			"json_path": "$"
		}
	}`

	if err := os.WriteFile(providersFile, []byte(providersData), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(saasFile, []byte(saasData), 0644); err != nil {
		t.Fatal(err)
	}

	t.Setenv("TEST_GITHUB_TOKEN", "mock-token")
	t.Setenv("TEST_GITHUB_ORG", "my-org")
	t.Setenv("TEST_GITHUB_REPO", "my-repo")

	configs, err := LoadSaaSConfigs(saasFile)
	if err != nil {
		t.Fatalf("LoadSaaSConfigs failed: %v", err)
	}

	cfg, exists := configs["E-CHG-01"]
	if !exists {
		t.Fatal("expected E-CHG-01 to exist")
	}

	if cfg.Provider != "github" {
		t.Errorf("expected provider github, got %s", cfg.Provider)
	}
	if cfg.URL != "https://api.github.com/repos/my-org/my-repo" {
		t.Errorf("expected joined URL https://api.github.com/repos/my-org/my-repo, got %q", cfg.URL)
	}
	if cfg.Headers["Accept"] != "application/vnd.github.v3+json" {
		t.Errorf("expected Accept header, got %q", cfg.Headers["Accept"])
	}
}

func TestLoadSaaSConfigs_StrictReferentialIntegrityFailure(t *testing.T) {
	tmpDir := t.TempDir()
	providersFile := filepath.Join(tmpDir, "providers.json")
	saasFile := filepath.Join(tmpDir, "saas_http.json")

	providersData := `{"github": {"base_url": "https://api.github.com"}}`
	saasData := `{
		"E-ERR-02": {
			"description": "Referencing undefined provider",
			"provider": "nonexistent-provider-name",
			"path": "/issues",
			"json_path": "$"
		}
	}`

	if err := os.WriteFile(providersFile, []byte(providersData), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(saasFile, []byte(saasData), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := LoadSaaSConfigs(saasFile)
	if err == nil {
		t.Fatal("expected strict referential integrity failure, got nil error")
	}
	if !strings.Contains(err.Error(), "referential integrity violation") {
		t.Errorf("expected referential integrity error, got: %v", err)
	}
}

func TestLoadSaaSConfigs_PathTraversalSSRFPrevention(t *testing.T) {
	tmpDir := t.TempDir()
	providersFile := filepath.Join(tmpDir, "providers.json")
	saasFile := filepath.Join(tmpDir, "saas_http.json")

	providersData := `{"github": {"base_url": "https://api.github.com"}}`
	saasData := `{
		"E-TRAVERSAL": {
			"description": "Path Traversal SSRF Test",
			"provider": "github",
			"path": "/repos/${MALICIOUS_PARAM}/details",
			"json_path": "$"
		}
	}`

	if err := os.WriteFile(providersFile, []byte(providersData), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(saasFile, []byte(saasData), 0644); err != nil {
		t.Fatal(err)
	}

	// Dynamic parameter contains path traversal injection payload
	t.Setenv("MALICIOUS_PARAM", "../../victim-org/secret-repo")
	defer os.Unsetenv("MALICIOUS_PARAM")

	configs, err := LoadSaaSConfigs(saasFile)
	if err != nil {
		t.Fatalf("LoadSaaSConfigs failed: %v", err)
	}

	cfg := configs["E-TRAVERSAL"]
	// Assert that url.PathEscape converted "../../" into "%2F..%2F..%2F" safely neutralizing SSRF
	expectedPath := "..%2F..%2Fvictim-org%2Fsecret-repo"
	if !strings.Contains(cfg.URL, expectedPath) {
		t.Errorf("expected escaped SSRF payload %q in URL, got %q", expectedPath, cfg.URL)
	}
}

func TestCredentialMasking_LogsAndJSONSerialization(t *testing.T) {
	prov := ProviderConfig{
		BaseURL: "https://api.github.com",
		Headers: map[string]string{
			"Authorization": "Bearer super-secret-private-key-12345",
			"Content-Type":  "application/json",
		},
		Auth: &AuthConfig{
			Type:            "oauth2",
			TokenURL:        "https://api.github.com/token",
			ClientIDEnv:     "CLIENT_ID",
			ClientSecretEnv: "SUPER_SECRET_ENV_VAR_KEY_NAME",
		},
	}

	// 1. Assert custom MarshalJSON hides credentials from structured JSON loggers
	marshaledBytes, err := json.Marshal(prov)
	if err != nil {
		t.Fatalf("MarshalJSON failed: %v", err)
	}
	marshaledStr := string(marshaledBytes)

	if strings.Contains(marshaledStr, "super-secret-private-key-12345") {
		t.Error("structured JSON serialization leaked authorization bearer secret")
	}
	if strings.Contains(marshaledStr, "SUPER_SECRET_ENV_VAR_KEY_NAME") {
		t.Error("structured JSON serialization leaked client secret environment variable name")
	}
	if !strings.Contains(marshaledStr, "*REDACTED*") {
		t.Error("expected *REDACTED* placeholder in marshaled ProviderConfig output")
	}

	// 2. Assert custom Stringer hides credentials from standard log dumps
	stringerDump := fmt.Sprintf("%+v", prov)
	if strings.Contains(stringerDump, "super-secret-private-key-12345") {
		t.Error("Stringer struct dump leaked authorization bearer secret")
	}
}

func TestEngine_StrictPaginationEnforcementFailure(t *testing.T) {
	// Response contains a standard next-page Link header
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Link", `<https://api.github.com/repos/org/repo/commits?page=2>; rel="next"`)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"commits": []}`))
	}))
	defer server.Close()

	engine := NewEngineWithClient(server.Client())

	// ERL lacks active pagination settings
	cfg := ExtractionConfig{
		Provider: "github",
		Method:   "GET",
		URL:      server.URL,
	}

	_, err := engine.Extract(context.Background(), "E-STRICT-PAGINATION", cfg, "test-run")
	if err == nil {
		t.Fatal("expected strict pagination enforcement error but got success")
	}
	if !strings.Contains(err.Error(), "strict pagination enforcement") {
		t.Errorf("expected strict pagination error message, got: %v", err)
	}
}

func TestEngine_RateLimitBackoffAndRetrySuccess(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts == 1 {
			// First attempt returns HTTP 429 with standard Retry-After header of 1 second
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			w.Write([]byte(`{"error": "rate limit exceeded"}`))
			return
		}
		// Subsequent attempt succeeds
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"data": "success"}`))
	}))
	defer server.Close()

	engine := NewEngineWithClient(server.Client())
	cfg := ExtractionConfig{
		Provider: "github",
		Method:   "GET",
		URL:      server.URL,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	finding, err := engine.Extract(ctx, "E-RATE-LIMIT", cfg, "test-run")
	if err != nil {
		t.Fatalf("expected rate-limit retry to succeed, got error: %v", err)
	}

	if attempts != 2 {
		t.Errorf("expected exactly 2 attempts before success, got %d", attempts)
	}
	if string(finding.RawData) != `{"data": "success"}` {
		t.Errorf("unexpected raw data payload: %s", string(finding.RawData))
	}
}
