package httpgeneric

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
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

func TestInterpolateEnvVars_MultipleVars(t *testing.T) {
	os.Setenv("TEST_USER_ABC", "admin")
	os.Setenv("TEST_PASS_ABC", "secret")
	defer os.Unsetenv("TEST_USER_ABC")
	defer os.Unsetenv("TEST_PASS_ABC")

	input := "${TEST_USER_ABC}:${TEST_PASS_ABC}"
	got := InterpolateEnvVars(input)
	expected := "admin:secret"

	if got != expected {
		t.Errorf("expected %q, got %q", expected, got)
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

func TestLoadSaaSConfigs_ValidFile(t *testing.T) {
	tmpFile := t.TempDir() + "/saas_http.json"
	data := `{
		"E-VUL-01": {
			"description": "Aikido Vulnerability Scan",
			"provider": "aikido",
			"method": "GET",
			"url": "https://app.aikido.dev/api/public/v1/issues/export",
			"headers": {"Authorization": "Bearer ${AIK_TOKEN}"},
			"json_path": "$"
		}
	}`

	if err := os.WriteFile(tmpFile, []byte(data), 0644); err != nil {
		t.Fatal(err)
	}

	configs, err := LoadSaaSConfigs(tmpFile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(configs) != 1 {
		t.Fatalf("expected 1 config, got %d", len(configs))
	}

	cfg, exists := configs["E-VUL-01"]
	if !exists {
		t.Fatal("expected E-VUL-01 in configs")
	}
	if cfg.Provider != "aikido" {
		t.Errorf("expected provider aikido, got %s", cfg.Provider)
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
