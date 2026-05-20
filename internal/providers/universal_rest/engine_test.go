package universal_rest

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestCleanPath(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{
			input:    "/issues/export?format=json&filter_status=open",
			expected: "/issues/export?format=json&filter_status=open",
		},
		{
			input:    "/issues/export?format=json&filter_status=open&jula_erl=E-MNT-03",
			expected: "/issues/export?format=json&filter_status=open",
		},
		{
			input:    "/issues/export?jula_erl=E-MNT-03&format=json",
			expected: "/issues/export?format=json",
		},
		{
			input:    "/issues/export?jula_erl=E-MNT-03",
			expected: "/issues/export",
		},
	}

	for _, tc := range tests {
		got := CleanPath(tc.input)
		if got != tc.expected {
			t.Errorf("CleanPath(%q) = %q, expected %q", tc.input, got, tc.expected)
		}
	}
}

func TestInterpolateEnvVars(t *testing.T) {
	t.Setenv("TEST_VAR", "hello")
	t.Setenv("TEST_SPACE", "hello world")

	// Escape = false (for headers, URLs, etc)
	got1 := InterpolateEnvVars("prefix-${TEST_VAR}-suffix", false)
	if got1 != "prefix-hello-suffix" {
		t.Errorf("expected prefix-hello-suffix, got %q", got1)
	}

	// Escape = true (for path params)
	got2 := InterpolateEnvVars("/path/${TEST_SPACE}", true)
	if got2 != "/path/hello%20world" {
		t.Errorf("expected /path/hello%%20world, got %q", got2)
	}
}

func TestEngine_Execute_BearerSuccess(t *testing.T) {
	t.Setenv("TEST_GITHUB_TOKEN", "super-secret-token")
	defer os.Unsetenv("TEST_GITHUB_TOKEN")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("expected GET method, got %q", r.Method)
		}
		if r.URL.Path != "/repos/org/repo" {
			t.Errorf("expected path /repos/org/repo, got %q", r.URL.Path)
		}
		auth := r.Header.Get("Authorization")
		if auth != "Bearer super-secret-token" {
			t.Errorf("expected Authorization Bearer super-secret-token, got %q", auth)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"name":"repo-metadata"}`))
	}))
	defer server.Close()

	bp := &OpenAPIBlueprint{
		VendorName: "github",
		BaseURL:    server.URL,
		AuthFlow: AuthFlowConfig{
			Type:     "bearer",
			TokenEnv: "TEST_GITHUB_TOKEN",
		},
	}

	ep := EndpointConfig{
		ErlID:       "E-CHG-01",
		Description: "GitHub Repository Metadata",
	}

	engine := NewEngine(server.Client())
	findings, err := engine.Execute(context.Background(), bp, "/repos/org/repo", ep, "run-1")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	f := findings[0]
	if f.ErlID != "E-CHG-01" {
		t.Errorf("expected ErlID E-CHG-01, got %q", f.ErlID)
	}
	if f.Provider != "github" {
		t.Errorf("expected Provider github, got %q", f.Provider)
	}
	if string(f.RawData) != `{"name":"repo-metadata"}` {
		t.Errorf("expected raw data body, got %q", string(f.RawData))
	}
}

func TestEngine_Execute_OAuth2Success(t *testing.T) {
	t.Setenv("TEST_CLIENT_ID", "client-id-value")
	t.Setenv("TEST_SECRET_KEY", "secret-key-value")
	defer os.Unsetenv("TEST_CLIENT_ID")
	defer os.Unsetenv("TEST_SECRET_KEY")

	var authExchangeCalled bool
	var dataExchangeCalled bool

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			authExchangeCalled = true
			if r.Method != http.MethodPost {
				t.Errorf("expected POST to token URL, got %q", r.Method)
			}
			auth := r.Header.Get("Authorization")
			expectedAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("client-id-value:secret-key-value"))
			if auth != expectedAuth {
				t.Errorf("expected basic auth header %q, got %q", expectedAuth, auth)
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"access_token":"oauth-token-val"}`))
			return
		}

		if r.URL.Path == "/issues" {
			dataExchangeCalled = true
			if r.Method != http.MethodGet {
				t.Errorf("expected GET to data URL, got %q", r.Method)
			}
			auth := r.Header.Get("Authorization")
			if auth != "Bearer oauth-token-val" {
				t.Errorf("expected bearer auth header, got %q", auth)
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"issues":[]}`))
			return
		}

		t.Errorf("unexpected path requested: %q", r.URL.Path)
	}))
	defer server.Close()

	bp := &OpenAPIBlueprint{
		VendorName: "aikido",
		BaseURL:    server.URL,
		AuthFlow: AuthFlowConfig{
			Type:            "oauth2",
			TokenURL:        server.URL + "/oauth/token",
			ClientIDEnv:     "TEST_CLIENT_ID",
			ClientSecretEnv: "TEST_SECRET_KEY",
		},
	}

	ep := EndpointConfig{
		ErlID:       "E-MNT-03",
		Description: "Aikido Issues",
	}

	engine := NewEngine(server.Client())
	findings, err := engine.Execute(context.Background(), bp, "/issues", ep, "run-1")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if !authExchangeCalled {
		t.Error("expected oauth exchange endpoint to be called")
	}
	if !dataExchangeCalled {
		t.Error("expected data endpoint to be called")
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if string(findings[0].RawData) != `{"issues":[]}` {
		t.Errorf("unexpected payload: %s", string(findings[0].RawData))
	}
}

func TestEngine_Execute_LinkHeaderPagination(t *testing.T) {
	t.Setenv("TEST_TOKEN", "dummy")
	defer os.Unsetenv("TEST_TOKEN")

	var requestsReceived int
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestsReceived++
		w.Header().Set("Content-Type", "application/json")

		if requestsReceived == 1 {
			w.Header().Set("Link", `<`+server.URL+`/repos/issues?page=2>; rel="next"`)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`[{"id": 1}]`))
			return
		}

		if requestsReceived == 2 {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`[{"id": 2}]`))
			return
		}

		t.Errorf("unexpected request %d to page url %q", requestsReceived, r.URL.String())
	}))
	defer server.Close()

	bp := &OpenAPIBlueprint{
		VendorName: "github",
		BaseURL:    server.URL,
		AuthFlow: AuthFlowConfig{
			Type:     "bearer",
			TokenEnv: "TEST_TOKEN",
		},
	}

	ep := EndpointConfig{
		ErlID:       "E-CHG-03",
		Description: "GitHub Paginated Issues",
		Pagination: &PaginationConfig{
			NextURLField: "header.Link",
			MaxPages:     5,
		},
	}

	engine := NewEngine(server.Client())
	findings, err := engine.Execute(context.Background(), bp, "/repos/issues", ep, "run-1")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if requestsReceived != 2 {
		t.Errorf("expected 2 page requests, got %d", requestsReceived)
	}

	if len(findings) != 2 {
		t.Fatalf("expected 2 findings (one per page), got %d", len(findings))
	}

	if string(findings[0].RawData) != `[{"id": 1}]` {
		t.Errorf("expected page 1 finding to match raw payload, got %q", string(findings[0].RawData))
	}
	if string(findings[1].RawData) != `[{"id": 2}]` {
		t.Errorf("expected page 2 finding to match raw payload, got %q", string(findings[1].RawData))
	}
}

func TestEngine_Execute_JSONPathPagination(t *testing.T) {
	t.Setenv("TEST_TOKEN", "dummy")
	defer os.Unsetenv("TEST_TOKEN")

	var requestsReceived int
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestsReceived++
		w.Header().Set("Content-Type", "application/json")

		if requestsReceived == 1 {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"data": [1,2], "pagination": {"next": "/items?cursor=xyz"}}`))
			return
		}

		if requestsReceived == 2 {
			if r.URL.Query().Get("cursor") != "xyz" {
				t.Errorf("expected cursor query param value 'xyz', got %q", r.URL.RawQuery)
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"data": [3,4]}`))
			return
		}

		t.Errorf("unexpected request %d to url %q", requestsReceived, r.URL.String())
	}))
	defer server.Close()

	bp := &OpenAPIBlueprint{
		VendorName: "generic",
		BaseURL:    server.URL,
		AuthFlow: AuthFlowConfig{
			Type:     "bearer",
			TokenEnv: "TEST_TOKEN",
		},
	}

	ep := EndpointConfig{
		ErlID:       "E-VPM-01",
		Description: "JSON Path Paginated Endpoint",
		Pagination: &PaginationConfig{
			NextURLField: "pagination.next",
			MaxPages:     3,
		},
	}

	engine := NewEngine(server.Client())
	findings, err := engine.Execute(context.Background(), bp, "/items", ep, "run-1")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if requestsReceived != 2 {
		t.Errorf("expected 2 requests, got %d", requestsReceived)
	}

	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}

	// Verify the pagination token extraction resolved the relative URL correctly against BaseURL/currentURL
	var page2 struct {
		Data []int `json:"data"`
	}
	if err := json.Unmarshal(findings[1].RawData, &page2); err != nil {
		t.Fatalf("failed to unmarshal page 2 raw data: %v", err)
	}
	if len(page2.Data) != 2 || page2.Data[0] != 3 {
		t.Errorf("unexpected page 2 contents: %s", string(findings[1].RawData))
	}
}

func TestEngine_Execute_404Allowed(t *testing.T) {
	t.Setenv("TEST_TOKEN", "dummy")
	defer os.Unsetenv("TEST_TOKEN")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	bp := &OpenAPIBlueprint{
		VendorName: "generic",
		BaseURL:    server.URL,
		AuthFlow: AuthFlowConfig{
			Type:     "bearer",
			TokenEnv: "TEST_TOKEN",
		},
	}

	ep := EndpointConfig{
		ErlID:       "E-CHG-04",
		Description: "CODEOWNERS file (optional)",
		Allow404:    true,
	}

	engine := NewEngine(server.Client())
	findings, err := engine.Execute(context.Background(), bp, "/CODEOWNERS", ep, "run-1")
	if err != nil {
		t.Fatalf("expected 404 to be swallowed, but got error: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	if string(findings[0].RawData) != "null" {
		t.Errorf("expected raw data for allowed 404 to be 'null', got %q", string(findings[0].RawData))
	}
}

func TestEngine_Execute_StrictPaginationEnforcement(t *testing.T) {
	t.Setenv("TEST_TOKEN", "dummy")
	defer os.Unsetenv("TEST_TOKEN")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Link", `<https://api.example.com/items?page=2>; rel="next"`)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[]`))
	}))
	defer server.Close()

	bp := &OpenAPIBlueprint{
		VendorName: "generic",
		BaseURL:    server.URL,
		AuthFlow: AuthFlowConfig{
			Type:     "bearer",
			TokenEnv: "TEST_TOKEN",
		},
	}

	ep := EndpointConfig{
		ErlID:       "E-TEST-STRICT",
		Description: "No pagination instructions",
	}

	engine := NewEngine(server.Client())
	_, err := engine.Execute(context.Background(), bp, "/items", ep, "run-1")
	if err == nil {
		t.Fatal("expected error due to strict pagination enforcement, got nil")
	}
}
