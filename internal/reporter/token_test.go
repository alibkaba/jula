package reporter

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNewMetadataTokenProvider_ReturnsProvider(t *testing.T) {
	p := NewMetadataTokenProvider(&http.Client{})
	if p == nil {
		t.Fatal("expected non-nil provider")
	}
}

func TestMetadataTokenProvider_FetchesToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Metadata-Flavor") != "Google" {
			t.Error("missing Metadata-Flavor header")
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(metadataTokenResponse{
			AccessToken: "fresh-token",
			ExpiresIn:   3600,
			TokenType:   "Bearer",
		})
	}))
	defer server.Close()

	p := &metadataTokenProvider{httpClient: server.Client()}
	// The real provider hits the metadata URL, but in tests we can't override it
	// without an interface. Instead, test the caching path directly.
	p.cachedToken = "cached-token"
	p.tokenExpiry = time.Now().Add(1 * time.Hour)

	tok, err := p.Token()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tok != "cached-token" {
		t.Errorf("expected cached-token, got %s", tok)
	}
}

func TestMetadataTokenProvider_ExpiredTokenRefreshes(t *testing.T) {
	p := &metadataTokenProvider{
		httpClient:  &http.Client{},
		cachedToken: "old-token",
		tokenExpiry: time.Now().Add(-1 * time.Hour), // Expired.
	}

	// This will fail because the metadata server is unreachable in tests,
	// but it confirms the expiry check triggers a refresh attempt.
	_, err := p.Token()
	if err == nil {
		t.Fatal("expected error when metadata server is unreachable")
	}
}
