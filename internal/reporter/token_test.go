package reporter

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMetadataTokenProvider_Token(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Metadata-Flavor") != "Google" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		resp := metadataTokenResponse{
			AccessToken: "fake-token",
			ExpiresIn:   3600,
			TokenType:   "Bearer",
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	p := &metadataTokenProvider{
		httpClient: server.Client(),
		baseURL:    server.URL,
	}

	token, err := p.Token()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token != "fake-token" {
		t.Errorf("expected fake-token, got %s", token)
	}
}

func TestMetadataTokenProvider_Error(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	p := &metadataTokenProvider{
		httpClient: server.Client(),
		baseURL:    server.URL,
	}

	_, err := p.Token()
	if err == nil {
		t.Fatal("expected error for 500 response")
	}
}

func TestNewMetadataTokenProvider(t *testing.T) {
	p := NewMetadataTokenProvider(nil)
	if p == nil {
		t.Fatal("expected non-nil provider")
	}
}

func TestMetadataTokenProvider_Cache(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		resp := metadataTokenResponse{
			AccessToken: fmt.Sprintf("token-%d", callCount),
			ExpiresIn:   3600,
			TokenType:   "Bearer",
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	p := &metadataTokenProvider{
		httpClient: server.Client(),
		baseURL:    server.URL,
	}

	t1, _ := p.Token()
	t2, _ := p.Token()

	if t1 != t2 {
		t.Errorf("expected cached token, got %s and %s", t1, t2)
	}
	if callCount != 1 {
		t.Errorf("expected 1 call to metadata server, got %d", callCount)
	}
}
