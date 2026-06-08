package reporter

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
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

// TestMetadataTokenProvider_Negative tests error paths for GCP token retrieval.
func TestMetadataTokenProvider_Negative(t *testing.T) {
	tests := []struct {
		name           string
		handler        http.HandlerFunc
		expectedErrStr string
	}{
		{
			name: "HTTP 500 Internal Server Error",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte("server error"))
			},
			expectedErrStr: "metadata server returned HTTP 500",
		},
		{
			name: "Malformed JSON Response",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				// expires_in should be an int, passing a string causes unmarshal error
				w.Write([]byte(`{"access_token": "token", "expires_in": "not-an-int"}`))
			},
			expectedErrStr: "parsing metadata token",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ts := httptest.NewServer(tc.handler)
			defer ts.Close()

			provider := &metadataTokenProvider{
				httpClient: ts.Client(),
				baseURL:    ts.URL,
			}

			_, err := provider.Token()
			if err == nil || !strings.Contains(err.Error(), tc.expectedErrStr) {
				t.Errorf("expected error containing %q, got: %v", tc.expectedErrStr, err)
			}
		})
	}

	t.Run("Network Timeout / Connection Refused", func(t *testing.T) {
		provider := &metadataTokenProvider{
			httpClient: &http.Client{Timeout: 1 * time.Millisecond},
			baseURL:    "http://127.0.0.1:12345", // Assumed closed port to force failure
		}
		_, err := provider.Token()
		if err == nil || !strings.Contains(err.Error(), "metadata server request failed") {
			t.Errorf("expected request failure, got: %v", err)
		}
	})
}
