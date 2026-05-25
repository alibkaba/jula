package universal_rest

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

// mockRoundTripper implements http.RoundTripper for testing
type mockRoundTripper struct {
	roundTripFunc func(req *http.Request) (*http.Response, error)
}

func (m *mockRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return m.roundTripFunc(req)
}

func TestSignAzureIdentity(t *testing.T) {
	// Save and restore original http.DefaultClient.Transport
	originalTransport := http.DefaultClient.Transport
	defer func() {
		http.DefaultClient.Transport = originalTransport
	}()

	// Helper to clear environment variables and cache before each test
	setupTest := func() {
		os.Unsetenv("AZURE_TENANT_ID")
		os.Unsetenv("AZURE_CLIENT_ID")
		os.Unsetenv("AZURE_CLIENT_SECRET")

		globalAzureCache.mu.Lock()
		globalAzureCache.token = ""
		globalAzureCache.expiresAt = time.Time{}
		globalAzureCache.mu.Unlock()
	}

	tests := []struct {
		name          string
		setupEnv      func()
		setupCache    func()
		mockTransport func(req *http.Request) (*http.Response, error)
		wantErr       bool
		wantAuth      string
	}{
		{
			name: "cache hit",
			setupEnv: func() {
				// Env vars shouldn't matter if cache hits
				os.Setenv("AZURE_TENANT_ID", "test-tenant")
				os.Setenv("AZURE_CLIENT_ID", "test-client")
				os.Setenv("AZURE_CLIENT_SECRET", "test-secret")
			},
			setupCache: func() {
				globalAzureCache.mu.Lock()
				globalAzureCache.token = "cached-token"
				globalAzureCache.expiresAt = time.Now().Add(2 * time.Hour)
				globalAzureCache.mu.Unlock()
			},
			mockTransport: func(req *http.Request) (*http.Response, error) {
				t.Fatal("network should not be called on cache hit")
				return nil, nil
			},
			wantErr:  false,
			wantAuth: "Bearer cached-token",
		},
		{
			name: "service principal flow - success",
			setupEnv: func() {
				os.Setenv("AZURE_TENANT_ID", "test-tenant")
				os.Setenv("AZURE_CLIENT_ID", "test-client")
				os.Setenv("AZURE_CLIENT_SECRET", "test-secret")
			},
			setupCache: func() {},
			mockTransport: func(req *http.Request) (*http.Response, error) {
				if !strings.Contains(req.URL.String(), "test-tenant") {
					t.Errorf("expected tenant ID in URL, got %s", req.URL.String())
				}
				body := `{"access_token": "sp-token", "expires_in": 3600}`
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewBufferString(body)),
				}, nil
			},
			wantErr:  false,
			wantAuth: "Bearer sp-token",
		},
		{
			name: "service principal flow - network error",
			setupEnv: func() {
				os.Setenv("AZURE_TENANT_ID", "test-tenant")
				os.Setenv("AZURE_CLIENT_ID", "test-client")
				os.Setenv("AZURE_CLIENT_SECRET", "test-secret")
			},
			setupCache: func() {},
			mockTransport: func(req *http.Request) (*http.Response, error) {
				return nil, os.ErrDeadlineExceeded
			},
			wantErr: true,
		},
		{
			name: "service principal flow - bad status code",
			setupEnv: func() {
				os.Setenv("AZURE_TENANT_ID", "test-tenant")
				os.Setenv("AZURE_CLIENT_ID", "test-client")
				os.Setenv("AZURE_CLIENT_SECRET", "test-secret")
			},
			setupCache: func() {},
			mockTransport: func(req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusUnauthorized,
					Body:       io.NopCloser(bytes.NewBufferString("unauthorized")),
				}, nil
			},
			wantErr: true,
		},
		{
			name: "service principal flow - invalid json",
			setupEnv: func() {
				os.Setenv("AZURE_TENANT_ID", "test-tenant")
				os.Setenv("AZURE_CLIENT_ID", "test-client")
				os.Setenv("AZURE_CLIENT_SECRET", "test-secret")
			},
			setupCache: func() {},
			mockTransport: func(req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewBufferString("invalid json")),
				}, nil
			},
			wantErr: true,
		},
		{
			name: "imds flow - success float expiration",
			setupEnv: func() {
				// Missing env vars falls back to IMDS
			},
			setupCache: func() {},
			mockTransport: func(req *http.Request) (*http.Response, error) {
				if req.Header.Get("Metadata") != "true" {
					t.Errorf("expected Metadata header to be true")
				}
				body := `{"access_token": "imds-token", "expires_in": 3600.0}`
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewBufferString(body)),
				}, nil
			},
			wantErr:  false,
			wantAuth: "Bearer imds-token",
		},
		{
			name: "imds flow - success string expiration",
			setupEnv: func() {
			},
			setupCache: func() {},
			mockTransport: func(req *http.Request) (*http.Response, error) {
				body := `{"access_token": "imds-token", "expires_in": "3600"}`
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewBufferString(body)),
				}, nil
			},
			wantErr:  false,
			wantAuth: "Bearer imds-token",
		},
		{
			name: "imds flow - success default expiration",
			setupEnv: func() {
			},
			setupCache: func() {},
			mockTransport: func(req *http.Request) (*http.Response, error) {
				body := `{"access_token": "imds-token"}`
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewBufferString(body)),
				}, nil
			},
			wantErr:  false,
			wantAuth: "Bearer imds-token",
		},
		{
			name: "imds flow - missing token",
			setupEnv: func() {
			},
			setupCache: func() {},
			mockTransport: func(req *http.Request) (*http.Response, error) {
				body := `{"expires_in": 3600}`
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewBufferString(body)),
				}, nil
			},
			wantErr: true,
		},
		{
			name: "imds flow - network error",
			setupEnv: func() {
			},
			setupCache: func() {},
			mockTransport: func(req *http.Request) (*http.Response, error) {
				return nil, os.ErrDeadlineExceeded
			},
			wantErr: true,
		},
		{
			name: "imds flow - bad status code",
			setupEnv: func() {
			},
			setupCache: func() {},
			mockTransport: func(req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusNotFound,
					Body:       io.NopCloser(bytes.NewBufferString("not found")),
				}, nil
			},
			wantErr: true,
		},
		{
			name: "imds flow - invalid json",
			setupEnv: func() {
			},
			setupCache: func() {},
			mockTransport: func(req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewBufferString("invalid json")),
				}, nil
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setupTest()
			tt.setupEnv()
			tt.setupCache()

			http.DefaultClient.Transport = &mockRoundTripper{
				roundTripFunc: tt.mockTransport,
			}

			req, _ := http.NewRequest("GET", "https://management.azure.com", nil)
			err := SignAzureIdentity(context.Background(), req)

			if (err != nil) != tt.wantErr {
				t.Errorf("SignAzureIdentity() error = %v, wantErr %v", err, tt.wantErr)
			}

			if !tt.wantErr {
				auth := req.Header.Get("Authorization")
				if auth != tt.wantAuth {
					t.Errorf("SignAzureIdentity() auth = %v, want %v", auth, tt.wantAuth)
				}
			}
		})
	}
}
