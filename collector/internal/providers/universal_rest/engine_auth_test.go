package universal_rest

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestEngine_applyAuth_Bearer(t *testing.T) {
	e := NewEngine(http.DefaultClient)
	ctx := context.Background()

	t.Run("missing token_env config", func(t *testing.T) {
		req, _ := http.NewRequestWithContext(ctx, "GET", "http://example.com", nil)
		auth := &AuthFlowConfig{Type: "bearer"}
		err := e.applyAuth(ctx, req, auth, nil)
		if err == nil || err.Error() != "bearer auth requires token_env to be configured" {
			t.Errorf("expected missing token_env error, got: %v", err)
		}
	})

	t.Run("missing token_env value", func(t *testing.T) {
		req, _ := http.NewRequestWithContext(ctx, "GET", "http://example.com", nil)
		auth := &AuthFlowConfig{Type: "bearer", TokenEnv: "MISSING_ENV_VAR"}
		err := e.applyAuth(ctx, req, auth, nil)
		if err == nil {
			t.Errorf("expected error when token env var is not set, got nil")
		}
	})
}

func TestEngine_applyAuth_OAuth2(t *testing.T) {
	e := NewEngine(http.DefaultClient)
	ctx := context.Background()

	t.Run("missing oauth config", func(t *testing.T) {
		req, _ := http.NewRequestWithContext(ctx, "GET", "http://example.com", nil)
		auth := &AuthFlowConfig{Type: "oauth2"}
		err := e.applyAuth(ctx, req, auth, nil)
		if err == nil || err.Error() != "oauth2 auth requires token_url, client_id_env, and client_secret_env to be configured" {
			t.Errorf("expected missing config error, got: %v", err)
		}
	})

	t.Run("missing env vars", func(t *testing.T) {
		req, _ := http.NewRequestWithContext(ctx, "GET", "http://example.com", nil)
		auth := &AuthFlowConfig{Type: "oauth2", TokenURL: "http://token", ClientIDEnv: "MISSING_CLIENT", ClientSecretEnv: "MISSING_SECRET"}
		err := e.applyAuth(ctx, req, auth, nil)
		if err == nil {
			t.Errorf("expected error when env vars are missing")
		}
	})
}

func TestEngine_applyAuth_OAuth2_Success(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("Expected POST request, got %s", r.Method)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("Expected Content-Type application/json, got %s", r.Header.Get("Content-Type"))
		}
		// Expect Basic auth
		auth := r.Header.Get("Authorization")
		if auth == "" {
			t.Errorf("Expected Authorization header")
		}

		w.WriteHeader(http.StatusOK)
		resp := map[string]string{"access_token": "mock-token"}
		json.NewEncoder(w).Encode(resp)
	}))
	defer ts.Close()

	t.Setenv("TEST_CLIENT_ID", "client_id")
	t.Setenv("TEST_CLIENT_SECRET", "client_secret")

	e := NewEngine(ts.Client())
	ctx := context.Background()
	req, _ := http.NewRequestWithContext(ctx, "GET", "http://example.com", nil)
	auth := &AuthFlowConfig{
		Type:            "oauth2",
		TokenURL:        ts.URL,
		ClientIDEnv:     "TEST_CLIENT_ID",
		ClientSecretEnv: "TEST_CLIENT_SECRET",
	}

	err := e.applyAuth(ctx, req, auth, nil)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if req.Header.Get("Authorization") != "Bearer mock-token" {
		t.Errorf("expected Bearer mock-token, got %s", req.Header.Get("Authorization"))
	}
}

func TestEngine_applyAuth_OAuth2_Failures(t *testing.T) {
	t.Setenv("TEST_CLIENT_ID", "client_id")
	t.Setenv("TEST_CLIENT_SECRET", "client_secret")

	ctx := context.Background()
	auth := &AuthFlowConfig{
		Type:            "oauth2",
		ClientIDEnv:     "TEST_CLIENT_ID",
		ClientSecretEnv: "TEST_CLIENT_SECRET",
	}

	tests := []struct {
		name       string
		handler    http.HandlerFunc
		wantErrMsg string
	}{
		{
			name: "server error",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			},
			wantErrMsg: "token exchange returned HTTP 500",
		},
		{
			name: "invalid json",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{invalid-json`))
			},
			wantErrMsg: "parsing token response:",
		},
		{
			name: "missing access token",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{}`))
			},
			wantErrMsg: "token response missing access_token field",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(tt.handler)
			defer ts.Close()

			e := NewEngine(ts.Client())
			req, _ := http.NewRequestWithContext(ctx, "GET", "http://example.com", nil)

			authClone := *auth
			authClone.TokenURL = ts.URL

			err := e.applyAuth(ctx, req, &authClone, nil)
			if err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tt.wantErrMsg) {
				t.Errorf("expected error to contain %q, got: %v", tt.wantErrMsg, err)
			}
		})
	}
}

func TestEngine_applyAuth_Other(t *testing.T) {
	e := NewEngine(http.DefaultClient)
	ctx := context.Background()

	// AWS Signature Fail
	t.Run("aws_sigv4 failure", func(t *testing.T) {
		req, _ := http.NewRequestWithContext(ctx, "GET", "http://example.com", nil)
		auth := &AuthFlowConfig{Type: "aws_sigv4"}
		// we haven't mocked AWS keys, so it should fail gracefully
		err := e.applyAuth(ctx, req, auth, nil)
		if err == nil {
			t.Errorf("expected aws_sigv4 error")
		}
	})

	// GCP ADC Fail
	t.Run("gcp_adc failure", func(t *testing.T) {
		req, _ := http.NewRequestWithContext(ctx, "GET", "http://example.com", nil)
		auth := &AuthFlowConfig{Type: "gcp_adc"}
		err := e.applyAuth(ctx, req, auth, nil)
		if err == nil {
			t.Errorf("expected gcp_adc error")
		}
	})

	// Azure Identity Fail
	t.Run("azure_identity failure", func(t *testing.T) {
		req, _ := http.NewRequestWithContext(ctx, "GET", "http://example.com", nil)
		auth := &AuthFlowConfig{Type: "azure_identity"}
		err := e.applyAuth(ctx, req, auth, nil)
		if err == nil {
			t.Errorf("expected azure_identity error")
		}
	})

	// OCI Cavage Fail
	t.Run("oci_cavage failure", func(t *testing.T) {
		req, _ := http.NewRequestWithContext(ctx, "GET", "http://example.com", nil)
		auth := &AuthFlowConfig{Type: "oci_cavage"}
		err := e.applyAuth(ctx, req, auth, nil)
		if err == nil {
			t.Errorf("expected oci_cavage error")
		}
	})

	// Ali Tencent HMAC Fail
	t.Run("ali_tencent_hmac failure", func(t *testing.T) {
		req, _ := http.NewRequestWithContext(ctx, "GET", "http://example.com", nil)
		auth := &AuthFlowConfig{Type: "ali_tencent_hmac"}
		err := e.applyAuth(ctx, req, auth, nil)
		if err == nil {
			t.Errorf("expected ali_tencent_hmac error")
		}
	})

	// JWS Financial Fail
	t.Run("jws_financial failure", func(t *testing.T) {
		req, _ := http.NewRequestWithContext(ctx, "GET", "http://example.com", nil)
		auth := &AuthFlowConfig{Type: "jws_financial"}
		err := e.applyAuth(ctx, req, auth, nil)
		if err == nil {
			t.Errorf("expected jws_financial error")
		}
	})

	// Unrecognized Auth Type
	t.Run("unknown auth type", func(t *testing.T) {
		req, _ := http.NewRequestWithContext(ctx, "GET", "http://example.com", nil)
		auth := &AuthFlowConfig{Type: "unknown"}
		err := e.applyAuth(ctx, req, auth, nil)
		if err != nil {
			t.Errorf("expected nil for unknown type, got %v", err)
		}
	})
}

func TestEngine_applyAuth_Bearer_Success(t *testing.T) {
	t.Setenv("BEARER_TOKEN", "valid-token")

	e := NewEngine(http.DefaultClient)
	ctx := context.Background()

	req, _ := http.NewRequestWithContext(ctx, "GET", "http://example.com", nil)
	auth := &AuthFlowConfig{Type: "bearer", TokenEnv: "BEARER_TOKEN"}

	err := e.applyAuth(ctx, req, auth, nil)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if req.Header.Get("Authorization") != "Bearer valid-token" {
		t.Errorf("expected Bearer valid-token, got %s", req.Header.Get("Authorization"))
	}
}

func TestEngine_applyAuth_OAuth2_TokenExchangeFailed(t *testing.T) {
	t.Setenv("TEST_CLIENT_ID", "client_id")
	t.Setenv("TEST_CLIENT_SECRET", "client_secret")

	// Pass an invalid URL to induce a client.Do error
	e := NewEngine(http.DefaultClient)
	ctx := context.Background()
	req, _ := http.NewRequestWithContext(ctx, "GET", "http://example.com", nil)
	auth := &AuthFlowConfig{
		Type:            "oauth2",
		TokenURL:        "http://127.0.0.1:0", // Invalid port/connection refused
		ClientIDEnv:     "TEST_CLIENT_ID",
		ClientSecretEnv: "TEST_CLIENT_SECRET",
	}

	err := e.applyAuth(ctx, req, auth, nil)
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "token exchange request failed") {
		t.Errorf("expected error to contain 'token exchange request failed', got: %v", err)
	}
}

func TestEngine_applyAuth_OAuth2_TokenExchangeContextCancel(t *testing.T) {
	t.Setenv("TEST_CLIENT_ID", "client_id")
	t.Setenv("TEST_CLIENT_SECRET", "client_secret")

	// Set up a mock server that never responds
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {} // Block indefinitely
	}))
	defer ts.Close()

	e := NewEngine(ts.Client())
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	req, _ := http.NewRequestWithContext(ctx, "GET", "http://example.com", nil)
	auth := &AuthFlowConfig{
		Type:            "oauth2",
		TokenURL:        ts.URL,
		ClientIDEnv:     "TEST_CLIENT_ID",
		ClientSecretEnv: "TEST_CLIENT_SECRET",
	}

	err := e.applyAuth(ctx, req, auth, nil)
	if err == nil {
		t.Fatalf("expected error due to canceled context, got nil")
	}
	if !strings.Contains(err.Error(), "token exchange request failed") {
		t.Errorf("expected error to contain 'token exchange request failed', got: %v", err)
	}
}

func TestEngine_applyAuth_OAuth2_TokenExchangeCreateReqError(t *testing.T) {
	t.Setenv("TEST_CLIENT_ID", "client_id")
	t.Setenv("TEST_CLIENT_SECRET", "client_secret")

	e := NewEngine(http.DefaultClient)
	ctx := context.Background()
	req, _ := http.NewRequestWithContext(ctx, "GET", "http://example.com", nil)
	auth := &AuthFlowConfig{
		Type:            "oauth2",
		TokenURL:        "http://invalid-url.local\x00", // invalid URL to trigger NewRequest error
		ClientIDEnv:     "TEST_CLIENT_ID",
		ClientSecretEnv: "TEST_CLIENT_SECRET",
	}

	err := e.applyAuth(ctx, req, auth, nil)
	if err == nil {
		t.Fatalf("expected error due to invalid URL, got nil")
	}
	if !strings.Contains(err.Error(), "creating token request") {
		t.Errorf("expected error to contain 'creating token request', got: %v", err)
	}
}
