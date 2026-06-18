package objstore

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

func TestECSCredentialProvider_Fetch(t *testing.T) {
	tests := []struct {
		name          string
		envVars       map[string]string
		handler       http.HandlerFunc
		expectedCreds Credentials
		wantErr       bool
	}{
		{
			name: "local environment variables",
			envVars: map[string]string{
				"AWS_ACCESS_KEY_ID":     "AKIALOCAL",
				"AWS_SECRET_ACCESS_KEY": "secretlocal",
				"AWS_SESSION_TOKEN":     "sessionlocal",
			},
			expectedCreds: Credentials{
				AccessKeyID:     "AKIALOCAL",
				SecretAccessKey: "secretlocal",
				SessionToken:    "sessionlocal",
			},
			wantErr: false,
		},
		{
			name:    "missing credentials",
			envVars: map[string]string{},
			wantErr: true,
		},
		{
			name: "full uri success",
			envVars: map[string]string{
				"AWS_CONTAINER_CREDENTIALS_FULL_URI": "DYNAMIC_URL",
				"AWS_CONTAINER_AUTHORIZATION_TOKEN":  "my-token",
			},
			handler: func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "my-token" {
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				w.WriteHeader(http.StatusOK)
				resp := ecsCredentialResponse{
					AccessKeyID:     "AKIAFULL",
					SecretAccessKey: "secretfull",
					Token:           "tokenfull",
					Expiration:      time.Now().Add(1 * time.Hour).Format(time.RFC3339),
				}
				json.NewEncoder(w).Encode(resp)
			},
			expectedCreds: Credentials{
				AccessKeyID:     "AKIAFULL",
				SecretAccessKey: "secretfull",
				SessionToken:    "tokenfull",
			},
			wantErr: false,
		},
		{
			name: "endpoint HTTP error",
			envVars: map[string]string{
				"AWS_CONTAINER_CREDENTIALS_FULL_URI": "DYNAMIC_URL",
			},
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			},
			wantErr: true,
		},
		{
			name: "endpoint invalid JSON",
			envVars: map[string]string{
				"AWS_CONTAINER_CREDENTIALS_FULL_URI": "DYNAMIC_URL",
			},
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("invalid json"))
			},
			wantErr: true,
		},
		{
			name: "endpoint invalid expiration",
			envVars: map[string]string{
				"AWS_CONTAINER_CREDENTIALS_FULL_URI": "DYNAMIC_URL",
			},
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				resp := ecsCredentialResponse{
					AccessKeyID:     "AKIA",
					SecretAccessKey: "secret",
					Expiration:      "invalid-time-format",
				}
				json.NewEncoder(w).Encode(resp)
			},
			wantErr: true,
		},
		{
			name: "relative uri without mock server",
			envVars: map[string]string{
				"AWS_CONTAINER_CREDENTIALS_RELATIVE_URI": "/test/path",
			},
			// This will fail network request to 169.254.170.2 because there is no server there.
			// But we just want to ensure it tries and returns an error.
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("AWS_ACCESS_KEY_ID", "")
			t.Setenv("AWS_SECRET_ACCESS_KEY", "")
			t.Setenv("AWS_SESSION_TOKEN", "")
			t.Setenv("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "")
			t.Setenv("AWS_CONTAINER_CREDENTIALS_FULL_URI", "")
			t.Setenv("AWS_CONTAINER_AUTHORIZATION_TOKEN", "")

			for k, v := range tt.envVars {
				t.Setenv(k, v)
			}

			provider := newECSCredentialProvider(nil)

			if tt.handler != nil {
				server := httptest.NewServer(tt.handler)
				defer server.Close()

				if val := os.Getenv("AWS_CONTAINER_CREDENTIALS_FULL_URI"); val == "DYNAMIC_URL" {
					t.Setenv("AWS_CONTAINER_CREDENTIALS_FULL_URI", server.URL)
				}
			}

			creds, err := provider.fetch()

			if (err != nil) != tt.wantErr {
				t.Errorf("fetch() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if creds.AccessKeyID != tt.expectedCreds.AccessKeyID {
					t.Errorf("AccessKeyID got %v, want %v", creds.AccessKeyID, tt.expectedCreds.AccessKeyID)
				}
				if creds.SecretAccessKey != tt.expectedCreds.SecretAccessKey {
					t.Errorf("SecretAccessKey got %v, want %v", creds.SecretAccessKey, tt.expectedCreds.SecretAccessKey)
				}
				if creds.SessionToken != tt.expectedCreds.SessionToken {
					t.Errorf("SessionToken got %v, want %v", creds.SessionToken, tt.expectedCreds.SessionToken)
				}
			}
		})
	}
}

func TestECSCredentialProvider_FetchFromEndpoint_AlternateTimeFormat(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		resp := ecsCredentialResponse{
			AccessKeyID:     "AKIAALT",
			SecretAccessKey: "secretalt",
			Token:           "tokenalt",
			Expiration:      time.Now().Add(1 * time.Hour).Format("2006-01-02T15:04:05Z"),
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	provider := newECSCredentialProvider(nil)
	creds, err := provider.fetchFromEndpoint(server.URL)
	if err != nil {
		t.Fatalf("fetchFromEndpoint failed: %v", err)
	}

	if creds.AccessKeyID != "AKIAALT" {
		t.Errorf("got %v, want AKIAALT", creds.AccessKeyID)
	}
	if creds.Expiration.IsZero() {
		t.Errorf("expected parsed expiration date, got zero")
	}
}

func TestECSCredentialProvider_Resolve_Caching(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.WriteHeader(http.StatusOK)
		resp := ecsCredentialResponse{
			AccessKeyID:     "AKIACACHE",
			SecretAccessKey: "secretcache",
			Token:           "tokencache",
			Expiration:      time.Now().Add(1 * time.Hour).Format(time.RFC3339),
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	t.Setenv("AWS_ACCESS_KEY_ID", "")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "")
	t.Setenv("AWS_CONTAINER_CREDENTIALS_FULL_URI", server.URL)

	provider := newECSCredentialProvider(nil)

	// First call should hit the endpoint
	creds1, err := provider.Resolve()
	if err != nil {
		t.Fatalf("First Resolve failed: %v", err)
	}
	if creds1.AccessKeyID != "AKIACACHE" {
		t.Errorf("expected AKIACACHE, got %v", creds1.AccessKeyID)
	}
	if callCount != 1 {
		t.Errorf("expected 1 endpoint call, got %d", callCount)
	}

	// Second call should return cached credentials
	creds2, err := provider.Resolve()
	if err != nil {
		t.Fatalf("Second Resolve failed: %v", err)
	}
	if creds2.AccessKeyID != "AKIACACHE" {
		t.Errorf("expected AKIACACHE, got %v", creds2.AccessKeyID)
	}
	if callCount != 1 {
		t.Errorf("expected 1 endpoint call after second Resolve, got %d", callCount)
	}
}

func TestCredentials_IsExpired(t *testing.T) {
	tests := []struct {
		name       string
		expiration time.Time
		margin     time.Duration
		expected   bool
	}{
		{
			name:       "zero expiration",
			expiration: time.Time{},
			margin:     5 * time.Minute,
			expected:   false,
		},
		{
			name:       "expired",
			expiration: time.Now().Add(-1 * time.Hour),
			margin:     5 * time.Minute,
			expected:   true,
		},
		{
			name:       "within margin",
			expiration: time.Now().Add(1 * time.Minute),
			margin:     5 * time.Minute,
			expected:   true,
		},
		{
			name:       "valid outside margin",
			expiration: time.Now().Add(1 * time.Hour),
			margin:     5 * time.Minute,
			expected:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := Credentials{Expiration: tt.expiration}
			if got := c.IsExpired(tt.margin); got != tt.expected {
				t.Errorf("IsExpired() = %v, want %v", got, tt.expected)
			}
		})
	}
}
