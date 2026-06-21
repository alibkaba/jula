package universal_rest

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSignAWSv4(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://config.us-east-1.amazonaws.com/?test=123", nil)

	// No credentials should fail
	if err := SignAWSv4(req, nil); err == nil {
		t.Fatal("expected error without credentials")
	}

	t.Setenv("AWS_ACCESS_KEY_ID", "TEST_KEY")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "TEST_SECRET")
	t.Setenv("AWS_REGION", "us-east-1")
	t.Setenv("AWS_SESSION_TOKEN", "TEST_TOKEN")

	err := SignAWSv4(req, []byte("payload"))
	if err != nil {
		t.Fatalf("expected success, got: %v", err)
	}

	if req.Header.Get("Authorization") == "" {
		t.Error("expected Authorization header to be set")
	}
	if req.Header.Get("X-Amz-Security-Token") != "TEST_TOKEN" {
		t.Error("expected X-Amz-Security-Token to be set")
	}

	// Test missing host
	req2, _ := http.NewRequest("GET", "/", nil)
	if err := SignAWSv4(req2, nil); err == nil {
		t.Fatal("expected error with missing host")
	}
}

func TestResolveECSCredentials(t *testing.T) {
	tests := []struct {
		name        string
		setupServer func() *httptest.Server
		setupEnv    func(t *testing.T)
		wantErr     bool
		wantKey     string
	}{
		{
			name: "success",
			setupServer: func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					json.NewEncoder(w).Encode(ecsCredentials{
						AccessKeyID:     "ECS_KEY",
						SecretAccessKey: "ECS_SECRET",
						Token:           "ECS_TOKEN",
					})
				}))
			},
			setupEnv: func(t *testing.T) {
				t.Setenv("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "/test-creds")
			},
			wantErr: false,
			wantKey: "ECS_KEY",
		},
		{
			name: "missing URI",
			setupServer: func() *httptest.Server {
				return nil
			},
			setupEnv: func(t *testing.T) {
				t.Setenv("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "")
			},
			wantErr: true,
		},
		{
			name: "server error",
			setupServer: func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusInternalServerError)
				}))
			},
			setupEnv: func(t *testing.T) {
				t.Setenv("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "/test-creds")
			},
			wantErr: true,
		},
		{
			name: "invalid JSON response",
			setupServer: func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Write([]byte(`{invalid-json`))
				}))
			},
			setupEnv: func(t *testing.T) {
				t.Setenv("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "/test-creds")
			},
			wantErr: true,
		},
	}

	origPrefix := ecsCredentialsEndpointPrefix
	defer func() { ecsCredentialsEndpointPrefix = origPrefix }()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Restore the prefix at the start of each test
			ecsCredentialsEndpointPrefix = origPrefix

			if tt.setupServer != nil {
				server := tt.setupServer()
				if server != nil {
					defer server.Close()
					ecsCredentialsEndpointPrefix = server.URL
				}
			}
			tt.setupEnv(t)

			creds, err := resolveECSCredentials()
			if (err != nil) != tt.wantErr {
				t.Errorf("resolveECSCredentials() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && creds != nil && creds.AccessKeyID != tt.wantKey {
				t.Errorf("resolveECSCredentials() got key = %v, want %v", creds.AccessKeyID, tt.wantKey)
			}
		})
	}
}

func TestSignAWSv4WithECSCredentials(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(ecsCredentials{
			AccessKeyID:     "ECS_KEY_FROM_META",
			SecretAccessKey: "ECS_SECRET_FROM_META",
			Token:           "ECS_TOKEN_FROM_META",
		})
	}))
	defer server.Close()

	origPrefix := ecsCredentialsEndpointPrefix
	defer func() { ecsCredentialsEndpointPrefix = origPrefix }()
	ecsCredentialsEndpointPrefix = server.URL

	t.Setenv("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "/test-creds")
	t.Setenv("AWS_REGION", "us-east-1")
	// Unset AWS_ACCESS_KEY_ID to trigger fallback
	t.Setenv("AWS_ACCESS_KEY_ID", "")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "")

	req, _ := http.NewRequest("GET", "https://config.us-east-1.amazonaws.com/", nil)

	err := SignAWSv4(req, nil)
	if err != nil {
		t.Fatalf("expected success with ECS credentials, got: %v", err)
	}

	if req.Header.Get("X-Amz-Security-Token") != "ECS_TOKEN_FROM_META" {
		t.Error("expected ECS token to be set")
	}
}

func TestExtractAWSService(t *testing.T) {
	tests := []struct {
		name string
		host string
		want string
	}{
		{
			name: "standard host",
			host: "config.us-east-1.amazonaws.com",
			want: "config",
		},
		{
			name: "no dots",
			host: "localhost",
			want: "localhost",
		},
		{
			name: "empty",
			host: "",
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := extractAWSService(tt.host); got != tt.want {
				t.Errorf("extractAWSService() = %v, want %v", got, tt.want)
			}
		})
	}
}
