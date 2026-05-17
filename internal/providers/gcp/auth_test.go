package gcp

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"testing"
	"time"
)

// mockRoundTripper intercepts HTTP requests and returns a mock response.
type mockRoundTripper struct {
	Response *http.Response
	Err      error
}

func (m *mockRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if m.Err != nil {
		return nil, m.Err
	}
	return m.Response, nil
}

// errReader simulates a read error.
type errReader struct{}

func (e errReader) Read(p []byte) (n int, err error) {
	return 0, errors.New("simulated read error")
}

func (e errReader) Close() error {
	return nil
}

func TestServiceAccountKey_JSON(t *testing.T) {
	jsonData := `{
		"type": "service_account",
		"project_id": "test-project",
		"private_key_id": "pk-id",
		"private_key": "---BEGIN PRIVATE KEY---...",
		"client_email": "test@example.com",
		"client_id": "123",
		"auth_uri": "https://auth",
		"token_uri": "https://token",
		"auth_provider_x509_cert_url": "https://auth-cert",
		"client_x509_cert_url": "https://client-cert"
	}`

	var key serviceAccountKey
	err := json.Unmarshal([]byte(jsonData), &key)
	if err != nil {
		t.Fatalf("failed to unmarshal service account key: %v", err)
	}

	if key.ProjectID != "test-project" {
		t.Errorf("expected project_id test-project, got %s", key.ProjectID)
	}
}

func TestTokenResponse_JSON(t *testing.T) {
	jsonData := `{
		"access_token": "mock-token",
		"token_type": "Bearer",
		"expires_in": 3600
	}`

	var resp tokenResponse
	err := json.Unmarshal([]byte(jsonData), &resp)
	if err != nil {
		t.Fatalf("failed to unmarshal token response: %v", err)
	}

	if resp.AccessToken != "mock-token" {
		t.Errorf("expected access_token mock-token, got %s", resp.AccessToken)
	}
}

func TestNewTokenSource(t *testing.T) {
	validKey := "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDVaf7F2s9kjc1x\n76NypKt2eeLywrFnlSV95jbIjr4PXv28yh97cithjvr2VrgZyxVXtTfOHY+DiFiD\nu4TyFpbCE2qzAVgCEl1kpZvZgv32VafH5OO27JxdpgYWaKkdOYFZUbxFotsuWDSA\nCOpl14af0Nnt4v6olVBA1fb5p9EwRKDY4A1UO8R42kueFUYSinpI7RAv1EV4rEkS\n6sdhbH56cmhmWhGf+Qb/CeSgr5G5JQOw5xWWoXGychDqWPBFC2w/e143cNGojuRw\nyyptVhAM2mWHFO1yy1yarQgp6QchrFlTcEkNZzUVtSXUUMv+yev5DRXc2caRgqQG\nrdfNLdkRAgMBAAECggEAAPNr8y26ZtRK6gsLS2N4cBqy7Cn56GA9voXcEKCyMBdY\nQhMUeNRVZSXh8F8KivLgsXdZPE3dadSdsFiRixKWsV6sxwdmgPvb9qrWOu3ee859\n5OIcMaB0QeaPeGIW/s5WyTMYB6dmGprCASAJC1Megm/HyMuOHuorZV6OryYURIbH\nq3bPp5KAsizY/WzSNzluJaE/gmAiCO/w+guzzS0ACCkcIeGI6ER9vBt28tJeVMDT\ntxuQUdaKrz76l0VSQ9WTLl4bJYI8rn5Gj9T2k3EOHlRNgV/Gj3tzV1WVb3SoaTRS\nlU4oNzKjqoKXhJKuXUgCR28pldDsqc2VvrOxZH4tAQKBgQDowIMToAHFGIv25LRS\nVo8924ojBzsuGy9fH9insaisuFhzbIKK3h/NPSBpDEZuEKoOSpHETCcR7MkZcwRv\nM4YMIL1iSRJ1NKyEgVgy06kc5SHJaMP9pC022Lr/BbX1E7qlw+eoM2BGdEoo0cVo\n6lMzccxnk6EURJF/uutp+62DWQKBgQDquwKR6nHfOGCY3l3CmTkoNc6j2EEPachi\n8nm1thNrCr6FpDdGDcXvlsc99XKmLnqMQGPY1D5Mq6dbMUUhXs/h7ISMDLeecUqn\nu0NEZWVx8P7kSsg6GgFe7rlAVveSLNzYtXXCu3glu35AX00yBFsNLlFSQAHrhpZc\nJ24uiDxkeQKBgQDhd8wCMNhGE/dSHk7IDG4KYCe6swCTM2Z6YaFBIYridlnIxm7X\nE0H/UZ2Z5Xg8mwwBeB8o5xRZ+uT8MD01c9YA3Z5YHa0xuOr+GUZVRlDmWtiWAVUK\n2gWqwdyzutZ/KLOAbPx2Jf63gWNtk3gGoCglB7IZDBvYRGwmLe5q5pE5UQKBgQDN\nbsBQDjx83S2FfM/YORuR+o2QTfqaz7zmBErK4sBZ5XxbIB6T/AfoqTBVJJSjpnfw\neYYpRZAEsBJ3OEbFbuJHWyWiIJsvWv24kKbNnGRNdVrPWDemyg27FPkiuzpPP15F\nd4LJ3CLJ+y8CjaXVCYTao1fewVAs3oyHuKawqOEaGQKBgDpEYLW8pyX2MlmYxP9o\nzewqax7iyE8vN7iK/e1OHsj7+qE/w1aPG1Ruo0Vi0DOR7IL8/NmsQTnuE4rx3U7C\nU1otrsHhjoAD3dcopdpuOcEoqTbRHgtiAz2URk+FaR11GQB2THVVADDsBnrSeLiF\nwE5dQuq6J4wd/oG3xeBmq71u\n-----END PRIVATE KEY-----\n"

	tests := []struct {
		name    string
		key     *serviceAccountKey
		wantErr bool
	}{
		{
			name: "Valid Key",
			key: &serviceAccountKey{
				PrivateKey: validKey,
			},
			wantErr: false,
		},
		{
			name: "Valid Key with custom TokenURI",
			key: &serviceAccountKey{
				PrivateKey: validKey,
				TokenURI:   "https://custom-token-uri",
			},
			wantErr: false,
		},
		{
			name: "Invalid PEM",
			key: &serviceAccountKey{
				PrivateKey: "invalid pem",
			},
			wantErr: true,
		},
		{
			name: "Invalid RSA Key",
			key: &serviceAccountKey{
				PrivateKey: "-----BEGIN PRIVATE KEY-----\nMEECAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEJzAlAgEBBCAwEwYHKoZIzj0CAQYI\nKoZIzj0DAQc=\n-----END PRIVATE KEY-----", // Valid PEM but not RSA
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := newTokenSource(tt.key, http.DefaultClient)
			if (err != nil) != tt.wantErr {
				t.Errorf("newTokenSource() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestTokenSource_Token_And_Refresh(t *testing.T) {
	validKey := "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDVaf7F2s9kjc1x\n76NypKt2eeLywrFnlSV95jbIjr4PXv28yh97cithjvr2VrgZyxVXtTfOHY+DiFiD\nu4TyFpbCE2qzAVgCEl1kpZvZgv32VafH5OO27JxdpgYWaKkdOYFZUbxFotsuWDSA\nCOpl14af0Nnt4v6olVBA1fb5p9EwRKDY4A1UO8R42kueFUYSinpI7RAv1EV4rEkS\n6sdhbH56cmhmWhGf+Qb/CeSgr5G5JQOw5xWWoXGychDqWPBFC2w/e143cNGojuRw\nyyptVhAM2mWHFO1yy1yarQgp6QchrFlTcEkNZzUVtSXUUMv+yev5DRXc2caRgqQG\nrdfNLdkRAgMBAAECggEAAPNr8y26ZtRK6gsLS2N4cBqy7Cn56GA9voXcEKCyMBdY\nQhMUeNRVZSXh8F8KivLgsXdZPE3dadSdsFiRixKWsV6sxwdmgPvb9qrWOu3ee859\n5OIcMaB0QeaPeGIW/s5WyTMYB6dmGprCASAJC1Megm/HyMuOHuorZV6OryYURIbH\nq3bPp5KAsizY/WzSNzluJaE/gmAiCO/w+guzzS0ACCkcIeGI6ER9vBt28tJeVMDT\ntxuQUdaKrz76l0VSQ9WTLl4bJYI8rn5Gj9T2k3EOHlRNgV/Gj3tzV1WVb3SoaTRS\nlU4oNzKjqoKXhJKuXUgCR28pldDsqc2VvrOxZH4tAQKBgQDowIMToAHFGIv25LRS\nVo8924ojBzsuGy9fH9insaisuFhzbIKK3h/NPSBpDEZuEKoOSpHETCcR7MkZcwRv\nM4YMIL1iSRJ1NKyEgVgy06kc5SHJaMP9pC022Lr/BbX1E7qlw+eoM2BGdEoo0cVo\n6lMzccxnk6EURJF/uutp+62DWQKBgQDquwKR6nHfOGCY3l3CmTkoNc6j2EEPachi\n8nm1thNrCr6FpDdGDcXvlsc99XKmLnqMQGPY1D5Mq6dbMUUhXs/h7ISMDLeecUqn\nu0NEZWVx8P7kSsg6GgFe7rlAVveSLNzYtXXCu3glu35AX00yBFsNLlFSQAHrhpZc\nJ24uiDxkeQKBgQDhd8wCMNhGE/dSHk7IDG4KYCe6swCTM2Z6YaFBIYridlnIxm7X\nE0H/UZ2Z5Xg8mwwBeB8o5xRZ+uT8MD01c9YA3Z5YHa0xuOr+GUZVRlDmWtiWAVUK\n2gWqwdyzutZ/KLOAbPx2Jf63gWNtk3gGoCglB7IZDBvYRGwmLe5q5pE5UQKBgQDN\nbsBQDjx83S2FfM/YORuR+o2QTfqaz7zmBErK4sBZ5XxbIB6T/AfoqTBVJJSjpnfw\neYYpRZAEsBJ3OEbFbuJHWyWiIJsvWv24kKbNnGRNdVrPWDemyg27FPkiuzpPP15F\nd4LJ3CLJ+y8CjaXVCYTao1fewVAs3oyHuKawqOEaGQKBgDpEYLW8pyX2MlmYxP9o\nzewqax7iyE8vN7iK/e1OHsj7+qE/w1aPG1Ruo0Vi0DOR7IL8/NmsQTnuE4rx3U7C\nU1otrsHhjoAD3dcopdpuOcEoqTbRHgtiAz2URk+FaR11GQB2THVVADDsBnrSeLiF\nwE5dQuq6J4wd/oG3xeBmq71u\n-----END PRIVATE KEY-----\n"

	tests := []struct {
		name          string
		mockStatus    int
		mockBody      string
		mockErr       error
		mockBodyError bool
		setupCache    bool
		cacheExpired  bool
		wantErr       bool
		expectedToken string
	}{
		{
			name:          "Happy Path Refresh",
			mockStatus:    http.StatusOK,
			mockBody:      `{"access_token": "new-token", "expires_in": 3600}`,
			setupCache:    false,
			wantErr:       false,
			expectedToken: "new-token",
		},
		{
			name:          "Use Cached Token",
			mockStatus:    http.StatusOK, // shouldn't be called
			setupCache:    true,
			cacheExpired:  false,
			wantErr:       false,
			expectedToken: "cached-token",
		},
		{
			name:          "Refresh Expired Cache",
			mockStatus:    http.StatusOK,
			mockBody:      `{"access_token": "refreshed-token", "expires_in": 3600}`,
			setupCache:    true,
			cacheExpired:  true,
			wantErr:       false,
			expectedToken: "refreshed-token",
		},
		{
			name:       "HTTP Error 500",
			mockStatus: http.StatusInternalServerError,
			mockBody:   "Internal Server Error",
			setupCache: false,
			wantErr:    true,
		},
		{
			name:       "Invalid JSON Response",
			mockStatus: http.StatusOK,
			mockBody:   "not json",
			setupCache: false,
			wantErr:    true,
		},
		{
			name:       "Transport Error",
			mockErr:    errors.New("network error"),
			setupCache: false,
			wantErr:    true,
		},
		{
			name:          "Body Read Error",
			mockStatus:    http.StatusOK,
			mockBodyError: true,
			setupCache:    false,
			wantErr:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var bodyReader io.ReadCloser
			if tt.mockBodyError {
				bodyReader = errReader{}
			} else {
				bodyReader = io.NopCloser(bytes.NewBufferString(tt.mockBody))
			}

			client := &http.Client{
				Transport: &mockRoundTripper{
					Response: &http.Response{
						StatusCode: tt.mockStatus,
						Body:       bodyReader,
					},
					Err: tt.mockErr,
				},
			}

			key := &serviceAccountKey{PrivateKey: validKey}
			ts, err := newTokenSource(key, client)
			if err != nil {
				t.Fatalf("setup failed: %v", err)
			}

			if tt.setupCache {
				ts.cachedToken = "cached-token"
				if tt.cacheExpired {
					ts.tokenExpiry = time.Now().Add(-1 * time.Hour)
				} else {
					ts.tokenExpiry = time.Now().Add(1 * time.Hour)
				}
			}

			token, err := ts.Token()
			if (err != nil) != tt.wantErr {
				t.Errorf("Token() error = %v, wantErr %v", err, tt.wantErr)
			}

			if !tt.wantErr && token != tt.expectedToken {
				t.Errorf("Token() = %v, want %v", token, tt.expectedToken)
			}
		})
	}
}

func TestMetadataTokenSource(t *testing.T) {
	tests := []struct {
		name          string
		mockStatus    int
		mockBody      string
		mockErr       error
		mockBodyError bool
		setupCache    bool
		cacheExpired  bool
		wantErr       bool
		expectedToken string
	}{
		{
			name:          "Happy Path Metadata",
			mockStatus:    http.StatusOK,
			mockBody:      `{"access_token": "meta-token", "expires_in": 3600}`,
			setupCache:    false,
			wantErr:       false,
			expectedToken: "meta-token",
		},
		{
			name:          "Use Cached Metadata Token",
			setupCache:    true,
			cacheExpired:  false,
			wantErr:       false,
			expectedToken: "meta-cached-token",
		},
		{
			name:          "Refresh Expired Metadata Cache",
			mockStatus:    http.StatusOK,
			mockBody:      `{"access_token": "meta-refreshed-token", "expires_in": 3600}`,
			setupCache:    true,
			cacheExpired:  true,
			wantErr:       false,
			expectedToken: "meta-refreshed-token",
		},
		{
			name:       "Metadata HTTP Error 404",
			mockStatus: http.StatusNotFound,
			mockBody:   "Not Found",
			setupCache: false,
			wantErr:    true,
		},
		{
			name:       "Metadata Invalid JSON",
			mockStatus: http.StatusOK,
			mockBody:   "invalid",
			setupCache: false,
			wantErr:    true,
		},
		{
			name:       "Transport Error",
			mockErr:    errors.New("network error"),
			setupCache: false,
			wantErr:    true,
		},
		{
			name:          "Body Read Error",
			mockStatus:    http.StatusOK,
			mockBodyError: true,
			setupCache:    false,
			wantErr:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var bodyReader io.ReadCloser
			if tt.mockBodyError {
				bodyReader = errReader{}
			} else {
				bodyReader = io.NopCloser(bytes.NewBufferString(tt.mockBody))
			}

			client := &http.Client{
				Transport: &mockRoundTripper{
					Response: &http.Response{
						StatusCode: tt.mockStatus,
						Body:       bodyReader,
					},
					Err: tt.mockErr,
				},
			}

			ts := newMetadataTokenSource(client)

			if tt.setupCache {
				ts.metadataSource.cachedToken = "meta-cached-token"
				if tt.cacheExpired {
					ts.metadataSource.tokenExpiry = time.Now().Add(-1 * time.Hour)
				} else {
					ts.metadataSource.tokenExpiry = time.Now().Add(1 * time.Hour)
				}
			}

			token, err := ts.Token()
			if (err != nil) != tt.wantErr {
				t.Errorf("Token() error = %v, wantErr %v", err, tt.wantErr)
			}

			if !tt.wantErr && token != tt.expectedToken {
				t.Errorf("Token() = %v, want %v", token, tt.expectedToken)
			}
		})
	}
}

func TestToken_DelegateToMetadata(t *testing.T) {
	client := &http.Client{
		Transport: &mockRoundTripper{
			Response: &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString(`{"access_token": "delegated-token", "expires_in": 3600}`)),
			},
		},
	}
	ts := newMetadataTokenSource(client)
	token, err := ts.Token()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token != "delegated-token" {
		t.Errorf("expected token delegated-token, got %s", token)
	}
}
