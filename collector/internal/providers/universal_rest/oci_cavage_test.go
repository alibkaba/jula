package universal_rest

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"os"
	"strings"
	"testing"
)

// generateMockRSAPrivateKey generates a fresh RSA key for testing.
func generateMockRSAPrivateKey(t *testing.T) string {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	privBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privBytes,
	})

	return string(privPEM)
}

func generateMockPKCS8PrivateKey(t *testing.T) string {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	privBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("Failed to marshal PKCS8: %v", err)
	}
	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privBytes,
	})

	return string(privPEM)
}

func TestSignOCICavage(t *testing.T) {
	mockKeyID := "ocid1.tenancy.oc1..xyz/ocid1.user.oc1..xyz/fingerprint"
	mockRSAKey := generateMockRSAPrivateKey(t)
	mockPKCS8Key := generateMockPKCS8PrivateKey(t)

	tests := []struct {
		name        string
		keyID       string
		privateKey  string
		method      string
		url         string
		payload     []byte
		setupHeader func(req *http.Request)
		wantErr     bool
		errMsg      string
	}{
		{
			name:       "valid get request (PKCS1)",
			keyID:      mockKeyID,
			privateKey: mockRSAKey,
			method:     http.MethodGet,
			url:        "https://iaas.us-ashburn-1.oraclecloud.com/20160918/instances?compartmentId=ocid1",
			payload:    nil,
			wantErr:    false,
		},
		{
			name:       "valid get request (PKCS8)",
			keyID:      mockKeyID,
			privateKey: mockPKCS8Key,
			method:     http.MethodGet,
			url:        "https://iaas.us-ashburn-1.oraclecloud.com/20160918/instances",
			payload:    nil,
			wantErr:    false,
		},
		{
			name:       "valid post request with payload",
			keyID:      mockKeyID,
			privateKey: mockRSAKey,
			method:     http.MethodPost,
			url:        "https://iaas.us-ashburn-1.oraclecloud.com/20160918/instances",
			payload:    []byte(`{"test":"data"}`),
			wantErr:    false,
		},
		{
			name:       "missing credentials",
			keyID:      "",
			privateKey: "",
			method:     http.MethodGet,
			url:        "https://iaas.us-ashburn-1.oraclecloud.com",
			payload:    nil,
			wantErr:    true,
			errMsg:     "oci_cavage requires OCI_KEY_ID and OCI_PRIVATE_KEY",
		},
		{
			name:       "invalid pem block",
			keyID:      mockKeyID,
			privateKey: "INVALID_PEM_DATA",
			method:     http.MethodGet,
			url:        "https://iaas.us-ashburn-1.oraclecloud.com",
			payload:    nil,
			wantErr:    true,
			errMsg:     "failed to parse PEM block from OCI_PRIVATE_KEY",
		},
		{
			name:       "unsupported pem type",
			keyID:      mockKeyID,
			privateKey: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("invalid")})),
			method:     http.MethodGet,
			url:        "https://iaas.us-ashburn-1.oraclecloud.com",
			payload:    nil,
			wantErr:    true,
			errMsg:     "unsupported OCI_PRIVATE_KEY PEM block type: CERTIFICATE",
		},
		{
			name:       "invalid rsa private key data",
			keyID:      mockKeyID,
			privateKey: string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: []byte("invalid data")})),
			method:     http.MethodGet,
			url:        "https://iaas.us-ashburn-1.oraclecloud.com",
			payload:    nil,
			wantErr:    true,
			errMsg:     "parsing PKCS1/PKCS8 private key",
		},
		{
			name:       "invalid pkcs8 private key data",
			keyID:      mockKeyID,
			privateKey: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("invalid data")})),
			method:     http.MethodGet,
			url:        "https://iaas.us-ashburn-1.oraclecloud.com",
			payload:    nil,
			wantErr:    true,
			errMsg:     "parsing PKCS8 private key",
		},
		{
			name:       "request with existing X-Date header",
			keyID:      mockKeyID,
			privateKey: mockRSAKey,
			method:     http.MethodGet,
			url:        "https://iaas.us-ashburn-1.oraclecloud.com",
			payload:    nil,
			setupHeader: func(req *http.Request) {
				req.Header.Set("X-Date", "Mon, 02 Jan 2006 15:04:05 GMT")
			},
			wantErr: false,
		},
		{
			name:       "request with existing Date header",
			keyID:      mockKeyID,
			privateKey: mockRSAKey,
			method:     http.MethodGet,
			url:        "https://iaas.us-ashburn-1.oraclecloud.com",
			payload:    nil,
			setupHeader: func(req *http.Request) {
				req.Header.Set("Date", "Mon, 02 Jan 2006 15:04:05 GMT")
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.keyID != "" {
				os.Setenv("OCI_KEY_ID", tt.keyID)
			} else {
				os.Unsetenv("OCI_KEY_ID")
			}
			if tt.privateKey != "" {
				os.Setenv("OCI_PRIVATE_KEY", tt.privateKey)
			} else {
				os.Unsetenv("OCI_PRIVATE_KEY")
			}
			defer os.Unsetenv("OCI_KEY_ID")
			defer os.Unsetenv("OCI_PRIVATE_KEY")

			var reqBody *bytes.Reader
			if tt.payload != nil {
				reqBody = bytes.NewReader(tt.payload)
			} else {
				reqBody = bytes.NewReader(nil)
			}

			req, err := http.NewRequest(tt.method, tt.url, reqBody)
			if err != nil {
				t.Fatalf("Failed to create request: %v", err)
			}

			if tt.setupHeader != nil {
				tt.setupHeader(req)
			}

			err = SignOCICavage(req, tt.payload)

			if (err != nil) != tt.wantErr {
				t.Errorf("SignOCICavage() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("SignOCICavage() error message = %v, expected to contain %v", err.Error(), tt.errMsg)
				}
				return
			}

			// Validate successful signature injection
			authHeader := req.Header.Get("Authorization")
			if authHeader == "" {
				t.Errorf("Expected Authorization header, got empty")
			}

			if !strings.Contains(authHeader, `Signature version="1"`) {
				t.Errorf("Missing version in Authorization header: %s", authHeader)
			}

			if !strings.Contains(authHeader, `keyId="`+mockKeyID+`"`) {
				t.Errorf("Missing/incorrect keyId in Authorization header: %s", authHeader)
			}

			if !strings.Contains(authHeader, `headers="`) {
				t.Errorf("Missing headers list in Authorization header: %s", authHeader)
			}

			if !strings.Contains(authHeader, `signature="`) {
				t.Errorf("Missing signature in Authorization header: %s", authHeader)
			}
		})
	}
}
