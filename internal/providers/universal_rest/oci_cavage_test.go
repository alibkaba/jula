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

func TestSignOCICavage_GetRequest(t *testing.T) {
	mockKeyID := "ocid1.tenancy.oc1..xyz/ocid1.user.oc1..xyz/fingerprint"
	mockPEM := generateMockRSAPrivateKey(t)

	os.Setenv("OCI_KEY_ID", mockKeyID)
	os.Setenv("OCI_PRIVATE_KEY", mockPEM)
	defer os.Unsetenv("OCI_KEY_ID")
	defer os.Unsetenv("OCI_PRIVATE_KEY")

	req, err := http.NewRequest(http.MethodGet, "https://iaas.us-ashburn-1.oraclecloud.com/20160918/instances?compartmentId=ocid1", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	err = SignOCICavage(req, nil)
	if err != nil {
		t.Fatalf("SignOCICavage failed: %v", err)
	}

	authHeader := req.Header.Get("Authorization")
	if authHeader == "" {
		t.Fatalf("Expected Authorization header, got empty")
	}

	if !strings.HasPrefix(authHeader, `Signature version="1",keyId="`+mockKeyID+`",algorithm="rsa-sha256"`) {
		t.Errorf("Authorization header prefix mismatch. Got: %s", authHeader)
	}

	if !strings.Contains(authHeader, `headers="date (request-target) host"`) {
		t.Errorf("Authorization header headers list mismatch. Got: %s", authHeader)
	}

	if !strings.Contains(authHeader, `signature="`) {
		t.Errorf("Authorization header signature missing. Got: %s", authHeader)
	}

	// Verify required headers were injected
	if req.Header.Get("Date") == "" {
		t.Errorf("Expected Date header to be injected")
	}
	if req.Header.Get("Host") == "" {
		t.Errorf("Expected Host header to be injected")
	}
}

func TestSignOCICavage_PostRequest(t *testing.T) {
	mockKeyID := "ocid1.test.key"
	mockPEM := generateMockRSAPrivateKey(t)

	os.Setenv("OCI_KEY_ID", mockKeyID)
	os.Setenv("OCI_PRIVATE_KEY", mockPEM)
	defer os.Unsetenv("OCI_KEY_ID")
	defer os.Unsetenv("OCI_PRIVATE_KEY")

	payload := []byte(`{"test":"data"}`)
	req, err := http.NewRequest(http.MethodPost, "https://iaas.us-ashburn-1.oraclecloud.com/20160918/instances", bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	err = SignOCICavage(req, payload)
	if err != nil {
		t.Fatalf("SignOCICavage failed: %v", err)
	}

	authHeader := req.Header.Get("Authorization")
	if authHeader == "" {
		t.Fatalf("Expected Authorization header, got empty")
	}

	expectedHeaders := `headers="date (request-target) host x-content-sha256 content-length content-type"`
	if !strings.Contains(authHeader, expectedHeaders) {
		t.Errorf("Authorization header headers list mismatch. Expected to contain %s, Got: %s", expectedHeaders, authHeader)
	}

	if req.Header.Get("X-Content-Sha256") == "" {
		t.Errorf("Expected X-Content-Sha256 header to be injected for POST")
	}
	if req.Header.Get("Content-Length") != "15" {
		t.Errorf("Expected Content-Length to be 15, got: %s", req.Header.Get("Content-Length"))
	}
	if req.Header.Get("Content-Type") != "application/json" {
		t.Errorf("Expected Content-Type to be application/json, got: %s", req.Header.Get("Content-Type"))
	}
}

func TestSignOCICavage_MissingEnvVars(t *testing.T) {
	os.Unsetenv("OCI_KEY_ID")
	os.Unsetenv("OCI_PRIVATE_KEY")

	req, _ := http.NewRequest(http.MethodGet, "https://oracle.com", nil)
	err := SignOCICavage(req, nil)
	if err == nil {
		t.Errorf("Expected error when missing OCI_KEY_ID and OCI_PRIVATE_KEY, got nil")
	}
}
