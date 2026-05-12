package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
)

func generateTestKey() (string, error) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", err
	}
	der, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		return "", err
	}
	pemBlock := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: der,
	}
	return string(pem.EncodeToMemory(pemBlock)), nil
}

func TestHandleRun_HappyPath(t *testing.T) {
	key, err := generateTestKey()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	t.Setenv("JULA_SIGNING_KEY", key)
	t.Setenv("JULA_PROVIDER", "gcp")
	t.Setenv("JULA_FRAMEWORK", "soc2")
	t.Setenv("JULA_OUTPUT_TARGET", "local")
	t.Setenv("JULA_OUTPUT_PATH", t.TempDir())
	t.Setenv("JULA_ENVIRONMENT_ID", "test-project")

	err = handleRun([]string{})

	// It's expected to fail downstream (e.g., at extraction if no real creds),
	// but we want to make sure it doesn't fail at PEM parsing or CLI validation.
	if err != nil {
		if strings.Contains(err.Error(), "failed to decode PEM block") ||
			strings.Contains(err.Error(), "parsing JULA_SIGNING_KEY") ||
			strings.Contains(err.Error(), "provider is required") ||
			strings.Contains(err.Error(), "framework is required") ||
			strings.Contains(err.Error(), "target is required") {
			t.Errorf("handleRun() failed at CLI validation stage: %v", err)
		}
	}
}

func TestHandleRun_ValidationFailures(t *testing.T) {
	key, _ := generateTestKey()
	t.Setenv("JULA_SIGNING_KEY", key)

	tests := []struct {
		name    string
		env     map[string]string
		wantErr string
	}{
		{
			name: "empty provider",
			env: map[string]string{
				"JULA_PROVIDER":      "",
				"JULA_FRAMEWORK":     "soc2",
				"JULA_OUTPUT_TARGET": "local",
				"JULA_OUTPUT_PATH":   "/tmp",
			},
			wantErr: "provider is required",
		},
		{
			name: "invalid provider",
			env: map[string]string{
				"JULA_PROVIDER":      "azure",
				"JULA_FRAMEWORK":     "soc2",
				"JULA_OUTPUT_TARGET": "local",
				"JULA_OUTPUT_PATH":   "/tmp",
			},
			wantErr: "unknown provider",
		},
		{
			name: "empty framework",
			env: map[string]string{
				"JULA_PROVIDER":      "gcp",
				"JULA_FRAMEWORK":     "",
				"JULA_OUTPUT_TARGET": "local",
				"JULA_OUTPUT_PATH":   "/tmp",
			},
			wantErr: "framework is required",
		},
		{
			name: "invalid framework",
			env: map[string]string{
				"JULA_PROVIDER":      "gcp",
				"JULA_FRAMEWORK":     "hipaa",
				"JULA_OUTPUT_TARGET": "local",
				"JULA_OUTPUT_PATH":   "/tmp",
			},
			wantErr: "unknown framework",
		},
		{
			name: "empty target",
			env: map[string]string{
				"JULA_PROVIDER":      "gcp",
				"JULA_FRAMEWORK":     "soc2",
				"JULA_OUTPUT_TARGET": "",
				"JULA_OUTPUT_PATH":   "/tmp",
			},
			wantErr: "target is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for k, v := range tt.env {
				t.Setenv(k, v)
			}
			err := handleRun([]string{})
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("handleRun() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestHandleRun_InvalidKey(t *testing.T) {
	t.Setenv("JULA_SIGNING_KEY", "invalid-hex-garbage")
	t.Setenv("JULA_PROVIDER", "gcp")
	t.Setenv("JULA_FRAMEWORK", "soc2")
	t.Setenv("JULA_OUTPUT_TARGET", "local")
	t.Setenv("JULA_OUTPUT_PATH", t.TempDir())

	err := handleRun([]string{})
	if err == nil {
		t.Fatal("expected error for invalid key")
	}
	if !strings.Contains(err.Error(), "failed to decode PEM block") {
		t.Errorf("expected PEM decode error, got: %v", err)
	}
}

func TestHandleRun_GCSTarget(t *testing.T) {
	key, _ := generateTestKey()
	t.Setenv("JULA_SIGNING_KEY", key)
	t.Setenv("JULA_PROVIDER", "gcp")
	t.Setenv("JULA_FRAMEWORK", "soc2")
	t.Setenv("JULA_OUTPUT_TARGET", "gcs")
	t.Setenv("JULA_OUTPUT_PATH", "gs://test-bucket")
	t.Setenv("JULA_ENVIRONMENT_ID", "test-project")

	err := handleRun([]string{})
	if err != nil && (strings.Contains(err.Error(), "failed to decode PEM block") || strings.Contains(err.Error(), "parsing JULA_SIGNING_KEY")) {
		t.Errorf("expected no PEM parsing error, got: %v", err)
	}
}

func TestHandleRun_WrongKeyType(t *testing.T) {
	// RSA key in PEM block
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	der := x509.MarshalPKCS1PrivateKey(privKey)
	pemBlock := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: der}
	pemString := string(pem.EncodeToMemory(pemBlock))

	t.Setenv("JULA_SIGNING_KEY", pemString)
	t.Setenv("JULA_PROVIDER", "gcp")
	t.Setenv("JULA_FRAMEWORK", "soc2")
	t.Setenv("JULA_OUTPUT_TARGET", "local")
	t.Setenv("JULA_OUTPUT_PATH", t.TempDir())

	err := handleRun([]string{})
	if err == nil {
		t.Fatal("expected error for RSA key (expected EC)")
	}
	if !strings.Contains(err.Error(), "parsing JULA_SIGNING_KEY") {
		t.Errorf("expected parsing error, got: %v", err)
	}
}

func TestHandleRun_S3Target(t *testing.T) {
	key, _ := generateTestKey()
	t.Setenv("JULA_SIGNING_KEY", key)
	t.Setenv("JULA_PROVIDER", "gcp")
	t.Setenv("JULA_FRAMEWORK", "soc2")
	t.Setenv("JULA_OUTPUT_TARGET", "s3")
	t.Setenv("JULA_OUTPUT_PATH", "s3://test-bucket")
	t.Setenv("JULA_ENVIRONMENT_ID", "test-project")

	err := handleRun([]string{})
	if err == nil {
		t.Fatal("expected error for s3 target (not implemented)")
	}
	if !strings.Contains(err.Error(), "reporter not implemented for target: s3") {
		t.Errorf("expected reporter not implemented error, got: %v", err)
	}
}

func TestHandleRun_MultipleProviders(t *testing.T) {
	key, _ := generateTestKey()
	t.Setenv("JULA_SIGNING_KEY", key)
	t.Setenv("JULA_PROVIDER", "gcp,aws")
	t.Setenv("JULA_FRAMEWORK", "soc2")
	t.Setenv("JULA_OUTPUT_TARGET", "local")
	t.Setenv("JULA_OUTPUT_PATH", t.TempDir())
	t.Setenv("JULA_ENVIRONMENT_ID", "test-project")

	err := handleRun([]string{})
	if err != nil && (strings.Contains(err.Error(), "failed to decode PEM block") || strings.Contains(err.Error(), "parsing JULA_SIGNING_KEY")) {
		t.Errorf("expected no PEM parsing error, got: %v", err)
	}
}

func TestHandleRun_ISO27001Framework(t *testing.T) {
	key, _ := generateTestKey()
	t.Setenv("JULA_SIGNING_KEY", key)
	t.Setenv("JULA_PROVIDER", "gcp")
	t.Setenv("JULA_FRAMEWORK", "iso27001")
	t.Setenv("JULA_OUTPUT_TARGET", "local")
	t.Setenv("JULA_OUTPUT_PATH", t.TempDir())
	t.Setenv("JULA_ENVIRONMENT_ID", "test-project")

	err := handleRun([]string{})
	if err == nil {
		t.Fatal("expected error for iso27001 framework (mapper not implemented)")
	}
	if !strings.Contains(err.Error(), "mapper not implemented for framework: iso27001") {
		t.Errorf("expected mapper not implemented error, got: %v", err)
	}
}

func TestHandleRun_InvalidTimeout(t *testing.T) {
	key, _ := generateTestKey()
	t.Setenv("JULA_SIGNING_KEY", key)
	t.Setenv("JULA_PROVIDER", "gcp")
	t.Setenv("JULA_FRAMEWORK", "soc2")
	t.Setenv("JULA_OUTPUT_TARGET", "local")
	t.Setenv("JULA_OUTPUT_PATH", "/tmp")

	err := handleRun([]string{"-timeout", "not-a-duration"})
	if err == nil {
		t.Fatal("expected error for invalid timeout")
	}
}

func TestHandleRun_BadFlagParsing(t *testing.T) {
	err := handleRun([]string{"--unknown-flag"})
	if err == nil {
		t.Fatal("expected error for unknown flag")
	}
}
