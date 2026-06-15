package objstore

import (
	"net/http"
	"testing"
)

func TestSigV4_DeriveSigningKey(t *testing.T) {
	// AWS test vector from documentation.
	key := deriveSigningKey("wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", "20120215", "us-east-1", "iam")
	if len(key) != 32 {
		t.Fatalf("expected 32-byte key, got %d bytes", len(key))
	}
}

func TestSigV4_HashPayload(t *testing.T) {
	// SHA256 of empty string.
	emptyHash := hashPayload(nil)
	expected := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if emptyHash != expected {
		t.Fatalf("empty hash mismatch:\n got: %s\nwant: %s", emptyHash, expected)
	}

	// SHA256 of known data.
	dataHash := hashPayload([]byte("hello"))
	expectedData := "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
	if dataHash != expectedData {
		t.Fatalf("data hash mismatch:\n got: %s\nwant: %s", dataHash, expectedData)
	}
}

func TestSigV4_CanonicalizeHeaders(t *testing.T) {
	headers := http.Header{
		"Host":                 {"example.amazonaws.com"},
		"X-Amz-Date":          {"20130524T000000Z"},
		"X-Amz-Content-Sha256": {"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
		"Content-Type":         {"application/json"},
		"X-Custom-Header":      {"should-be-ignored"},
	}

	signedHeaders, canonical := canonicalizeHeaders(headers)

	// X-Custom-Header should be excluded.
	if signedHeaders != "content-type;host;x-amz-content-sha256;x-amz-date" {
		t.Fatalf("unexpected signed headers: %q", signedHeaders)
	}

	// Each header line should be lowercase key:value with trailing newline.
	if canonical == "" {
		t.Fatal("canonical headers is empty")
	}
}

func TestSigV4_CanonicalizeQuery(t *testing.T) {
	tests := []struct {
		name   string
		query  string
		expect string
	}{
		{"empty", "", ""},
		{"single", "Action=ListUsers", "Action=ListUsers"},
		{"sorted", "Version=2010-05-08&Action=ListUsers", "Action=ListUsers&Version=2010-05-08"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest("GET", "https://example.com?"+tt.query, nil)
			got := canonicalizeQuery(req.URL.Query())
			if got != tt.expect {
				t.Fatalf("got %q, want %q", got, tt.expect)
			}
		})
	}
}

func TestSigV4_CanonicalizePath(t *testing.T) {
	tests := []struct {
		path   string
		expect string
	}{
		{"", "/"},
		{"/", "/"},
		{"/bucket/key", "/bucket/key"},
	}

	for _, tt := range tests {
		got := canonicalizePath(tt.path)
		if got != tt.expect {
			t.Fatalf("canonicalizePath(%q) = %q, want %q", tt.path, got, tt.expect)
		}
	}
}

func TestSigV4_SignSetsAuthorizationHeader(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://s3.us-east-1.amazonaws.com/mybucket/mykey", nil)
	req.Host = "s3.us-east-1.amazonaws.com"

	creds := Credentials{
		AccessKeyID:    "AKIAIOSFODNN7EXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		SessionToken:   "FwoGZXIvYXdzEBY...",
	}

	signV4(req, creds, "us-east-1", "s3", hashPayload(nil))

	authHeader := req.Header.Get("Authorization")
	if authHeader == "" {
		t.Fatal("Authorization header not set")
	}
	if authHeader[:16] != "AWS4-HMAC-SHA256" {
		t.Fatalf("unexpected auth header prefix: %q", authHeader[:16])
	}

	// Verify security token header is set.
	if req.Header.Get("x-amz-security-token") != creds.SessionToken {
		t.Fatal("x-amz-security-token not set")
	}

	// Verify date header is set.
	if req.Header.Get("x-amz-date") == "" {
		t.Fatal("x-amz-date not set")
	}
}

func TestSigV4_SignWithoutSessionToken(t *testing.T) {
	req, _ := http.NewRequest("PUT", "https://s3.us-east-1.amazonaws.com/mybucket/mykey", nil)
	req.Host = "s3.us-east-1.amazonaws.com"

	creds := Credentials{
		AccessKeyID:    "AKIAIOSFODNN7EXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
	}

	signV4(req, creds, "us-east-1", "s3", hashPayload(nil))

	if req.Header.Get("x-amz-security-token") != "" {
		t.Fatal("x-amz-security-token should not be set without session token")
	}

	authHeader := req.Header.Get("Authorization")
	if authHeader == "" {
		t.Fatal("Authorization header not set")
	}
}
