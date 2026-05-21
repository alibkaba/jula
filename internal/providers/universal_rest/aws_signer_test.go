package universal_rest

import (
	"net/http"
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
