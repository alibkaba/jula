package universal_rest

import (
	"net/http"
	"testing"
)

func TestSignAliTencentHMAC(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://cvm.tencentcloudapi.com/?Action=DescribeInstances&Version=2017-03-12", nil)

	// No credentials should fail
	if err := SignAliTencentHMAC(req, nil); err == nil {
		t.Fatal("expected error without credentials")
	}

	t.Setenv("CLOUD_SECRET_ID", "TEST_ID")
	t.Setenv("CLOUD_SECRET_KEY", "TEST_KEY")

	err := SignAliTencentHMAC(req, []byte("payload"))
	if err != nil {
		t.Fatalf("expected success, got: %v", err)
	}

	if req.Header.Get("Authorization") == "" {
		t.Error("expected Authorization header to be set")
	}

	// Missing host
	req2, _ := http.NewRequest("GET", "/", nil)
	if err := SignAliTencentHMAC(req2, nil); err == nil {
		t.Fatal("expected error with missing host")
	}
}
