package universal_rest

import (
	"context"
	"net/http"
	"testing"
)

func TestSignAzureIdentity(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://management.azure.com", nil)
	err := SignAzureIdentity(context.Background(), req)
	if err == nil {
		t.Fatal("expected error with no az credentials")
	}
}
