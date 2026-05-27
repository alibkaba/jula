package safehttp

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestNewClient_DialContext(t *testing.T) {
	// Use a very short timeout so dial attempts fail fast with a timeout error
	// rather than making a real network connection or blocking tests.
	client := NewClient(1 * time.Millisecond)

	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("expected transport to be of type *http.Transport")
	}
	dialContext := transport.DialContext

	tests := []struct {
		name       string
		addr       string
		wantErrStr string
	}{
		{
			name:       "invalid address format",
			addr:       "invalid-port",
			wantErrStr: "invalid address format",
		},
		{
			name:       "dns lookup failure",
			addr:       "nonexistent.invalid:80",
			wantErrStr: "dns lookup failed",
		},
		{
			name:       "reject loopback IPv4",
			addr:       "127.0.0.1:80",
			wantErrStr: "SSRF violation: connection to loopback IP",
		},
		{
			name:       "reject loopback IPv6",
			addr:       "[::1]:80",
			wantErrStr: "SSRF violation: connection to loopback IP",
		},
		{
			name:       "reject link-local unicast",
			addr:       "169.254.169.254:80", // Standard AWS/GCP metadata IP
			wantErrStr: "SSRF violation: connection to link-local IP",
		},
		{
			name:       "reject link-local multicast",
			addr:       "224.0.0.252:80",
			wantErrStr: "SSRF violation: connection to link-local IP",
		},
		{
			name:       "allow external safe IP",
			addr:       "192.0.2.1:80", // TEST-NET-1 (RFC 5737), non-routable but valid
			wantErrStr: "i/o timeout",  // We expect a timeout since we used 1ms timeout, meaning it passed SSRF
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn, err := dialContext(context.Background(), "tcp", tt.addr)
			if conn != nil {
				conn.Close()
			}

			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.wantErrStr)
			}

			if !strings.Contains(err.Error(), tt.wantErrStr) {
				t.Errorf("DialContext() error = %v, want error containing %q", err, tt.wantErrStr)
			}
		})
	}
}
