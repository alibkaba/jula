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

func TestIsHostAllowed(t *testing.T) {
	allowlist := []string{"googleapis.com", "amazonaws.com", "github.com"}

	tests := []struct {
		name     string
		hostname string
		want     bool
	}{
		{
			name:     "exact match",
			hostname: "googleapis.com",
			want:     true,
		},
		{
			name:     "subdomain match",
			hostname: "storage.googleapis.com",
			want:     true,
		},
		{
			name:     "deep subdomain match",
			hostname: "us-central1-storage.googleapis.com",
			want:     true,
		},
		{
			name:     "AWS subdomain match",
			hostname: "s3.us-east-1.amazonaws.com",
			want:     true,
		},
		{
			name:     "GitHub API match",
			hostname: "api.github.com",
			want:     true,
		},
		{
			name:     "block Jula-controlled domain",
			hostname: "api.julacontrols.com",
			want:     false,
		},
		{
			name:     "block arbitrary domain",
			hostname: "evil.example.com",
			want:     false,
		},
		{
			name:     "case insensitive",
			hostname: "Storage.GoogleAPIs.COM",
			want:     true,
		},
		{
			name:     "trailing dot handling",
			hostname: "api.github.com.",
			want:     true,
		},
		{
			name:     "partial match rejected (not a suffix)",
			hostname: "notgoogleapis.com",
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsHostAllowed(tt.hostname, allowlist)
			if got != tt.want {
				t.Errorf("IsHostAllowed(%q) = %v, want %v", tt.hostname, got, tt.want)
			}
		})
	}
}

func TestIsHostAllowed_EmptyAllowlist(t *testing.T) {
	// Empty allowlist means no restriction: all hosts are allowed.
	if !IsHostAllowed("anything.example.com", nil) {
		t.Error("expected nil allowlist to allow all hosts")
	}
	if !IsHostAllowed("anything.example.com", []string{}) {
		t.Error("expected empty allowlist to allow all hosts")
	}
}

func TestNewClientWithEgressAllowlist_BlocksNonAllowlisted(t *testing.T) {
	client := NewClientWithEgressAllowlist(1*time.Millisecond, []string{"googleapis.com"})

	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("expected transport to be of type *http.Transport")
	}
	dialContext := transport.DialContext

	// This domain is NOT in the allowlist.
	conn, err := dialContext(context.Background(), "tcp", "evil.example.com:443")
	if conn != nil {
		conn.Close()
	}

	if err == nil {
		t.Fatal("expected egress violation error, got nil")
	}
	if !strings.Contains(err.Error(), "egress violation") {
		t.Errorf("expected egress violation error, got: %v", err)
	}
}

func TestNewClientWithEgressAllowlist_AllowsListed(t *testing.T) {
	client := NewClientWithEgressAllowlist(1*time.Millisecond, []string{"googleapis.com"})

	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("expected transport to be of type *http.Transport")
	}
	dialContext := transport.DialContext

	// This domain IS in the allowlist. It should pass the allowlist check
	// and then fail on DNS/timeout (proving the allowlist didn't block it).
	conn, err := dialContext(context.Background(), "tcp", "storage.googleapis.com:443")
	if conn != nil {
		conn.Close()
	}

	if err == nil {
		t.Skip("unexpectedly connected; network may be available")
	}
	// The error should NOT be an egress violation (it should be DNS or timeout).
	if strings.Contains(err.Error(), "egress violation") {
		t.Errorf("allowlisted domain was blocked: %v", err)
	}
}
