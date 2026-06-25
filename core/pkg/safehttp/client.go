package safehttp

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

// NewClient returns an *http.Client configured with strict SSRF protections.
// It intercepts DNS resolutions directly at the DialContext layer to prevent
// DNS rebinding attacks and explicitly rejects Loopback and LinkLocalUnicast IPs
// (e.g., 169.254.169.254) which are heavily targeted for Cloud Metadata extraction.
// It allows Private RFC1918 IPs (10.x, 192.168.x) to support enterprise on-premise targets.
func NewClient(timeout time.Duration) *http.Client {
	return newClient(timeout, nil)
}

// newClientWithEgressAllowlist returns an *http.Client with SSRF protection AND
// egress domain allowlisting. Only connections to hosts matching one of the
// allowed domain suffixes are permitted. All other outbound connections are blocked.
//
// This enforces the Zero-Knowledge Evidence Handling guarantee (ADR-001):
// the Collector and Assessor can only connect to approved cloud API endpoints.
// Jula-controlled domains are blocked unless explicitly allowlisted.
//
// Example allowlist: ["googleapis.com", "amazonaws.com", "github.com"]
func newClientWithEgressAllowlist(timeout time.Duration, allowedDomains []string) *http.Client {
	return newClient(timeout, allowedDomains)
}

// IsHostAllowed checks whether the given hostname matches any suffix in the
// allowlist. Returns true if the allowlist is nil/empty (no restriction).
func IsHostAllowed(hostname string, allowedDomains []string) bool {
	if len(allowedDomains) == 0 {
		return true
	}

	hostname = strings.ToLower(strings.TrimSuffix(hostname, "."))

	for _, domain := range allowedDomains {
		domain = strings.ToLower(strings.TrimSuffix(domain, "."))
		if hostname == domain || strings.HasSuffix(hostname, "."+domain) {
			return true
		}
	}

	return false
}

func newClient(timeout time.Duration, allowedDomains []string) *http.Client {
	dialer := &net.Dialer{
		Timeout:   timeout,
		KeepAlive: 30 * time.Second,
	}

	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, fmt.Errorf("invalid address format: %w", err)
			}

			// Egress allowlist check: reject connections to non-allowlisted domains.
			if len(allowedDomains) > 0 && !IsHostAllowed(host, allowedDomains) {
				return nil, fmt.Errorf("egress violation: connection to %q blocked by allowlist policy", host)
			}

			// Force DNS resolution before establishing connection
			ips, err := net.LookupIP(host)
			if err != nil {
				return nil, fmt.Errorf("dns lookup failed: %w", err)
			}
			if len(ips) == 0 {
				return nil, fmt.Errorf("no IP addresses found for host: %s", host)
			}

			// Inspect resolved IP against SSRF blocklist
			var targetIP net.IP
			for _, ip := range ips {
				if ip.IsLoopback() {
					return nil, fmt.Errorf("SSRF violation: connection to loopback IP %s rejected", ip.String())
				}
				if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
					return nil, fmt.Errorf("SSRF violation: connection to link-local IP %s rejected", ip.String())
				}
				// We pick the first IP that passes the check to avoid rebinding vulnerabilities
				// where subsequent dial requests resolve to a newly mapped malicious IP.
				if targetIP == nil {
					targetIP = ip
				}
			}

			// Construct the explicit IP string rather than passing the hostname back into the dialer
			safeAddr := net.JoinHostPort(targetIP.String(), port)
			return dialer.DialContext(ctx, network, safeAddr)
		},
	}

	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
	}
}
