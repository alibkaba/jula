package gcp

import (
	"net/http"
	"testing"
	"time"

	"github.com/alibkaba/jula-evidence-collector/pkg/types"
)

// newTestProvider creates a GCPProvider with a pre-cached token
// so no real OAuth2 exchange is needed during tests.
func newTestProvider(t *testing.T) *GCPProvider {
	t.Helper()

	return &GCPProvider{
		projectID:  "test-project",
		httpClient: &http.Client{},
		policy:     defaultTestPolicy(),
		tokenSource: &tokenSource{
			cachedToken: "test-token",
			tokenExpiry: time.Now().Add(1 * time.Hour),
		},
	}
}

// testWithRedirect temporarily overrides the httpClient transport
// to redirect all requests to the test server URL.
func testWithRedirect(p *GCPProvider, serverURL string, fn func() ([]types.Finding, error)) ([]types.Finding, error) {
	origTransport := p.httpClient.Transport
	p.httpClient.Transport = &testTransport{serverURL: serverURL, base: origTransport}
	defer func() { p.httpClient.Transport = origTransport }()
	return fn()
}

// testTransport redirects all HTTP requests to the test server.
type testTransport struct {
	serverURL string
	base      http.RoundTripper
}

func (t *testTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.URL.Scheme = "http"
	req.URL.Host = t.serverURL[len("http://"):]
	if t.base != nil {
		return t.base.RoundTrip(req)
	}
	return http.DefaultTransport.RoundTrip(req)
}

func TestToRawPayload(t *testing.T) {
	input := map[string]string{"foo": "bar"}
	output := toRawPayload(input)
	if output["foo"] != "bar" {
		t.Errorf("expected bar, got %v", output["foo"])
	}

	// Test unmarshalable input (e.g. channel)
	if toRawPayload(make(chan int)) != nil {
		t.Error("expected nil for unmarshalable input")
	}
}
