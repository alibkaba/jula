package aikido

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"testing"
	"time"
)

// mockTransport implements http.RoundTripper for testing
type mockTransport struct {
	roundTripFunc func(req *http.Request) (*http.Response, error)
}

func init() {
	defaultBackoff = 1 * time.Millisecond
}

func (m *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return m.roundTripFunc(req)
}

func TestName(t *testing.T) {
	p := New()
	if p.Name() != providerName {
		t.Errorf("expected %s, got %s", providerName, p.Name())
	}
}

func TestValidate(t *testing.T) {
	t.Run("missing client ID", func(t *testing.T) {
		p := &Provider{secretKey: "secret"}
		if err := p.Validate(); err == nil {
			t.Fatal("expected error, got nil")
		}
	})

	t.Run("missing secret key", func(t *testing.T) {
		p := &Provider{clientID: "client"}
		if err := p.Validate(); err == nil {
			t.Fatal("expected error, got nil")
		}
	})

	t.Run("valid", func(t *testing.T) {
		p := &Provider{clientID: "client", secretKey: "secret"}
		if err := p.Validate(); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

func TestExtract(t *testing.T) {
	p := New()
	p.clientID = "test-client"
	p.secretKey = "test-secret"
	
	reqCount := 0
	p.client.Transport = &mockTransport{
		roundTripFunc: func(req *http.Request) (*http.Response, error) {
			reqCount++
			if req.URL.Path == "/api/oauth/token" {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewBufferString(`{"access_token": "mock-token"}`)),
				}, nil
			}
			if req.URL.Path == "/api/public/v1/issues/export" {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewBufferString(`[{"id": 123, "title": "CVE-TEST"}]`)),
				}, nil
			}
			return nil, errors.New("unexpected url")
		},
	}

	findings, err := p.Extract(context.Background(), "run-123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	if findings[0].ID != "aikido.open_vulnerability" {
		t.Errorf("unexpected finding ID: %v", findings[0].ID)
	}
}

func TestExtract_NoIssues(t *testing.T) {
	p := New()
	p.clientID = "test-client"
	p.secretKey = "test-secret"
	
	p.client.Transport = &mockTransport{
		roundTripFunc: func(req *http.Request) (*http.Response, error) {
			if req.URL.Path == "/api/oauth/token" {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewBufferString(`{"access_token": "mock-token"}`)),
				}, nil
			}
			if req.URL.Path == "/api/public/v1/issues/export" {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewBufferString(`[]`)),
				}, nil
			}
			return nil, errors.New("unexpected url")
		},
	}

	findings, err := p.Extract(context.Background(), "run-123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	if findings[0].Status != "PASS" {
		t.Errorf("expected PASS status for no issues, got %v", findings[0].Status)
	}
}

func TestAuthenticate_Errors(t *testing.T) {
	p := New()
	p.clientID = "test"
	p.secretKey = "test"
	
	p.client.Transport = &mockTransport{
		roundTripFunc: func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusUnauthorized,
				Body:       io.NopCloser(bytes.NewBufferString(`{"error": "unauthorized"}`)),
			}, nil
		},
	}

	_, err := p.authenticate(context.Background())
	if err == nil {
		t.Fatal("expected auth error")
	}
}

func TestAuthenticate_RateLimited(t *testing.T) {
	p := New()
	p.clientID = "test"
	p.secretKey = "test"
	
	reqCount := 0
	p.client.Transport = &mockTransport{
		roundTripFunc: func(req *http.Request) (*http.Response, error) {
			reqCount++
			if reqCount == 1 {
				return &http.Response{
					StatusCode: http.StatusTooManyRequests,
					Body:       io.NopCloser(bytes.NewBufferString(`{"error": "rate limited"}`)),
				}, nil
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString(`{"access_token": "mock-token-retry"}`)),
			}, nil
		},
	}

	token, err := p.authenticate(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token != "mock-token-retry" {
		t.Errorf("unexpected token: %v", token)
	}
}

func TestFetchIssues_RateLimited(t *testing.T) {
	p := New()
	reqCount := 0
	p.client.Transport = &mockTransport{
		roundTripFunc: func(req *http.Request) (*http.Response, error) {
			reqCount++
			if reqCount == 1 {
				return &http.Response{
					StatusCode: http.StatusTooManyRequests,
					Body:       io.NopCloser(bytes.NewBufferString(`{"error": "rate limited"}`)),
				}, nil
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString(`[{"id": 456}]`)),
			}, nil
		},
	}

	issues, err := p.fetchIssues(context.Background(), "token")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(issues) != 1 {
		t.Errorf("unexpected issues length: %d", len(issues))
	}
}
