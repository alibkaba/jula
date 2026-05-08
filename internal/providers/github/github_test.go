package github

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

type mockTransport struct {
	roundTripFunc func(req *http.Request) (*http.Response, error)
}

func (m *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return m.roundTripFunc(req)
}

func TestName(t *testing.T) {
	p := &Provider{}
	if p.Name() != providerName {
		t.Errorf("expected %s, got %s", providerName, p.Name())
	}
}

func TestValidate(t *testing.T) {
	t.Run("missing token", func(t *testing.T) {
		t.Setenv("GITHUB_REPO", "alibkaba/repo")
		p := &Provider{}
		if err := p.Validate(); err == nil {
			t.Fatal("expected error, got nil")
		}
	})

	t.Run("missing repo", func(t *testing.T) {
		t.Setenv("GITHUB_TOKEN", "token")
		p := &Provider{}
		if err := p.Validate(); err == nil {
			t.Fatal("expected error, got nil")
		}
	})

	t.Run("valid", func(t *testing.T) {
		t.Setenv("GITHUB_TOKEN", "token")
		t.Setenv("GITHUB_REPO", "alibkaba/repo")
		p := &Provider{}
		if err := p.Validate(); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

func TestExtract_ProtectionEnabled(t *testing.T) {
	p := &Provider{
		token: "test",
		repo:  "alibkaba/jula",
		httpClient: &http.Client{
			Transport: &mockTransport{
				roundTripFunc: func(req *http.Request) (*http.Response, error) {
					if strings.Contains(req.URL.Path, "/protection") {
						body := `{"required_pull_request_reviews": {"dismiss_stale_reviews": true}}`
						return &http.Response{
							StatusCode: http.StatusOK,
							Body:       io.NopCloser(bytes.NewBufferString(body)),
						}, nil
					}
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(bytes.NewBufferString(`[]`)),
					}, nil
				},
			},
		},
	}

	findings, err := p.Extract(context.Background(), "run-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}

	if findings[0].Status != "PASS" || findings[1].Status != "PASS" {
		t.Errorf("expected PASS for both, got %s and %s", findings[0].Status, findings[1].Status)
	}
}

func TestExtract_ProtectionDisabled(t *testing.T) {
	p := &Provider{
		token: "test",
		repo:  "alibkaba/jula",
		httpClient: &http.Client{
			Transport: &mockTransport{
				roundTripFunc: func(req *http.Request) (*http.Response, error) {
					return &http.Response{
						StatusCode: http.StatusNotFound,
						Body:       io.NopCloser(bytes.NewBufferString(`{"message": "Branch not protected"}`)),
					}, nil
				},
			},
		},
	}

	findings, err := p.Extract(context.Background(), "run-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}

	if findings[0].Status != "FAIL" || findings[1].Status != "FAIL" {
		t.Errorf("expected FAIL for both, got %s and %s", findings[0].Status, findings[1].Status)
	}
}

func TestExtract_RulesetsEnabled(t *testing.T) {
	p := &Provider{
		token: "test",
		repo:  "alibkaba/jula",
		httpClient: &http.Client{
			Transport: &mockTransport{
				roundTripFunc: func(req *http.Request) (*http.Response, error) {
					if strings.Contains(req.URL.Path, "/protection") {
						return &http.Response{
							StatusCode: http.StatusNotFound,
							Body:       io.NopCloser(bytes.NewBufferString(`{"message": "Branch not protected"}`)),
						}, nil
					}
					// Return a ruleset that enforces PRs
					body := `[{"type": "pull_request"}]`
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(bytes.NewBufferString(body)),
					}, nil
				},
			},
		},
	}

	findings, err := p.Extract(context.Background(), "run-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}

	if findings[0].Status != "PASS" || findings[1].Status != "PASS" {
		t.Errorf("expected PASS for both, got %s and %s", findings[0].Status, findings[1].Status)
	}
}

func TestExtract_RulesetsWithoutPRs(t *testing.T) {
	p := &Provider{
		token: "test",
		repo:  "alibkaba/jula",
		httpClient: &http.Client{
			Transport: &mockTransport{
				roundTripFunc: func(req *http.Request) (*http.Response, error) {
					if strings.Contains(req.URL.Path, "/protection") {
						return &http.Response{
							StatusCode: http.StatusNotFound,
							Body:       io.NopCloser(bytes.NewBufferString(`{"message": "Branch not protected"}`)),
						}, nil
					}
					// Return a ruleset that does NOT enforce PRs
					body := `[{"type": "deletion"}, {"type": "non_fast_forward"}]`
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(bytes.NewBufferString(body)),
					}, nil
				},
			},
		},
	}

	findings, err := p.Extract(context.Background(), "run-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if findings[0].Status != "PASS" {
		t.Errorf("expected branch protection to PASS, got %s", findings[0].Status)
	}
	if findings[1].Status != "FAIL" {
		t.Errorf("expected PR review to FAIL, got %s", findings[1].Status)
	}
}

