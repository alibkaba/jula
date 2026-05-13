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

func TestParseEnvList(t *testing.T) {
	t.Setenv("TEST_EMPTY", "")
	t.Setenv("TEST_LIST", "a,b,c")

	if res := parseEnvList("TEST_EMPTY"); res != nil {
		t.Errorf("expected nil, got %v", res)
	}

	res := parseEnvList("TEST_LIST")
	if len(res) != 3 || res[0] != "a" || res[1] != "b" || res[2] != "c" {
		t.Errorf("expected [a b c], got %v", res)
	}
}

func TestFetchSBOM(t *testing.T) {
	p := New()

	t.Run("success", func(t *testing.T) {
		p.client.Transport = &mockTransport{
			roundTripFunc: func(req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewBufferString(`{"bomFormat": "CycloneDX"}`)),
				}, nil
			},
		}

		res, err := p.fetchSBOM(context.Background(), "token", "http://test")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res["bomFormat"] != "CycloneDX" {
			t.Errorf("unexpected payload: %v", res)
		}
	})

	t.Run("404 not found", func(t *testing.T) {
		p.client.Transport = &mockTransport{
			roundTripFunc: func(req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusNotFound,
					Body:       io.NopCloser(bytes.NewBufferString(`{}`)),
				}, nil
			},
		}

		_, err := p.fetchSBOM(context.Background(), "token", "http://test")
		if !errors.Is(err, ErrResourceNotFound) {
			t.Errorf("expected ErrResourceNotFound, got %v", err)
		}
	})

	t.Run("rate limit retry", func(t *testing.T) {
		reqCount := 0
		p.client.Transport = &mockTransport{
			roundTripFunc: func(req *http.Request) (*http.Response, error) {
				reqCount++
				if reqCount == 1 {
					return &http.Response{
						StatusCode: http.StatusTooManyRequests,
						Body:       io.NopCloser(bytes.NewBufferString(`{}`)),
					}, nil
				}
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewBufferString(`{"bomFormat": "CycloneDX"}`)),
				}, nil
			},
		}

		res, err := p.fetchSBOM(context.Background(), "token", "http://test")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res["bomFormat"] != "CycloneDX" {
			t.Errorf("unexpected payload: %v", res)
		}
	})

	t.Run("500 error", func(t *testing.T) {
		p.client.Transport = &mockTransport{
			roundTripFunc: func(req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusInternalServerError,
					Body:       io.NopCloser(bytes.NewBufferString(`{"error":"server error"}`)),
				}, nil
			},
		}

		_, err := p.fetchSBOM(context.Background(), "token", "http://test")
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})

	t.Run("invalid json", func(t *testing.T) {
		p.client.Transport = &mockTransport{
			roundTripFunc: func(req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewBufferString(`invalid json`)),
				}, nil
			},
		}

		_, err := p.fetchSBOM(context.Background(), "token", "http://test")
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})
}

func TestBuildSBOMFinding(t *testing.T) {
	p := New()

	t.Run("success", func(t *testing.T) {
		sbom := map[string]any{"key": "value"}
		f := p.buildSBOMFinding("id", "type", "arn", "run", sbom, nil)
		if f.Status != "PASS" {
			t.Errorf("expected PASS, got %s", f.Status)
		}
		if f.RawPayload["key"] != "value" {
			t.Errorf("unexpected payload: %v", f.RawPayload)
		}
	})

	t.Run("not found error", func(t *testing.T) {
		f := p.buildSBOMFinding("id", "type", "arn", "run", nil, ErrResourceNotFound)
		if f.Status != "FAIL" {
			t.Errorf("expected FAIL, got %s", f.Status)
		}
		if f.RawPayload["error"] != "Resource not found (404)" {
			t.Errorf("unexpected payload: %v", f.RawPayload)
		}
	})

	t.Run("other error", func(t *testing.T) {
		f := p.buildSBOMFinding("id", "type", "arn", "run", nil, errors.New("timeout"))
		if f.Status != "FAIL" {
			t.Errorf("expected FAIL, got %s", f.Status)
		}
		if f.RawPayload["error"] != "timeout" {
			t.Errorf("unexpected payload: %v", f.RawPayload)
		}
	})
}

func TestAutoDiscoverHelpers(t *testing.T) {
	p := New()
	p.clientID = "test-client"
	p.secretKey = "test-secret"

	t.Run("success", func(t *testing.T) {
		p.client.Transport = &mockTransport{
			roundTripFunc: func(req *http.Request) (*http.Response, error) {
				if req.URL.Path == "/api/public/v1/repositories/code" {
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(bytes.NewBufferString(`[{"id": "auto-code-1"}, {"id": "auto-code-2"}]`)),
					}, nil
				}
				if req.URL.Path == "/api/public/v1/containers" {
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(bytes.NewBufferString(`[{"id": "auto-con-1"}]`)),
					}, nil
				}
				if req.URL.Path == "/api/public/v1/virtual-machines" {
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(bytes.NewBufferString(`[{"id": "auto-vm-1"}]`)),
					}, nil
				}
				return nil, errors.New("unexpected url: " + req.URL.Path)
			},
		}

		codeIDs, err := p.autoDiscoverCodeRepos(context.Background(), "token")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(codeIDs) != 2 || codeIDs[0] != "auto-code-1" || codeIDs[1] != "auto-code-2" {
			t.Errorf("unexpected codeIDs: %v", codeIDs)
		}

		conIDs, err := p.autoDiscoverContainers(context.Background(), "token")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(conIDs) != 1 || conIDs[0] != "auto-con-1" {
			t.Errorf("unexpected conIDs: %v", conIDs)
		}

		vmIDs, err := p.autoDiscoverVMs(context.Background(), "token")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(vmIDs) != 1 || vmIDs[0] != "auto-vm-1" {
			t.Errorf("unexpected vmIDs: %v", vmIDs)
		}
	})

	t.Run("http error", func(t *testing.T) {
		p.client.Transport = &mockTransport{
			roundTripFunc: func(req *http.Request) (*http.Response, error) {
				return nil, errors.New("network error")
			},
		}

		_, err := p.autoDiscoverCodeRepos(context.Background(), "token")
		if err == nil {
			t.Error("expected error, got nil")
		}

		_, err = p.autoDiscoverContainers(context.Background(), "token")
		if err == nil {
			t.Error("expected error, got nil")
		}

		_, err = p.autoDiscoverVMs(context.Background(), "token")
		if err == nil {
			t.Error("expected error, got nil")
		}
	})

	t.Run("decode error", func(t *testing.T) {
		p.client.Transport = &mockTransport{
			roundTripFunc: func(req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewBufferString(`invalid json`)),
				}, nil
			},
		}

		_, err := p.autoDiscoverCodeRepos(context.Background(), "token")
		if err == nil {
			t.Error("expected error, got nil")
		}

		_, err = p.autoDiscoverContainers(context.Background(), "token")
		if err == nil {
			t.Error("expected error, got nil")
		}

		_, err = p.autoDiscoverVMs(context.Background(), "token")
		if err == nil {
			t.Error("expected error, got nil")
		}
	})
}

func TestExtract_WithSBOMs(t *testing.T) {
	t.Setenv("AIK_CODE_REPO_IDS", "repo1")
	t.Setenv("AIK_CONTAINER_REPO_IDS", "con1")
	t.Setenv("AIK_VM_IDS", "vm1")

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
			if req.URL.Path == "/api/public/v1/repositories/code/repo1/licenses/export" {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewBufferString(`{"type": "code"}`)),
				}, nil
			}
			if req.URL.Path == "/api/public/v1/containers/con1/licenses/export" {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewBufferString(`{"type": "container"}`)),
				}, nil
			}
			if req.URL.Path == "/api/public/v1/virtual-machines/vm1/export/sbom" {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewBufferString(`{"type": "vm"}`)),
				}, nil
			}
			return nil, errors.New("unexpected url: " + req.URL.Path)
		},
	}

	findings, err := p.Extract(context.Background(), "run-123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// 1 for workspace PASS + 3 SBOMs = 4 findings
	if len(findings) != 4 {
		t.Fatalf("expected 4 findings, got %d", len(findings))
	}

	// Check the findings
	var foundCode, foundCon, foundVM bool
	for _, f := range findings {
		if f.ResourceIdentifier == "aikido:code_repo:repo1" {
			foundCode = true
		}
		if f.ResourceIdentifier == "aikido:container:con1" {
			foundCon = true
		}
		if f.ResourceIdentifier == "aikido:virtual_machine:vm1" {
			foundVM = true
		}
	}

	if !foundCode || !foundCon || !foundVM {
		t.Errorf("missing some expected SBOM findings")
	}
}
