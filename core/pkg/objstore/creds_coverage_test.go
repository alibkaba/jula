package objstore

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

type mockRoundTripper struct {
	fn func(*http.Request) (*http.Response, error)
}

func (m *mockRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return m.fn(req)
}

func TestECSCredentialProvider_Resolve(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v2/credentials/role123" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"AccessKeyId":"AKIAIOSFODNN7EXAMPLE","SecretAccessKey":"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY","Token":"token","Expiration":"2026-01-01T00:00:00Z"}`))
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()

	t.Run("success with full URI", func(t *testing.T) {
		t.Setenv("AWS_CONTAINER_CREDENTIALS_FULL_URI", ts.URL+"/v2/credentials/role123")
		t.Setenv("AWS_CONTAINER_AUTHORIZATION_TOKEN", "my-token")

		p := newECSCredentialProvider(http.DefaultClient)
		creds, err := p.Resolve()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if creds.AccessKeyID != "AKIAIOSFODNN7EXAMPLE" {
			t.Errorf("expected AKIAIOSFODNN7EXAMPLE, got %v", creds.AccessKeyID)
		}

		// Resolve again to hit cache
		credsCached, err := p.Resolve()
		if err != nil {
			t.Fatalf("unexpected error on second resolve: %v", err)
		}
		if credsCached.AccessKeyID != "AKIAIOSFODNN7EXAMPLE" {
			t.Errorf("expected cached AKIAIOSFODNN7EXAMPLE, got %v", credsCached.AccessKeyID)
		}
	})

	t.Run("error missing vars", func(t *testing.T) {
		// Ensure environment variables are not set for this test
		os.Unsetenv("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI")
		os.Unsetenv("AWS_CONTAINER_CREDENTIALS_FULL_URI")

		p := newECSCredentialProvider(http.DefaultClient)
		_, err := p.Resolve()
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})

	t.Run("error http error full URI", func(t *testing.T) {
		t.Setenv("AWS_CONTAINER_CREDENTIALS_FULL_URI", ts.URL+"/not-found")
		p := newECSCredentialProvider(http.DefaultClient)
		_, err := p.Resolve()
		if err == nil {
			t.Fatal("expected error for 404 response")
		}
	})

	t.Run("success with relative URI", func(t *testing.T) {
		t.Setenv("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "/v2/credentials/role123")

		mockTransport := &mockRoundTripper{
			fn: func(req *http.Request) (*http.Response, error) {
				if req.URL.Host == "169.254.170.2" && req.URL.Path == "/v2/credentials/role123" {
					rec := httptest.NewRecorder()
					rec.WriteHeader(http.StatusOK)
					rec.Write([]byte(`{"AccessKeyId":"AKIAIOSFODNN7EXAMPLE","SecretAccessKey":"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY","Token":"token","Expiration":"2026-01-01T00:00:00Z"}`))
					return rec.Result(), nil
				}
				return nil, os.ErrNotExist
			},
		}
		client := &http.Client{Transport: mockTransport}
		p := newECSCredentialProvider(client)
		creds, err := p.Resolve()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if creds.AccessKeyID != "AKIAIOSFODNN7EXAMPLE" {
			t.Errorf("expected AKIAIOSFODNN7EXAMPLE, got %v", creds.AccessKeyID)
		}
	})

	t.Run("decode error", func(t *testing.T) {
		t.Setenv("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "/v2/credentials/role123")
		mockTransport := &mockRoundTripper{
			fn: func(req *http.Request) (*http.Response, error) {
				rec := httptest.NewRecorder()
				rec.WriteHeader(http.StatusOK)
				rec.Write([]byte(`invalid json`))
				return rec.Result(), nil
			},
		}
		client := &http.Client{Transport: mockTransport}
		p := newECSCredentialProvider(client)
		_, err := p.Resolve()
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})

	t.Run("http request error", func(t *testing.T) {
		t.Setenv("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "/v2/credentials/role123")
		mockTransport := &mockRoundTripper{
			fn: func(req *http.Request) (*http.Response, error) {
				return nil, os.ErrNotExist
			},
		}
		client := &http.Client{Transport: mockTransport}
		p := newECSCredentialProvider(client)
		_, err := p.Resolve()
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})
}
