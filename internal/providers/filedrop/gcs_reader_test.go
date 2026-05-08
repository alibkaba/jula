package filedrop

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"testing"
)

type mockTokenProvider struct {
	token string
	err   error
}

func (m *mockTokenProvider) Token() (string, error) {
	return m.token, m.err
}

type mockTransport struct {
	roundTripFunc func(req *http.Request) (*http.Response, error)
}

func (m *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return m.roundTripFunc(req)
}

func TestGCSReader_ListFiles(t *testing.T) {
	r := &GCSReader{
		BucketName: "test-bucket",
		HTTPClient: &http.Client{
			Transport: &mockTransport{
				roundTripFunc: func(req *http.Request) (*http.Response, error) {
					body := `{"items": [{"name": "file1.json"}, {"name": "file2.json"}]}`
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(bytes.NewBufferString(body)),
					}, nil
				},
			},
		},
		TokenProvider: &mockTokenProvider{token: "test"},
	}

	keys, err := r.ListFiles(context.Background(), "prefix/")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(keys) != 2 || keys[0] != "file1.json" || keys[1] != "file2.json" {
		t.Errorf("unexpected keys: %v", keys)
	}
}

func TestGCSReader_GetFile(t *testing.T) {
	r := &GCSReader{
		BucketName: "test-bucket",
		HTTPClient: &http.Client{
			Transport: &mockTransport{
				roundTripFunc: func(req *http.Request) (*http.Response, error) {
					return &http.Response{
						StatusCode: http.StatusOK,
						Header: http.Header{
							"Content-Type": []string{"application/json"},
							"Etag":         []string{"12345"},
						},
						Body: io.NopCloser(bytes.NewBufferString(`{"data": "test"}`)),
					}, nil
				},
			},
		},
		TokenProvider: &mockTokenProvider{token: "test"},
	}

	body, meta, err := r.GetFile(context.Background(), "file1.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer body.Close()

	content, _ := io.ReadAll(body)
	if string(content) != `{"data": "test"}` {
		t.Errorf("unexpected body: %s", string(content))
	}

	if meta["content_type"] != "application/json" {
		t.Errorf("unexpected content type: %s", meta["content_type"])
	}
}

func TestGCSReader_TokenError(t *testing.T) {
	r := &GCSReader{
		TokenProvider: &mockTokenProvider{err: errors.New("auth failed")},
	}

	_, err := r.ListFiles(context.Background(), "")
	if err == nil {
		t.Error("expected error, got nil")
	}

	_, _, err = r.GetFile(context.Background(), "")
	if err == nil {
		t.Error("expected error, got nil")
	}
}
