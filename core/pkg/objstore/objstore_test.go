package objstore

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestGCSStore_PutGet(t *testing.T) {
	storage := make(map[string][]byte)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/o"):
			// Upload.
			name := r.URL.Query().Get("name")
			body, _ := io.ReadAll(r.Body)
			storage[name] = body
			w.WriteHeader(http.StatusOK)

		case r.Method == http.MethodGet && strings.Contains(r.URL.Query().Get("alt"), "media"):
			// Download.
			parts := strings.Split(r.URL.Path, "/o/")
			if len(parts) < 2 {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			key := parts[1]
			data, ok := storage[key]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.Write(data)

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	store := newgcsStore("test-bucket", server.Client(),
		withGCSBaseURL(server.URL),
		withGCSTokenFetcher(func(client *http.Client) (string, time.Duration, error) {
			return "mock-token", 1 * time.Hour, nil
		}),
	)

	ctx := context.Background()

	// Put.
	content := []byte(`{"test": true}`)
	err := store.Put(ctx, "evidence/test.json", bytes.NewReader(content), "application/json")
	if err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	// Get.
	rc, err := store.Get(ctx, "evidence/test.json")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	defer rc.Close()
	got, _ := io.ReadAll(rc)
	if !bytes.Equal(got, content) {
		t.Fatalf("content mismatch: got %q", string(got))
	}
}

func TestGCSStore_List(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]any{
			"items": []map[string]string{
				{"name": "deploy-abc/ev1.json", "size": "100"},
				{"name": "deploy-abc/ev2.json", "size": "200"},
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	store := newgcsStore("test-bucket", server.Client(),
		withGCSBaseURL(server.URL),
		withGCSTokenFetcher(func(client *http.Client) (string, time.Duration, error) {
			return "mock-token", 1 * time.Hour, nil
		}),
	)

	objects, err := store.List(context.Background(), "deploy-abc/")
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(objects) != 2 {
		t.Fatalf("expected 2 objects, got %d", len(objects))
	}
	if objects[0].Key != "deploy-abc/ev1.json" {
		t.Fatalf("unexpected key: %q", objects[0].Key)
	}
}

func TestS3Store_PutGet(t *testing.T) {
	storage := make(map[string][]byte)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Strip bucket prefix from path.
		path := strings.TrimPrefix(r.URL.Path, "/test-bucket/")

		switch r.Method {
		case http.MethodPut:
			body, _ := io.ReadAll(r.Body)
			storage[path] = body
			w.WriteHeader(http.StatusOK)

		case http.MethodGet:
			if strings.Contains(r.URL.RawQuery, "list-type") {
				// List response.
				resp := s3ListResponse{
					Contents: []s3ListObject{},
				}
				for k := range storage {
					prefix := r.URL.Query().Get("prefix")
					if strings.HasPrefix(k, prefix) {
						resp.Contents = append(resp.Contents, s3ListObject{Key: k, Size: int64(len(storage[k]))})
					}
				}
				w.Header().Set("Content-Type", "application/xml")
				xml.NewEncoder(w).Encode(resp)
				return
			}

			data, ok := storage[path]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.Write(data)

		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	defer server.Close()

	// Create static credential provider for testing.
	staticCreds := &staticCredProvider{
		creds: Credentials{
			AccessKeyID:     "AKIATESTKEY",
			SecretAccessKey: "testsecret",
		},
	}

	store := news3Store("test-bucket", "us-east-1", server.Client(),
		withS3BaseURL(server.URL),
		withS3Credentials(staticCreds),
	)

	ctx := context.Background()

	// Put.
	content := []byte(`{"s3": "test-data"}`)
	err := store.Put(ctx, "evidence/test.json", bytes.NewReader(content), "application/json")
	if err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	// Get.
	rc, err := store.Get(ctx, "evidence/test.json")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	defer rc.Close()
	got, _ := io.ReadAll(rc)
	if !bytes.Equal(got, content) {
		t.Fatalf("content mismatch: got %q", string(got))
	}

	// List.
	objects, err := store.List(ctx, "evidence/")
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(objects) != 1 {
		t.Fatalf("expected 1 object, got %d", len(objects))
	}
}

func TestFactory_GCS(t *testing.T) {
	store, prefix, err := FromURL("gs://my-bucket/deploy-abc/2026-01-15", nil)
	if err != nil {
		t.Fatalf("FromURL failed: %v", err)
	}
	if store.Bucket() != "my-bucket" {
		t.Fatalf("expected bucket 'my-bucket', got %q", store.Bucket())
	}
	if prefix != "deploy-abc/2026-01-15" {
		t.Fatalf("expected prefix 'deploy-abc/2026-01-15', got %q", prefix)
	}
}

func TestFactory_S3(t *testing.T) {
	store, prefix, err := FromURL("s3://my-s3-bucket/some-prefix", nil)
	if err != nil {
		t.Fatalf("FromURL failed: %v", err)
	}
	if store.Bucket() != "my-s3-bucket" {
		t.Fatalf("expected bucket 'my-s3-bucket', got %q", store.Bucket())
	}
	if prefix != "some-prefix" {
		t.Fatalf("expected prefix 'some-prefix', got %q", prefix)
	}
}

func TestFactory_Local(t *testing.T) {
	store, prefix, err := FromURL("./test-dir", nil)
	if err != nil {
		t.Fatalf("FromURL failed: %v", err)
	}
	if store.Bucket() != "./test-dir" {
		t.Fatalf("expected bucket './test-dir', got %q", store.Bucket())
	}
	if prefix != "" {
		t.Fatalf("expected empty prefix, got %q", prefix)
	}
}

func TestFactory_FileScheme(t *testing.T) {
	store, _, err := FromURL("file:///tmp/evidence", nil)
	if err != nil {
		t.Fatalf("FromURL failed: %v", err)
	}
	if store.Bucket() != "/tmp/evidence" {
		t.Fatalf("expected bucket '/tmp/evidence', got %q", store.Bucket())
	}
}

func TestFactory_EmptyBucket(t *testing.T) {
	_, _, err := FromURL("gs://", nil)
	if err == nil {
		t.Fatal("expected error for empty bucket")
	}
}

func TestParseBucketURL(t *testing.T) {
	tests := []struct {
		url    string
		bucket string
		prefix string
	}{
		{"gs://my-bucket", "my-bucket", ""},
		{"gs://my-bucket/", "my-bucket", ""},
		{"gs://my-bucket/deploy-abc/2026-01-15", "my-bucket", "deploy-abc/2026-01-15"},
		{"s3://my-bucket/prefix", "my-bucket", "prefix"},
	}

	for _, tt := range tests {
		bucket, prefix := parseBucketURL(tt.url)
		if bucket != tt.bucket || prefix != tt.prefix {
			t.Fatalf("parseBucketURL(%q) = (%q, %q), want (%q, %q)", tt.url, bucket, prefix, tt.bucket, tt.prefix)
		}
	}
}

// staticCredProvider is a test helper that returns fixed credentials.
type staticCredProvider struct {
	creds Credentials
}

func (p *staticCredProvider) Resolve() (Credentials, error) {
	return p.creds, nil
}

func TestGCSStore_Errors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal error"))
	}))
	defer server.Close()

	store := newgcsStore("test-bucket", server.Client(),
		withGCSBaseURL(server.URL),
		withGCSTokenFetcher(func(client *http.Client) (string, time.Duration, error) {
			return "mock-token", 1 * time.Hour, nil
		}),
	)

	ctx := context.Background()

	// Put error
	err := store.Put(ctx, "evidence/test.json", bytes.NewReader([]byte("test")), "application/json")
	if err == nil {
		t.Fatal("Put expected error, got nil")
	}

	// Get error
	_, err = store.Get(ctx, "evidence/test.json")
	if err == nil {
		t.Fatal("Get expected error, got nil")
	}

	// List error
	_, err = store.List(ctx, "evidence/")
	if err == nil {
		t.Fatal("List expected error, got nil")
	}
}

func TestGCSStore_TokenError(t *testing.T) {
	store := newgcsStore("test-bucket", nil,
		withGCSTokenFetcher(func(client *http.Client) (string, time.Duration, error) {
			return "", 0, errors.New("token error")
		}),
	)

	ctx := context.Background()

	// Put error
	err := store.Put(ctx, "test.json", bytes.NewReader(nil), "")
	if err == nil {
		t.Fatal("Put expected token error, got nil")
	}

	// Get error
	_, err = store.Get(ctx, "test.json")
	if err == nil {
		t.Fatal("Get expected token error, got nil")
	}

	// List error
	_, err = store.List(ctx, "")
	if err == nil {
		t.Fatal("List expected token error, got nil")
	}
}

func TestS3Store_Errors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal error"))
	}))
	defer server.Close()

	staticCreds := &staticCredProvider{
		creds: Credentials{
			AccessKeyID:     "AKIATESTKEY",
			SecretAccessKey: "testsecret",
		},
	}

	store := news3Store("test-bucket", "us-east-1", server.Client(),
		withS3BaseURL(server.URL),
		withS3Credentials(staticCreds),
	)

	ctx := context.Background()

	// Put error
	err := store.Put(ctx, "evidence/test.json", bytes.NewReader([]byte("test")), "application/json")
	if err == nil {
		t.Fatal("Put expected error, got nil")
	}

	// Get error
	_, err = store.Get(ctx, "evidence/test.json")
	if err == nil {
		t.Fatal("Get expected error, got nil")
	}

	// List error
	_, err = store.List(ctx, "evidence/")
	if err == nil {
		t.Fatal("List expected error, got nil")
	}
}

func TestS3Store_CredError(t *testing.T) {
	store := news3Store("test-bucket", "us-east-1", nil,
		withS3Credentials(&errorCredProvider{}),
	)

	ctx := context.Background()

	// Put error
	err := store.Put(ctx, "test.json", bytes.NewReader(nil), "")
	if err == nil {
		t.Fatal("Put expected cred error, got nil")
	}

	// Get error
	_, err = store.Get(ctx, "test.json")
	if err == nil {
		t.Fatal("Get expected cred error, got nil")
	}

	// List error
	_, err = store.List(ctx, "")
	if err == nil {
		t.Fatal("List expected cred error, got nil")
	}
}

type errorCredProvider struct{}

func (p *errorCredProvider) Resolve() (Credentials, error) {
	return Credentials{}, errors.New("cred error")
}
