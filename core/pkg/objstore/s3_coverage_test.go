package objstore

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type staticCredentialProvider struct {
	creds Credentials
}

func (p staticCredentialProvider) Resolve() (Credentials, error) {
	return p.creds, nil
}

func TestS3Store(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/my-bucket/test.txt") && r.Method == "PUT" {
			w.WriteHeader(http.StatusOK)
		} else if strings.Contains(r.URL.Path, "/my-bucket/test.txt") && r.Method == "GET" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("hello world"))
		} else if strings.Contains(r.URL.Path, "/my-bucket/error.txt") && r.Method == "GET" {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte("not found"))
		} else if strings.Contains(r.URL.Path, "/my-bucket") && r.Method == "GET" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?>
			<ListBucketResult>
				<Contents>
					<Key>file1.txt</Key>
				</Contents>
			</ListBucketResult>`))
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()

	credsProv := staticCredentialProvider{creds: Credentials{AccessKeyID: "ak", SecretAccessKey: "sk"}}
	store := NewS3Store("my-bucket", "us-east-1", http.DefaultClient, WithS3BaseURL(ts.URL), WithS3Credentials(credsProv))

	t.Run("Bucket", func(t *testing.T) {
		if store.Bucket() != "my-bucket" {
			t.Errorf("expected my-bucket, got %s", store.Bucket())
		}
	})

	t.Run("Put", func(t *testing.T) {
		err := store.Put(context.Background(), "test.txt", strings.NewReader("hello"), "text/plain")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("Get", func(t *testing.T) {
		rc, err := store.Get(context.Background(), "test.txt")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer rc.Close()
		content, _ := io.ReadAll(rc)
		if string(content) != "hello world" {
			t.Errorf("expected hello world, got %s", string(content))
		}
	})

	t.Run("List", func(t *testing.T) {
		items, err := store.List(context.Background(), "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(items) != 1 || items[0].Key != "file1.txt" {
			t.Errorf("unexpected list items: %v", items)
		}
	})

	t.Run("bucketURL without baseURL", func(t *testing.T) {
		s := NewS3Store("my-bucket", "us-east-1", http.DefaultClient)
		if url := s.bucketURL(); url != "https://s3.us-east-1.amazonaws.com/my-bucket" {
			t.Errorf("unexpected bucketURL: %v", url)
		}
	})

	t.Run("sign without credentials", func(t *testing.T) {
		s := NewS3Store("my-bucket", "us-east-1", http.DefaultClient)
		req, _ := http.NewRequest("GET", "http://example.com", nil)
		err := s.sign(req, "")
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})

	t.Run("Put error reading payload", func(t *testing.T) {
		err := store.Put(context.Background(), "test.txt", errReader{}, "text/plain")
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})

	t.Run("Get error from S3", func(t *testing.T) {
		_, err := store.Get(context.Background(), "error.txt")
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})

	t.Run("List error from S3", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := store.List(ctx, "")
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})
}
