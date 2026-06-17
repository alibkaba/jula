package objstore

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestGCSStore(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/b/my-bucket/o") && r.Method == "POST" {
			w.WriteHeader(http.StatusOK)
		} else if strings.Contains(r.URL.Path, "/b/my-bucket/o/test.txt") && r.Method == "GET" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("hello world"))
		} else if strings.Contains(r.URL.Path, "/b/my-bucket/o/error.txt") && r.Method == "GET" {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte("not found"))
		} else if strings.Contains(r.URL.Path, "/b/my-bucket/o") && r.Method == "GET" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"items": [{"name": "file1.txt"}]}`))
		} else if r.URL.Path == "/token" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"access_token": "token123", "expires_in": 3600}`))
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()

	fetcher := func(client *http.Client) (string, time.Duration, error) {
		return "token123", 3600 * time.Second, nil
	}

	store := NewGCSStore("my-bucket", http.DefaultClient, WithGCSBaseURL(ts.URL), WithGCSTokenFetcher(fetcher))

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

	t.Run("GCS uploadURL and apiURL when baseURL is not set", func(t *testing.T) {
		s := NewGCSStore("my-bucket", http.DefaultClient)
		if url := s.uploadURL(); url != "https://storage.googleapis.com/upload/storage/v1" {
			t.Errorf("unexpected uploadURL: %v", url)
		}
		if url := s.apiURL(); url != "https://storage.googleapis.com/storage/v1" {
			t.Errorf("unexpected apiURL: %v", url)
		}
	})

	t.Run("Get error from GCS", func(t *testing.T) {
		_, err := store.Get(context.Background(), "error.txt")
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})

	t.Run("List error from GCS", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := store.List(ctx, "")
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})

	t.Run("Put error reading payload", func(t *testing.T) {
		err := store.Put(context.Background(), "test.txt", errReaderLocal{}, "text/plain")
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})

	t.Run("fetchGCSToken connection error", func(t *testing.T) {
		s := NewGCSStore("my-bucket", http.DefaultClient)
		t.Setenv("GCE_METADATA_HOST", "127.0.0.1:0") // invalid host
		_, err := s.List(context.Background(), "")
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})
}
