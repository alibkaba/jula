package objstore

import (
	"net/http"
	"os"
	"testing"
)

func TestFactory_FromURL(t *testing.T) {
	t.Run("s3 url", func(t *testing.T) {
		t.Setenv("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "/test")
		store, prefix, err := FromURL("s3://my-bucket/path", http.DefaultClient)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if store == nil {
			t.Fatal("expected store, got nil")
		}
		if prefix != "path" {
			t.Errorf("expected path, got %s", prefix)
		}
	})

	t.Run("s3 invalid url", func(t *testing.T) {
		_, _, err := FromURL("s3://", http.DefaultClient)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})

	t.Run("gcs url", func(t *testing.T) {
		store, prefix, err := FromURL("gs://my-bucket/path", http.DefaultClient)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if store == nil {
			t.Fatal("expected store, got nil")
		}
		if prefix != "path" {
			t.Errorf("expected path, got %s", prefix)
		}
	})

	t.Run("gcs invalid url", func(t *testing.T) {
		_, _, err := FromURL("gs://", http.DefaultClient)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})

	t.Run("local url", func(t *testing.T) {
		dir, _ := os.MkdirTemp("", "jula-test")
		defer os.RemoveAll(dir)
		store, prefix, err := FromURL("file://"+dir, http.DefaultClient)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if store == nil {
			t.Fatal("expected store, got nil")
		}
		if prefix != "" {
			t.Errorf("expected empty prefix, got %s", prefix)
		}
	})

	t.Run("local plain path", func(t *testing.T) {
		dir, _ := os.MkdirTemp("", "jula-test")
		defer os.RemoveAll(dir)
		store, prefix, err := FromURL(dir, http.DefaultClient)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if store == nil {
			t.Fatal("expected store, got nil")
		}
		if prefix != "" {
			t.Errorf("expected empty prefix, got %s", prefix)
		}
	})

	t.Run("nil client", func(t *testing.T) {
		store, _, err := FromURL("file:///tmp", nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if store == nil {
			t.Fatal("expected store, got nil")
		}
	})
}
