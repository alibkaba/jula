package objstore

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLocalStore(t *testing.T) {
	dir, err := os.MkdirTemp("", "jula-local-store-test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(dir)

	store := NewLocalStore(dir)

	t.Run("Bucket", func(t *testing.T) {
		if store.Bucket() != dir {
			t.Errorf("expected %s, got %s", dir, store.Bucket())
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
		if string(content) != "hello" {
			t.Errorf("expected hello, got %s", string(content))
		}
	})

	t.Run("List", func(t *testing.T) {
		err := store.Put(context.Background(), "test2.txt", strings.NewReader("hello"), "text/plain")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		items, err := store.List(context.Background(), "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(items) != 2 {
			t.Errorf("expected 2 items, got %d", len(items))
		}
	})

	t.Run("Get not found", func(t *testing.T) {
		_, err := store.Get(context.Background(), "not-found.txt")
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})

	t.Run("Put with subdirs", func(t *testing.T) {
		err := store.Put(context.Background(), "a/b/c/test.txt", strings.NewReader("hello"), "text/plain")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("List with prefix", func(t *testing.T) {
		items, err := store.List(context.Background(), "a/")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(items) != 1 {
			t.Errorf("expected 1 item, got %d", len(items))
		}
	})

	t.Run("List directory not found error", func(t *testing.T) {
		store2 := NewLocalStore(filepath.Join(dir, "not-found"))
		_, err := store2.List(context.Background(), "")
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})
}

type errReaderLocal struct{}

func (errReaderLocal) Read(p []byte) (n int, err error) {
	return 0, os.ErrPermission
}

func TestLocalStore_PutError(t *testing.T) {
	dir, _ := os.MkdirTemp("", "jula-local-store-test")
	defer os.RemoveAll(dir)
	store := NewLocalStore(dir)

	err := store.Put(context.Background(), "test.txt", errReaderLocal{}, "text/plain")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}
