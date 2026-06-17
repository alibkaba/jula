package objstore

import (
	"os"
	"strings"
	"testing"
	"time"
)

func TestCredentials_IsExpired(t *testing.T) {
	tests := []struct {
		name     string
		creds    Credentials
		buffer   time.Duration
		expected bool
	}{
		{
			name:     "no expiration set",
			creds:    Credentials{},
			buffer:   0,
			expected: false,
		},
		{
			name: "not expired",
			creds: Credentials{
				Expiration: time.Now().Add(10 * time.Minute),
			},
			buffer:   0,
			expected: false,
		},
		{
			name: "expired past absolute time",
			creds: Credentials{
				Expiration: time.Now().Add(-10 * time.Minute),
			},
			buffer:   0,
			expected: true,
		},
		{
			name: "expired within buffer",
			creds: Credentials{
				Expiration: time.Now().Add(2 * time.Minute),
			},
			buffer:   5 * time.Minute,
			expected: true,
		},
		{
			name: "not expired with buffer",
			creds: Credentials{
				Expiration: time.Now().Add(10 * time.Minute),
			},
			buffer:   5 * time.Minute,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.creds.IsExpired(tt.buffer); got != tt.expected {
				t.Errorf("IsExpired() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestHashReader(t *testing.T) {
	t.Run("valid reader", func(t *testing.T) {
		r := strings.NewReader("hello world")
		hash, content, err := hashReader(r)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		expectedHash := "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
		if hash != expectedHash {
			t.Errorf("expected %s, got %s", expectedHash, hash)
		}
		if string(content) != "hello world" {
			t.Errorf("expected content 'hello world', got '%s'", string(content))
		}

		// The hashReader function returns the read bytes

	})

	t.Run("nil reader", func(t *testing.T) {
		hash, content, err := hashReader(nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if hash == "" {
			t.Error("expected non-empty hash for nil reader")
		}
		if content != nil {
			t.Errorf("expected nil content, got %v", content)
		}
	})
}

type errReader struct{}

func (errReader) Read(p []byte) (n int, err error) {
	return 0, os.ErrPermission
}

func TestHashReader_Error(t *testing.T) {
	_, _, err := hashReader(errReader{})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}
