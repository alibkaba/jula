package logging

import (
	"bytes"
	"context"
	"log/slog"
	"testing"
	"time"
)

func TestCapturingHandler(t *testing.T) {
	parent := slog.NewTextHandler(&bytes.Buffer{}, nil)
	h := NewCapturingHandler(parent)
	SetGlobalHandler(h)

	if GetGlobalHandler() != h {
		t.Fatal("expected global handler to be set")
	}

	record := slog.NewRecord(time.Now(), slog.LevelInfo, "test message", 0)
	record.AddAttrs(slog.String("bearer", "secret-token-123"))
	record.AddAttrs(slog.String("password", "my-secret-pass"))

	err := h.Handle(context.Background(), record)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	h2 := h.WithAttrs([]slog.Attr{slog.String("attr", "val")})
	h3 := h2.WithGroup("group")
	if h3 == nil {
		t.Fatal("expected non-nil handler")
	}

	b, err := h.GzipBytes()
	if err != nil {
		t.Fatalf("unexpected gzip error: %v", err)
	}
	if len(b) == 0 {
		t.Fatal("expected gzipped bytes")
	}

	h.Reset()
	b2, _ := h.GzipBytes()
	if len(b2) == 0 {
		t.Fatal("expected empty gzip stream to still have headers")
	}
}
