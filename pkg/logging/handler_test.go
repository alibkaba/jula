package logging

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"
)

func TestCapturingHandler_CaptureAndMask(t *testing.T) {
	// Setup standard slog JSON handler discarding stdout so we test duplication
	discardHandler := slog.NewJSONHandler(io.Discard, nil)
	capturer := NewCapturingHandler(discardHandler)

	logger := slog.New(capturer)
	ctx := context.Background()

	// Log some data including sensitive keys
	logger.InfoContext(ctx, "Starting session", slog.String("user", "alice"))
	logger.InfoContext(ctx, "Authenticating API", slog.String("auth", "Bearer secret-token-12345"))
	logger.InfoContext(ctx, "Configuring database", slog.String("password", "super-secure-pass"))

	// Retrieve logs
	rawLogs := string(capturer.buf.Bytes())

	if !strings.Contains(rawLogs, "Starting session user=alice") {
		t.Errorf("expected logs to contain basic log info, got:\n%s", rawLogs)
	}

	if !strings.Contains(rawLogs, "auth=[MASKED]") {
		t.Errorf("expected authorization header to be masked, got:\n%s", rawLogs)
	}

	if !strings.Contains(rawLogs, "password=[MASKED]") {
		t.Errorf("expected password to be masked, got:\n%s", rawLogs)
	}
}

func TestCapturingHandler_GzipCompression(t *testing.T) {
	discardHandler := slog.NewJSONHandler(io.Discard, nil)
	capturer := NewCapturingHandler(discardHandler)
	logger := slog.New(capturer)

	logger.Info("Hello World")

	gzBytes, err := capturer.GzipBytes()
	if err != nil {
		t.Fatalf("failed to compress logs: %v", err)
	}

	// Decompress and check
	gr, err := gzip.NewReader(bytes.NewReader(gzBytes))
	if err != nil {
		t.Fatalf("failed to create gzip reader: %v", err)
	}
	defer gr.Close()

	decompressed, err := io.ReadAll(gr)
	if err != nil {
		t.Fatalf("failed to read decompressed logs: %v", err)
	}

	if !strings.Contains(string(decompressed), "Hello World") {
		t.Errorf("decompressed logs did not contain original message, got: %s", string(decompressed))
	}
}

func TestGlobalHandler(t *testing.T) {
	discardHandler := slog.NewJSONHandler(io.Discard, nil)
	capturer := NewCapturingHandler(discardHandler)

	SetGlobalHandler(capturer)
	if got := GetGlobalHandler(); got != capturer {
		t.Errorf("GetGlobalHandler() = %v, want %v", got, capturer)
	}
}


func TestCapturingHandler_Reset(t *testing.T) {
	discardHandler := slog.NewJSONHandler(io.Discard, nil)
	capturer := NewCapturingHandler(discardHandler)
	logger := slog.New(capturer)

	logger.Info("Before reset")
	if capturer.buf.Len() == 0 {
		t.Errorf("Expected buffer to not be empty")
	}

	capturer.Reset()
	if capturer.buf.Len() != 0 {
		t.Errorf("Expected buffer to be empty after Reset(), got len %d", capturer.buf.Len())
	}
}

func TestCapturingHandler_WithAttrs(t *testing.T) {
	discardHandler := slog.NewJSONHandler(io.Discard, nil)
	capturer := NewCapturingHandler(discardHandler)
	attrs := []slog.Attr{slog.String("key", "value")}
	newHandler := capturer.WithAttrs(attrs)

	_, ok := newHandler.(*CapturingHandler)
	if !ok {
		t.Errorf("WithAttrs did not return a *CapturingHandler")
	}
}

func TestCapturingHandler_WithGroup(t *testing.T) {
	discardHandler := slog.NewJSONHandler(io.Discard, nil)
	capturer := NewCapturingHandler(discardHandler)
	newHandler := capturer.WithGroup("group")

	_, ok := newHandler.(*CapturingHandler)
	if !ok {
		t.Errorf("WithGroup did not return a *CapturingHandler")
	}
}
