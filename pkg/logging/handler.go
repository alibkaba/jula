package logging

import (
	"bytes"
	"compress/gzip"
	"context"
	"log/slog"
	"regexp"
	"sync"
)

var (
	// globalCapturingHandler keeps a global reference to the capturing handler.
	globalCapturingHandler *CapturingHandler
	globalMu               sync.RWMutex

	// secretPatterns matches common sensitive keys, tokens, and authorization values.
	secretPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)bearer\s+[A-Za-z0-9\-\._~\+\/]+=*`),
		regexp.MustCompile(`(?i)(key|password|secret|token|credential|passphrase|auth|signature)\s*[:=]\s*[^\s,{}"]+`),
	}
)

// CapturingHandler wraps an underlying slog.Handler, intercepts log lines,
// applies regex masking to sensitive parameters, and records logs in a memory buffer.
type CapturingHandler struct {
	slog.Handler
	mu  sync.Mutex
	buf bytes.Buffer
}

// NewCapturingHandler instantiates a thread-safe CapturingHandler.
func NewCapturingHandler(parent slog.Handler) *CapturingHandler {
	return &CapturingHandler{
		Handler: parent,
	}
}

// SetGlobalHandler sets the global capturing handler reference.
func SetGlobalHandler(h *CapturingHandler) {
	globalMu.Lock()
	defer globalMu.Unlock()
	globalCapturingHandler = h
}

// GetGlobalHandler retrieves the active global capturing handler reference.
func GetGlobalHandler() *CapturingHandler {
	globalMu.RLock()
	defer globalMu.RUnlock()
	return globalCapturingHandler
}

// Handle intercepts log records, forwards them to the underlying handler,
// formats the log line, masks secrets, and writes it to the internal buffer.
func (h *CapturingHandler) Handle(ctx context.Context, r slog.Record) error {
	// First, let the parent handler run (prints log output to console/stderr)
	err := h.Handler.Handle(ctx, r)

	// Format record as text row
	var line bytes.Buffer
	line.WriteString(r.Time.UTC().Format("2006-01-02T15:04:05.000Z") + " [" + r.Level.String() + "] " + r.Message)
	r.Attrs(func(a slog.Attr) bool {
		line.WriteString(" " + a.Key + "=" + a.Value.String())
		return true
	})
	line.WriteString("\n")

	// Apply regex masking to the line
	maskedBytes := maskSecrets(line.Bytes())

	// Append to captured buffer
	h.mu.Lock()
	h.buf.Write(maskedBytes)
	h.mu.Unlock()

	return err
}

// WithAttrs returns a new handler with the given attributes.
func (h *CapturingHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &CapturingHandler{
		Handler: h.Handler.WithAttrs(attrs),
	}
}

// WithGroup returns a new handler with the given group name.
func (h *CapturingHandler) WithGroup(name string) slog.Handler {
	return &CapturingHandler{
		Handler: h.Handler.WithGroup(name),
	}
}

// GzipBytes returns the gzipped representation of the accumulated logs.
func (h *CapturingHandler) GzipBytes() ([]byte, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	var gBuf bytes.Buffer
	gw := gzip.NewWriter(&gBuf)
	if _, err := gw.Write(h.buf.Bytes()); err != nil {
		return nil, err
	}
	if err := gw.Close(); err != nil {
		return nil, err
	}
	return gBuf.Bytes(), nil
}

// Reset clears the captured log buffer.
func (h *CapturingHandler) Reset() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.buf.Reset()
}

// maskSecrets replaces sensitive matches with [MASKED].
func maskSecrets(src []byte) []byte {
	res := src
	for _, p := range secretPatterns {
		res = p.ReplaceAllFunc(res, func(match []byte) []byte {
			// Find the delimiter (e.g. colon, equals, bearer prefix) and mask only the value part
			idx := bytes.IndexAny(match, ":= ")
			if idx == -1 {
				return []byte("[MASKED]")
			}
			prefix := match[:idx+1]
			out := make([]byte, len(prefix)+len("[MASKED]"))
			copy(out, prefix)
			copy(out[len(prefix):], "[MASKED]")
			return out
		})
	}
	return res
}
