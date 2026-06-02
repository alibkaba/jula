package reporter

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/alibkaba/jula-core/pkg/types"
)

func BenchmarkLocalReporter_Deliver(b *testing.B) {
	// Silence slog during benchmarks
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))

	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpDir := b.TempDir()

	numEvidence := 1000
	evidence := make([]types.Evidence, numEvidence)
	for i := 0; i < numEvidence; i++ {
		evidence[i] = types.Evidence{
			PayloadHash: fmt.Sprintf("hash-%d", i),
			Finding: types.Finding{
				EvidenceID: fmt.Sprintf("EVID-TEST-%d", i),
				Provider:   "gcp",
				Timestamp:  time.Now().UTC(),
				RawData:    []byte(`{"status":"ok"}`),
			},
		}
	}

	r := &LocalReporter{
		OutputDir:  tmpDir,
		SigningKey: privKey,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := r.Deliver(context.Background(), evidence, "bench-run")
		if err != nil {
			b.Fatal(err)
		}
	}
}
