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

	"github.com/alibkaba/jula-evidence-collector/pkg/types"
)

func BenchmarkLocalReporter_Deliver(b *testing.B) {
	// Silence slog during benchmarks
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))

	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpDir := b.TempDir()

	numEvidence := 10000
	numFrameworks := 100
	evidence := make([]types.Evidence, numEvidence)
	for i := 0; i < numEvidence; i++ {
		framework := fmt.Sprintf("framework-%d", i%numFrameworks)
		evidence[i] = types.Evidence{
			Finding: types.Finding{
				ID:                 fmt.Sprintf("finding-%d", i),
				Provider:           "gcp",
				ResourceIdentifier: fmt.Sprintf("res-%d", i),
				Timestamp:          time.Now().UTC(),
			},
			Framework: framework,
			Criteria:  []string{"C1"},
		}
	}

	r := &LocalReporter{
		OutputDir:        tmpDir,
		SigningKey:       privKey,
		ConsolidatedOnly: true, // Focus on the grouping logic and consolidation
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := r.Deliver(context.Background(), evidence, "bench-run")
		if err != nil {
			b.Fatal(err)
		}
	}
}
