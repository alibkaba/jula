package engine

import (
	"fmt"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/alibkaba/jula-evidence-collector/pkg/types"
)

func BenchmarkApplyExceptions(b *testing.B) {
	// Discard logs to prevent I/O bottleneck in benchmarks
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))

	o := &Orchestrator{
		exceptions: make([]types.Exception, 0, 1000),
	}
	for i := 0; i < 1000; i++ {
		o.exceptions = append(o.exceptions, types.Exception{
			ResourceIdentifier: fmt.Sprintf("resource-%d", i),
			Check:              fmt.Sprintf("check-%d", i),
			ExpiresAt:          time.Now().Add(24 * time.Hour),
		})
	}

	findings := make([]types.Finding, 0, 10000)
	for i := 0; i < 10000; i++ {
		findings = append(findings, types.Finding{
			Status:             "FAIL",
			ResourceIdentifier: fmt.Sprintf("resource-%d", i%2000),
			Check:              fmt.Sprintf("check-%d", i%2000),
		})
	}

	now := time.Now()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		findingsCopy := make([]types.Finding, len(findings))
		copy(findingsCopy, findings)
		o.ApplyExceptions(findingsCopy, now)
	}
}
