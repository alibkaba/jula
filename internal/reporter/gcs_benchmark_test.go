package reporter

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/alibkaba/jula-evidence-collector/pkg/types"
)

func BenchmarkGCSReporterDeliver(b *testing.B) {
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	reporter := &GCSReporter{
		BucketName:       "test-bucket",
		SigningKey:       key,
		HTTPClient:       server.Client(),
		TokenProvider:    &staticToken{token: "mock-token"},
		Format:           "json",
		ConsolidatedOnly: true, // we only care about testing grouping logic which creates the consolidated file
		baseURL:          server.URL,
	}

	numFrameworks := 5
	numEvidences := 1000

	var evidence []types.Evidence
	for i := 0; i < numEvidences; i++ {
		framework := fmt.Sprintf("framework-%d", i%numFrameworks)
		evidence = append(evidence, types.Evidence{
			Framework: framework,
			Finding: types.Finding{
				ID:       fmt.Sprintf("finding-%d", i),
				Provider: "test",
			},
		})
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := reporter.Deliver(context.Background(), evidence, "test-run")
		if err != nil {
			b.Fatalf("Deliver failed: %v", err)
		}
	}
}
