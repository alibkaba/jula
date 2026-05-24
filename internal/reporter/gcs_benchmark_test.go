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

	"github.com/alibkaba/jula-core/pkg/types"
)

func BenchmarkGCSReporterDeliver(b *testing.B) {
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	reporter := &GCSReporter{
		BucketName:    "test-bucket",
		SigningKey:    key,
		HTTPClient:    server.Client(),
		TokenProvider: &staticToken{token: "mock-token"},
		baseURL:       server.URL,
	}

	numEvidences := 1000

	var evidence []types.Evidence
	for i := 0; i < numEvidences; i++ {
		evidence = append(evidence, types.Evidence{
			PayloadHash: fmt.Sprintf("hash-%d", i),
			Finding: types.Finding{
				EvidenceID:    fmt.Sprintf("EVID-TEST-%d", i),
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
