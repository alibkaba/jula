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
	"time"

	"github.com/alibkaba/jula-evidence-collector/pkg/types"
)

func BenchmarkGCSReporter_Deliver(b *testing.B) {
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))

	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	numEvidence := 5000
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

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	r := &GCSReporter{
		BucketName:       "test-bucket",
		SigningKey:       privKey,
		TokenProvider:    &staticToken{"test-token"},
		HTTPClient:       server.Client(),
		baseURL:          server.URL,
		ConsolidatedOnly: true,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := r.Deliver(context.Background(), evidence, "bench-run")
		if err != nil {
			b.Fatal(err)
		}
	}
}
