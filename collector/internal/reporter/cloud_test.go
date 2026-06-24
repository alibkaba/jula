package reporter

import (
	"context"
	stdcrypto "crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"io"
	"strings"
	"testing"

	"github.com/alibkaba/jula-core/pkg/types"
)

type mockStore struct {
	puts map[string][]byte
	err  error
}

func (m *mockStore) Put(ctx context.Context, key string, body io.Reader, contentType string) error {
	if m.err != nil {
		return m.err
	}
	if m.puts == nil {
		m.puts = make(map[string][]byte)
	}
	data, _ := io.ReadAll(body)
	m.puts[key] = data
	return nil
}

func TestCloudReporter_Name(t *testing.T) {
	r := &CloudReporter{}
	if r.Name() != "cloud" {
		t.Errorf("expected cloud, got %s", r.Name())
	}
}

func TestCloudReporter_Validate(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tests := []struct {
		name    string
		store   *mockStore
		key     *ecdsa.PrivateKey
		wantErr bool
	}{
		{"valid", &mockStore{}, key, false},
		{"nil store", nil, key, true},
		{"nil key", &mockStore{}, nil, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var signer stdcrypto.Signer
			if tt.key != nil {
				signer = tt.key
			}

			var storeInterface *mockStore
			if tt.store != nil {
				storeInterface = tt.store
			}

			r := &CloudReporter{}
			if storeInterface != nil {
				r.Store = storeInterface
			}
			r.SigningKey = signer

			err := r.Validate(context.Background())
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestParseOutputURL(t *testing.T) {
	tests := []struct {
		name       string
		deployID   string
		outputURL  string
		wantBucket string
		wantPrefix string
		wantErr    bool
	}{
		{
			name:       "gcs url",
			deployID:   "12345",
			outputURL:  "gs://my-bucket",
			wantBucket: "gs://my-bucket",
			wantPrefix: "deploy-12345/",
			wantErr:    false,
		},
		{
			name:       "s3 url",
			deployID:   "67890",
			outputURL:  "s3://my-bucket/prefix",
			wantBucket: "s3://my-bucket",
			wantPrefix: "deploy-67890/",
			wantErr:    false,
		},
		{
			name:       "local file",
			deployID:   "12345",
			outputURL:  "/tmp/output",
			wantBucket: "/tmp/output",
			wantPrefix: "20",
			wantErr:    false,
		},
		{
			name:       "missing deploy id",
			deployID:   "",
			outputURL:  "gs://my-bucket",
			wantBucket: "",
			wantPrefix: "",
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.deployID != "" {
				t.Setenv("JULA_DEPLOYMENT_ID", tt.deployID)
			} else {
				t.Setenv("JULA_DEPLOYMENT_ID", "")
			}

			gotBucket, gotPrefix, err := ParseOutputURL(tt.outputURL)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseOutputURL() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				return
			}

			if gotBucket != tt.wantBucket {
				t.Errorf("ParseOutputURL() gotBucket = %v, want %v", gotBucket, tt.wantBucket)
			}

			if !strings.HasPrefix(gotPrefix, tt.wantPrefix) {
				t.Errorf("ParseOutputURL() gotPrefix = %v, want prefix to start with %v", gotPrefix, tt.wantPrefix)
			}
		})
	}
}

func TestCloudReporter_Deliver(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	tests := []struct {
		name      string
		store     *mockStore
		evidence  []types.Evidence
		runID     string
		cancelCtx bool
		wantErr   bool
		wantFiles int // Number of evidence/provenance files expected in manifest
	}{
		{
			name:  "success with evidence",
			store: &mockStore{puts: make(map[string][]byte)},
			evidence: []types.Evidence{
				{
					EvidenceID:  "EVID-1",
					ControlID:   "CTRL-1",
					SourceID:    "src-1",
					PayloadHash: "hash1",
					Finding: types.Finding{
						Provider: "gcp",
					},
				},
			},
			runID:     "run-123",
			cancelCtx: false,
			wantErr:   false,
			wantFiles: 2, // 1 evidence + 1 prov
		},
		{
			name:  "store put error",
			store: &mockStore{err: io.EOF, puts: make(map[string][]byte)},
			evidence: []types.Evidence{
				{
					EvidenceID:  "EVID-1",
					ControlID:   "CTRL-1",
					SourceID:    "src-1",
					PayloadHash: "hash1",
					Finding: types.Finding{
						Provider: "gcp",
					},
				},
			},
			runID:     "run-123",
			cancelCtx: false,
			wantErr:   true,
			wantFiles: 0,
		},
		{
			name:  "context cancelled",
			store: &mockStore{puts: make(map[string][]byte)},
			evidence: []types.Evidence{
				{
					EvidenceID:  "EVID-1",
					ControlID:   "CTRL-1",
					SourceID:    "src-1",
					PayloadHash: "hash1",
					Finding: types.Finding{
						Provider: "gcp",
					},
				},
			},
			runID:     "run-123",
			cancelCtx: true,
			wantErr:   true,
			wantFiles: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &CloudReporter{
				Store:      tt.store,
				SigningKey: key,
				PathPrefix: "test-prefix",
			}

			ctx := context.Background()
			if tt.cancelCtx {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}

			manifest, err := r.Deliver(ctx, tt.evidence, tt.runID)

			if (err != nil) != tt.wantErr {
				t.Errorf("Deliver() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if manifest == nil {
					t.Fatalf("Deliver() returned nil manifest")
				}

				if manifest.RunID != tt.runID {
					t.Errorf("Manifest RunID = %v, want %v", manifest.RunID, tt.runID)
				}

				// +1 if execution log is captured, but since logging is not globally setup, it should be just the evidence+prov + maybe log
				// We expect at least wantFiles
				if len(manifest.EvidenceFiles) < tt.wantFiles {
					t.Errorf("Manifest EvidenceFiles count = %v, want at least %v", len(manifest.EvidenceFiles), tt.wantFiles)
				}
			}
		})
	}
}

func TestCloudReporter_Deliver_ErrorPaths(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	// Create a mock store that fails on the second Put (provenance upload)

	t.Run("fails on second put (provenance)", func(t *testing.T) {
		r := &CloudReporter{
			Store:      &mockStoreWithCounter{errOnPut: 2}, // We'll implement this below
			SigningKey: key,
			PathPrefix: "test-prefix",
		}

		evidence := []types.Evidence{
			{EvidenceID: "E1", ControlID: "C1", SourceID: "S1", Finding: types.Finding{Provider: "p1"}},
		}
		_, err := r.Deliver(context.Background(), evidence, "run-1")
		if err == nil {
			t.Errorf("expected error when second put fails")
		}
	})
}

type mockStoreWithCounter struct {
	putCount int
	errOnPut int
}

func (m *mockStoreWithCounter) Put(ctx context.Context, key string, body io.Reader, contentType string) error {
	m.putCount++
	if m.putCount == m.errOnPut {
		return io.EOF
	}
	return nil
}

func TestCloudReporter_Deliver_ManifestPutFails(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	r := &CloudReporter{
		Store:      &mockStoreWithCounter{errOnPut: 3}, // fail on third put (manifest)
		SigningKey: key,
		PathPrefix: "test-prefix",
	}

	evidence := []types.Evidence{
		{EvidenceID: "E1", ControlID: "C1", SourceID: "S1", Finding: types.Finding{Provider: "p1"}},
	}
	_, err := r.Deliver(context.Background(), evidence, "run-1")
	if err == nil {
		t.Errorf("expected error when manifest put fails")
	}
}

func TestCloudReporter_Deliver_PutErrors(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	tests := []struct {
		name     string
		errOnPut int
	}{
		{"fails on second put (provenance)", 2},
		{"fails on third put (manifest)", 3},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &CloudReporter{
				Store:      &mockStoreWithCounter{errOnPut: tt.errOnPut},
				SigningKey: key,
				PathPrefix: "test-prefix",
			}

			evidence := []types.Evidence{
				{EvidenceID: "E1", ControlID: "C1", SourceID: "S1", Finding: types.Finding{Provider: "p1"}},
			}
			_, err := r.Deliver(context.Background(), evidence, "run-1")
			if err == nil {
				t.Errorf("expected error when put fails")
			}
		})
	}
}

type mockSigner struct {
	err error
}

func (m *mockSigner) Public() stdcrypto.PublicKey {
	return nil
}

func (m *mockSigner) Sign(rand io.Reader, digest []byte, opts stdcrypto.SignerOpts) ([]byte, error) {
	if m.err != nil {
		return nil, m.err
	}
	return []byte("mock-signature"), nil
}

func TestCloudReporter_Deliver_SigningErrors(t *testing.T) {
	tests := []struct {
		name    string
		signer  *mockSigner
		wantErr bool
	}{
		{"sign provenance fails", &mockSigner{err: io.EOF}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &CloudReporter{
				Store:      &mockStore{puts: make(map[string][]byte)},
				SigningKey: tt.signer,
				PathPrefix: "test-prefix",
			}

			evidence := []types.Evidence{
				{EvidenceID: "E1", ControlID: "C1", SourceID: "S1", Finding: types.Finding{Provider: "p1"}},
			}
			_, err := r.Deliver(context.Background(), evidence, "run-1")
			if (err != nil) != tt.wantErr {
				t.Errorf("Deliver() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// This is a test specific mock signer to bypass provenance sign error
// and fail on manifest signing. Actually wait, if we only return error on the second call.
type mockSignerManifestFail struct {
	callCount int
	err       error
}

func (m *mockSignerManifestFail) Public() stdcrypto.PublicKey {
	return nil
}

func (m *mockSignerManifestFail) Sign(rand io.Reader, digest []byte, opts stdcrypto.SignerOpts) ([]byte, error) {
	m.callCount++
	// Proveance signing is called for each evidence. If we have 1 evidence, it's called 1 time.
	// Manifest is called after all evidence. So 2nd call is Manifest.
	if m.callCount == 2 {
		return nil, m.err
	}
	return []byte("mock-signature"), nil
}

func TestCloudReporter_Deliver_ManifestSignFail(t *testing.T) {
	r := &CloudReporter{
		Store:      &mockStore{puts: make(map[string][]byte)},
		SigningKey: &mockSignerManifestFail{err: io.EOF},
		PathPrefix: "test-prefix",
	}

	evidence := []types.Evidence{
		{EvidenceID: "E1", ControlID: "C1", SourceID: "S1", Finding: types.Finding{Provider: "p1"}},
	}
	_, err := r.Deliver(context.Background(), evidence, "run-1")
	if err == nil {
		t.Errorf("expected error when manifest signing fails")
	}
}
