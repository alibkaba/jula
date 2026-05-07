package filedrop

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
	"testing"
)

// mockStorageReader is a test double for the StorageReader interface.
type mockStorageReader struct {
	files map[string][]byte
}

func (m *mockStorageReader) ListFiles(ctx context.Context, prefix string) ([]string, error) {
	var keys []string
	for k := range m.files {
		if strings.HasPrefix(k, prefix) {
			keys = append(keys, k)
		}
	}
	return keys, nil
}

func (m *mockStorageReader) GetFile(ctx context.Context, key string) (io.ReadCloser, map[string]string, error) {
	data, ok := m.files[key]
	if !ok {
		return nil, nil, fmt.Errorf("file not found: %s", key)
	}
	metadata := map[string]string{
		"content-type": "application/octet-stream",
	}
	return io.NopCloser(bytes.NewReader(data)), metadata, nil
}

func TestFileDropProvider_Name(t *testing.T) {
	p := &FileDropProvider{}
	if got := p.Name(); got != "filedrop" {
		t.Errorf("Name() = %q, want %q", got, "filedrop")
	}
}

func TestFileDropProvider_Validate(t *testing.T) {
	tests := []struct {
		name    string
		bucket  string
		client  StorageReader
		wantErr bool
	}{
		{
			name:    "valid configuration",
			bucket:  "my-bucket",
			client:  &mockStorageReader{},
			wantErr: false,
		},
		{
			name:    "missing bucket",
			bucket:  "",
			client:  &mockStorageReader{},
			wantErr: true,
		},
		{
			name:    "missing client",
			bucket:  "my-bucket",
			client:  nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &FileDropProvider{
				BucketName:    tt.bucket,
				StorageClient: tt.client,
			}
			err := p.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestFileDropProvider_Extract_JSONFile(t *testing.T) {
	jsonData := []byte(`{
		"scan_id": "scan-001",
		"timestamp": "2026-01-15T10:00:00Z",
		"scanner_name": "Nessus",
		"target": "192.168.1.0/24",
		"findings_summary": {
			"critical": 0,
			"high": 2,
			"medium": 5,
			"low": 10
		}
	}`)

	mock := &mockStorageReader{
		files: map[string][]byte{
			"evidence/vuln_scan_2026.json": jsonData,
		},
	}

	p := New("test-bucket", "evidence/", mock)
	findings, err := p.Extract(context.Background(), "run-test-001")

	if err != nil {
		t.Fatalf("Extract() unexpected error: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("Extract() returned %d findings, want 1", len(findings))
	}

	f := findings[0]
	if f.Provider != "filedrop" {
		t.Errorf("Finding.Provider = %q, want %q", f.Provider, "filedrop")
	}
	if f.Status != "PASS" {
		t.Errorf("Finding.Status = %q, want %q", f.Status, "PASS")
	}
	if f.Check != "byoe.vulnerability_scan" {
		t.Errorf("Finding.Check = %q, want %q", f.Check, "byoe.vulnerability_scan")
	}

	// Verify the hash is present in the raw payload.
	if _, ok := f.RawPayload["sha256_hash"]; !ok {
		t.Error("Finding.RawPayload missing sha256_hash")
	}
}

func TestFileDropProvider_Extract_PDFFile(t *testing.T) {
	pdfData := []byte("%PDF-1.4 fake policy document content for testing")

	mock := &mockStorageReader{
		files: map[string][]byte{
			"policies/hr_handbook.pdf": pdfData,
		},
	}

	p := New("test-bucket", "policies/", mock)
	findings, err := p.Extract(context.Background(), "run-test-002")

	if err != nil {
		t.Fatalf("Extract() unexpected error: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("Extract() returned %d findings, want 1", len(findings))
	}

	f := findings[0]
	if f.Check != "byoe.document_exists" {
		t.Errorf("Finding.Check = %q, want %q", f.Check, "byoe.document_exists")
	}
	if f.Status != "PASS" {
		t.Errorf("Finding.Status = %q, want %q", f.Status, "PASS")
	}

	// Verify the SHA-256 hash matches.
	expectedHash := sha256.Sum256(pdfData)
	expectedHex := hex.EncodeToString(expectedHash[:])
	if got, ok := f.RawPayload["sha256_hash"]; !ok || got != expectedHex {
		t.Errorf("Finding.RawPayload[sha256_hash] = %v, want %v", got, expectedHex)
	}
}

func TestFileDropProvider_Extract_TextFile(t *testing.T) {
	txtData := []byte("Information Security Policy v3.1 - Last reviewed 2026-04-01")

	mock := &mockStorageReader{
		files: map[string][]byte{
			"policies/infosec_policy.txt": txtData,
		},
	}

	p := New("test-bucket", "policies/", mock)
	findings, err := p.Extract(context.Background(), "run-test-003")

	if err != nil {
		t.Fatalf("Extract() unexpected error: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("Extract() returned %d findings, want 1", len(findings))
	}

	f := findings[0]
	if f.Check != "byoe.document_exists" {
		t.Errorf("Finding.Check = %q, want %q", f.Check, "byoe.document_exists")
	}
}

func TestFileDropProvider_Extract_InvalidJSON(t *testing.T) {
	badJSON := []byte(`{"broken": json,}`)

	mock := &mockStorageReader{
		files: map[string][]byte{
			"evidence/bad_data.json": badJSON,
		},
	}

	p := New("test-bucket", "evidence/", mock)
	findings, err := p.Extract(context.Background(), "run-test-004")

	if err != nil {
		t.Fatalf("Extract() unexpected error: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("Extract() returned %d findings, want 1", len(findings))
	}

	if findings[0].Status != "ERROR" {
		t.Errorf("Finding.Status = %q, want %q for invalid JSON", findings[0].Status, "ERROR")
	}
}

func TestFileDropProvider_Extract_EmptyBucket(t *testing.T) {
	mock := &mockStorageReader{
		files: map[string][]byte{},
	}

	p := New("test-bucket", "evidence/", mock)
	findings, err := p.Extract(context.Background(), "run-test-005")

	if err != nil {
		t.Fatalf("Extract() unexpected error: %v", err)
	}

	if findings != nil {
		t.Errorf("Extract() returned %d findings for empty bucket, want nil", len(findings))
	}
}

func TestFileDropProvider_Extract_UnsupportedExtension(t *testing.T) {
	mock := &mockStorageReader{
		files: map[string][]byte{
			"evidence/binary.exe": []byte("MZ binary data"),
		},
	}

	p := New("test-bucket", "evidence/", mock)
	findings, err := p.Extract(context.Background(), "run-test-006")

	if err != nil {
		t.Fatalf("Extract() unexpected error: %v", err)
	}

	if len(findings) != 0 {
		t.Errorf("Extract() returned %d findings for unsupported extension, want 0", len(findings))
	}
}

func TestFileDropProvider_Extract_MixedFiles(t *testing.T) {
	mock := &mockStorageReader{
		files: map[string][]byte{
			"drop/scan.json":    []byte(`{"scan_id":"s1","data":"ok"}`),
			"drop/policy.pdf":   []byte("%PDF-1.4 policy"),
			"drop/readme.md":    []byte("# Readme"),
			"drop/notes.txt":    []byte("Notes content"),
			"drop/report.csv":   []byte("col1,col2\nval1,val2"),
			"drop/ignored.xlsx": []byte("binary excel"),
		},
	}

	p := New("test-bucket", "drop/", mock)
	findings, err := p.Extract(context.Background(), "run-test-007")

	if err != nil {
		t.Fatalf("Extract() unexpected error: %v", err)
	}

	// Expected: 1 JSON + 4 hashable (pdf, md, txt, csv) = 5. xlsx is skipped.
	if len(findings) != 5 {
		t.Errorf("Extract() returned %d findings, want 5", len(findings))
	}
}

func TestNew(t *testing.T) {
	mock := &mockStorageReader{}
	p := New("bucket", "prefix/", mock)

	if p.BucketName != "bucket" {
		t.Errorf("BucketName = %q, want %q", p.BucketName, "bucket")
	}
	if p.Prefix != "prefix/" {
		t.Errorf("Prefix = %q, want %q", p.Prefix, "prefix/")
	}
	if p.StorageClient == nil {
		t.Error("StorageClient is nil")
	}
}
