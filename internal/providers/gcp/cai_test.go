package gcp

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"cloud.google.com/go/asset/apiv1/assetpb"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// --- Mocks ---

type mockResourceIterator struct {
	results []*assetpb.ResourceSearchResult
	err     error
	index   int
}

func (m *mockResourceIterator) Next() (*assetpb.ResourceSearchResult, error) {
	if m.err != nil {
		return nil, m.err
	}
	if m.index >= len(m.results) {
		return nil, iterator.Done
	}
	res := m.results[m.index]
	m.index++
	return res, nil
}

type mockAssetClient struct {
	iterator *mockResourceIterator
	closeErr error
}

func (m *mockAssetClient) SearchAllResources(ctx context.Context, req *assetpb.SearchAllResourcesRequest, opts ...option.ClientOption) ResourceIterator {
	return m.iterator
}

func (m *mockAssetClient) Close() error {
	return m.closeErr
}

// --- Tests ---

func TestLoadCAIConfigs_Success(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "cai.json")
	configContent := []byte(`{
		"E-TEST-01": {
			"description": "Test extraction",
			"scope": "projects/my-test-project",
			"query": "state:ACTIVE",
			"asset_types": ["compute.googleapis.com/Instance"]
		}
	}`)

	if err := os.WriteFile(configPath, configContent, 0644); err != nil {
		t.Fatalf("failed to write test config: %v", err)
	}

	configs, err := LoadCAIConfigs(configPath)
	if err != nil {
		t.Fatalf("LoadCAIConfigs failed: %v", err)
	}

	if len(configs) != 1 {
		t.Errorf("expected 1 config, got %d", len(configs))
	}

	cfg, ok := configs["E-TEST-01"]
	if !ok {
		t.Fatal("expected E-TEST-01 config")
	}
	if cfg.Query != "state:ACTIVE" {
		t.Errorf("expected query state:ACTIVE, got %s", cfg.Query)
	}
}

func TestLoadCAIConfigs_FileNotFound(t *testing.T) {
	_, err := LoadCAIConfigs("nonexistent.json")
	if err == nil {
		t.Fatal("expected error loading nonexistent config")
	}
}

func TestLoadCAIConfigs_InvalidJSON(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "invalid.json")
	if err := os.WriteFile(configPath, []byte(`{invalid-json`), 0644); err != nil {
		t.Fatalf("failed to write test config: %v", err)
	}

	_, err := LoadCAIConfigs(configPath)
	if err == nil {
		t.Fatal("expected error loading invalid JSON")
	}
}

func TestExtract_NoScope(t *testing.T) {
	t.Setenv("JULA_GCP_SCOPE", "")

	provider := &UnifiedCAIProvider{
		client:       &mockAssetClient{},
		defaultScope: "",
	}

	cfg := CAIExtractionConfig{
		Query: "state:ACTIVE",
	}

	_, err := provider.Extract(context.Background(), "E-TEST-01", cfg, "test-run")
	if err == nil {
		t.Fatal("expected error when no scope is provided")
	}
}

func TestExtract_Success(t *testing.T) {
	// Prepare mock data
	createTime := timestamppb.New(time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC))

	attrStruct, _ := structpb.NewStruct(map[string]interface{}{
		"key1": "value1",
	})

	mockResults := []*assetpb.ResourceSearchResult{
		{
			Name:                 "//compute.googleapis.com/projects/my-project/zones/us-central1-a/instances/instance-1",
			AssetType:            "compute.googleapis.com/Instance",
			Project:              "projects/my-project",
			State:                "RUNNING",
			CreateTime:           createTime,
			Labels:               map[string]string{"env": "prod"},
			AdditionalAttributes: attrStruct,
		},
	}

	mockClient := &mockAssetClient{
		iterator: &mockResourceIterator{
			results: mockResults,
		},
	}

	provider := &UnifiedCAIProvider{
		client:       mockClient,
		defaultScope: "projects/my-project",
	}

	cfg := CAIExtractionConfig{
		Query: "state:RUNNING",
	}

	finding, err := provider.Extract(context.Background(), "E-TEST-01", cfg, "run-123")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if finding.ErlID != "E-TEST-01" {
		t.Errorf("expected ErlID E-TEST-01, got %s", finding.ErlID)
	}
	if finding.Provider != "gcp_cai" {
		t.Errorf("expected Provider gcp_cai, got %s", finding.Provider)
	}
	if len(finding.RawData) == 0 {
		t.Error("expected RawData to be populated, got empty")
	}
}

func TestExtract_IteratorError(t *testing.T) {
	expectedErr := errors.New("simulated network error")
	mockClient := &mockAssetClient{
		iterator: &mockResourceIterator{
			err: expectedErr,
		},
	}

	provider := &UnifiedCAIProvider{
		client:       mockClient,
		defaultScope: "projects/my-project",
	}

	cfg := CAIExtractionConfig{
		Query: "state:RUNNING",
	}

	_, err := provider.Extract(context.Background(), "E-TEST-02", cfg, "run-123")
	if err == nil {
		t.Fatal("expected error from iterator, got nil")
	}
}

func TestUnifiedCAIProvider_Close(t *testing.T) {
	expectedErr := errors.New("close error")
	mockClient := &mockAssetClient{
		closeErr: expectedErr,
	}

	provider := &UnifiedCAIProvider{
		client: mockClient,
	}

	err := provider.Close()
	if err != expectedErr {
		t.Errorf("expected %v, got %v", expectedErr, err)
	}

	// Test nil client
	providerNil := &UnifiedCAIProvider{client: nil}
	if err := providerNil.Close(); err != nil {
		t.Errorf("expected nil error on nil client close, got %v", err)
	}
}
