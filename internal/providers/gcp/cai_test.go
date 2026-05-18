package gcp

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"cloud.google.com/go/asset/apiv1/assetpb"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
	"strings"
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

type mockIamPolicyIterator struct {
	results []*assetpb.IamPolicySearchResult
	err     error
	index   int
}

func (m *mockIamPolicyIterator) Next() (*assetpb.IamPolicySearchResult, error) {
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
	iterator    *mockResourceIterator
	iamIterator *mockIamPolicyIterator
	closeErr    error
}

func (m *mockAssetClient) SearchAllResources(ctx context.Context, req *assetpb.SearchAllResourcesRequest, opts ...option.ClientOption) ResourceIterator {
	return m.iterator
}

func (m *mockAssetClient) SearchAllIamPolicies(ctx context.Context, req *assetpb.SearchAllIamPoliciesRequest, opts ...option.ClientOption) IamPolicyIterator {
	return m.iamIterator
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

func TestExtract_IamPolicySuccess(t *testing.T) {
	mockIamResults := []*assetpb.IamPolicySearchResult{
		{
			Resource:  "//cloudresourcemanager.googleapis.com/projects/my-project",
			AssetType: "cloudresourcemanager.googleapis.com/Project",
			Project:   "projects/my-project",
		},
	}

	mockClient := &mockAssetClient{
		iamIterator: &mockIamPolicyIterator{
			results: mockIamResults,
		},
	}

	provider := &UnifiedCAIProvider{
		client:       mockClient,
		defaultScope: "projects/my-project",
	}

	cfg := CAIExtractionConfig{
		Query:      "policy:roles/owner",
		SearchType: "iam",
	}

	finding, err := provider.Extract(context.Background(), "E-TEST-03", cfg, "run-456")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if finding.ErlID != "E-TEST-03" {
		t.Errorf("expected ErlID E-TEST-03, got %s", finding.ErlID)
	}
	if len(finding.RawData) == 0 {
		t.Error("expected RawData to be populated, got empty")
	}
}

func TestNewUnifiedCAIProvider(t *testing.T) {
	tmpDir := t.TempDir()

	// Generate a dummy RSA key dynamically to avoid hardcoding secrets
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate dummy RSA key: %v", err)
	}
	keyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("failed to marshal key: %v", err)
	}
	pemBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyBytes,
	}
	pemBytes := pem.EncodeToMemory(pemBlock)
	privateKeyStr := strings.ReplaceAll(string(pemBytes), "\n", "\\n")

	dummyCreds := fmt.Sprintf(`{
		"type": "service_account",
		"project_id": "test-project",
		"private_key_id": "test-key-id",
		"private_key": "%s",
		"client_email": "test@test-project.iam.gserviceaccount.com",
		"client_id": "12345",
		"auth_uri": "https://accounts.google.com/o/oauth2/auth",
		"token_uri": "https://oauth2.googleapis.com/token",
		"auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
		"client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/test%%40test-project.iam.gserviceaccount.com"
	}`, privateKeyStr)

	validCredPath := filepath.Join(tmpDir, "dummy_creds.json")
	if err := os.WriteFile(validCredPath, []byte(dummyCreds), 0644); err != nil {
		t.Fatalf("failed to write dummy creds: %v", err)
	}

	invalidCredPath := filepath.Join(tmpDir, "invalid_creds.json")
	if err := os.WriteFile(invalidCredPath, []byte("invalid json data"), 0644); err != nil {
		t.Fatalf("failed to write invalid creds: %v", err)
	}

	tests := []struct {
		name          string
		credPath      string
		scope         string
		expectedScope string
		wantErr       bool
	}{
		{
			name:          "happy path - valid credentials",
			credPath:      validCredPath,
			scope:         "projects/test-project",
			expectedScope: "projects/test-project",
			wantErr:       false,
		},
		{
			name:          "error path - invalid credentials",
			credPath:      invalidCredPath,
			scope:         "projects/test-project",
			expectedScope: "",
			wantErr:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", tt.credPath)
			t.Setenv("JULA_GCP_SCOPE", tt.scope)

			provider, err := NewUnifiedCAIProvider(context.Background())

			if (err != nil) != tt.wantErr {
				t.Errorf("NewUnifiedCAIProvider() error = %v, wantErr %v", err, tt.wantErr)
			}

			if err == nil {
				if provider == nil {
					t.Error("expected provider to be non-nil")
				} else if provider.defaultScope != tt.expectedScope {
					t.Errorf("expected scope %s, got %s", tt.expectedScope, provider.defaultScope)
				}
			}
		})
	}
}
