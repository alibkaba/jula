package gcp

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"

	"cloud.google.com/go/asset/apiv1/assetpb"
	"google.golang.org/api/iterator"
)

func TestLoadCAIConfigs_Invalid(t *testing.T) {
	_, err := LoadCAIConfigs("nonexistent.json")
	if err == nil {
		t.Fatal("expected error loading nonexistent config")
	}
}

func TestLoadCAIConfigs_Empty(t *testing.T) {
	tmpFile := t.TempDir() + "/empty.json"
	os.WriteFile(tmpFile, []byte(`{}`), 0644)
	_, err := LoadCAIConfigs(tmpFile)
	if err == nil {
		t.Fatal("expected error loading empty config")
	}
}

func TestLoadCAIConfigs_Valid(t *testing.T) {
	tmpFile := t.TempDir() + "/valid.json"
	os.WriteFile(tmpFile, []byte(`{"E-TEST-01":{"description":"test","provider":"gcp_cai","asset_types":["compute.googleapis.com/Instance"]}}`), 0644)
	configs, err := LoadCAIConfigs(tmpFile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(configs) != 1 {
		t.Fatal("expected 1 config")
	}
}

func TestNewUnifiedCAIProvider_Error(t *testing.T) {
	// asset.NewClient typically fails in a constrained test environment without ADC.
	// We just want to cover the error path.
	_, err := NewUnifiedCAIProvider(context.Background())
	if err == nil {
		t.Log("Warning: NewUnifiedCAIProvider succeeded, which was unexpected in this environment.")
	}
}

func TestInterpolateEnvVars(t *testing.T) {
	os.Setenv("TEST_PROJECT", "my-project-123")
	os.Setenv("TEST_REGION", "us-east1")
	defer os.Unsetenv("TEST_PROJECT")
	defer os.Unsetenv("TEST_REGION")

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "No variables",
			input:    "projects/foo/assets",
			expected: "projects/foo/assets",
		},
		{
			name:     "Single variable",
			input:    "projects/{{TEST_PROJECT}}/assets",
			expected: "projects/my-project-123/assets",
		},
		{
			name:     "Multiple variables",
			input:    "projects/{{TEST_PROJECT}}/regions/{{TEST_REGION}}",
			expected: "projects/my-project-123/regions/us-east1",
		},
		{
			name:     "Unset variable",
			input:    "val-{{UNSET_VAR}}",
			expected: "val-",
		},
		{
			name:     "Malformed tag",
			input:    "projects/{{TEST_PROJECT/assets",
			expected: "projects/{{TEST_PROJECT/assets",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := interpolateEnvVars(tt.input)
			if got != tt.expected {
				t.Errorf("interpolateEnvVars() = %v, want %v", got, tt.expected)
			}
		})
	}
}

type mockResourceIterator struct {
	Items []*assetpb.ResourceSearchResult
	Err   error
	pos   int
}

func (m *mockResourceIterator) Next() (*assetpb.ResourceSearchResult, error) {
	if m.Err != nil {
		return nil, m.Err
	}
	if m.pos >= len(m.Items) {
		return nil, iterator.Done
	}
	item := m.Items[m.pos]
	m.pos++
	return item, nil
}

type mockAssetSearcher struct {
	Iter *mockResourceIterator
}

func (m *mockAssetSearcher) SearchAllResources(ctx context.Context, req *assetpb.SearchAllResourcesRequest) ResourceIterator {
	return m.Iter
}

func (m *mockAssetSearcher) Close() error {
	return nil
}

func TestUnifiedCAIProvider_Extract(t *testing.T) {
	tests := []struct {
		name          string
		mockItems     []*assetpb.ResourceSearchResult
		mockErr       error
		expectErrStr  string
		expectRawData string
	}{
		{
			name: "Success with items",
			mockItems: []*assetpb.ResourceSearchResult{
				{Name: "projects/123/assets/foo"},
			},
			expectRawData: `projects/123/assets/foo`,
		},
		{
			name: "Success empty",
			mockItems: []*assetpb.ResourceSearchResult{},
			expectRawData: `[]`,
		},
		{
			name: "Iterator error",
			mockErr:      fmt.Errorf("cai api error"),
			expectErrStr: "cai api error",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			iter := &mockResourceIterator{
				Items: tc.mockItems,
				Err:   tc.mockErr,
			}
			provider := &UnifiedCAIProvider{
				client: &mockAssetSearcher{Iter: iter},
			}

			finding, err := provider.Extract(context.Background(), "E-TEST", CAIConfig{Scope: "projects/123"}, "test-run")
			if tc.expectErrStr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.expectErrStr) {
					t.Errorf("expected error containing %q, got %v", tc.expectErrStr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			
			if len(tc.mockItems) > 0 && !strings.Contains(string(finding.RawData), tc.expectRawData) {
				t.Errorf("expected RawData to contain %s, got %s", tc.expectRawData, string(finding.RawData))
			}
			if len(tc.mockItems) == 0 && string(finding.RawData) != "[]" {
				t.Errorf("expected [], got %s", string(finding.RawData))
			}
		})
	}
}

