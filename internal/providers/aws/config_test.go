package aws

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/configservice"
)

func TestLoadAWSConfigExtractions_Invalid(t *testing.T) {
	_, err := LoadAWSConfigExtractions("nonexistent.json")
	if err == nil {
		t.Fatal("expected error loading nonexistent config")
	}
}

func TestLoadAWSConfigExtractions_Empty(t *testing.T) {
	tmpFile := t.TempDir() + "/empty.json"
	os.WriteFile(tmpFile, []byte(`{}`), 0644)
	_, err := LoadAWSConfigExtractions(tmpFile)
	if err == nil {
		t.Fatal("expected error loading empty config")
	}
}

func TestLoadAWSConfigExtractions_Valid(t *testing.T) {
	tmpFile := t.TempDir() + "/valid.json"
	os.WriteFile(tmpFile, []byte(`{"E-TEST-01":{"description":"test","provider":"aws_config","query":"SELECT *"}}`), 0644)
	configs, err := LoadAWSConfigExtractions(tmpFile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(configs) != 1 {
		t.Fatal("expected 1 config")
	}
}

func TestNewUnifiedAWSConfigProvider_NoRegion(t *testing.T) {
	os.Unsetenv("AWS_REGION")
	os.Unsetenv("AWS_DEFAULT_REGION")
	_, err := NewUnifiedAWSConfigProvider(context.Background())
	if err == nil {
		t.Fatal("expected error when no region is set")
	}
}

func TestNewUnifiedAWSConfigProvider_WithRegion(t *testing.T) {
	os.Setenv("AWS_REGION", "us-east-1")
	defer os.Unsetenv("AWS_REGION")
	p, err := NewUnifiedAWSConfigProvider(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p == nil {
		t.Fatal("expected provider to be created")
	}
	err = p.Close()
	if err != nil {
		t.Fatalf("unexpected error closing: %v", err)
	}
}

type mockAWSConfigClient struct {
	Outputs []*configservice.SelectResourceConfigOutput
	Err     error
	callNum int
}

func (m *mockAWSConfigClient) SelectResourceConfig(ctx context.Context, params *configservice.SelectResourceConfigInput, optFns ...func(*configservice.Options)) (*configservice.SelectResourceConfigOutput, error) {
	if m.Err != nil {
		return nil, m.Err
	}
	if m.callNum >= len(m.Outputs) {
		return &configservice.SelectResourceConfigOutput{}, nil
	}
	out := m.Outputs[m.callNum]
	m.callNum++
	return out, nil
}

func TestUnifiedAWSConfigProvider_Extract(t *testing.T) {
	tests := []struct {
		name          string
		mockOutputs   []*configservice.SelectResourceConfigOutput
		mockErr       error
		expectErrStr  string
		expectRawData string
	}{
		{
			name: "Success Single Page",
			mockOutputs: []*configservice.SelectResourceConfigOutput{
				{
					Results: []string{
						`{"resourceId":"123"}`,
						`{"resourceId":"456"}`,
					},
				},
			},
			expectRawData: `[{"resourceId":"123"},{"resourceId":"456"}]`,
		},
		{
			name: "Success Multiple Pages",
			mockOutputs: []*configservice.SelectResourceConfigOutput{
				{
					Results:   []string{`{"resourceId":"1"}`},
					NextToken: ptr("token1"),
				},
				{
					Results: []string{`{"resourceId":"2"}`},
				},
			},
			expectRawData: `[{"resourceId":"1"},{"resourceId":"2"}]`,
		},
		{
			name:         "Client Error",
			mockErr:      fmt.Errorf("aws api error"),
			expectErrStr: "aws api error",
		},
		{
			name: "Malformed JSON Ignored",
			mockOutputs: []*configservice.SelectResourceConfigOutput{
				{
					Results: []string{
						`{"valid":"json"}`,
						`invalid-json-garbage`,
					},
				},
			},
			expectRawData: `[{"valid":"json"}]`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mockClient := &mockAWSConfigClient{
				Outputs: tc.mockOutputs,
				Err:     tc.mockErr,
			}
			provider := &UnifiedAWSConfigProvider{
				client: mockClient,
				region: "us-east-1",
			}

			finding, err := provider.Extract(context.Background(), "E-TEST", AWSConfigExtraction{Query: "SELECT *"}, "test-run")
			if tc.expectErrStr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.expectErrStr) {
					t.Errorf("expected error containing %q, got %v", tc.expectErrStr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if string(finding.RawData) != tc.expectRawData {
				t.Errorf("expected %s, got %s", tc.expectRawData, string(finding.RawData))
			}
		})
	}
}

func ptr(s string) *string {
	return &s
}
