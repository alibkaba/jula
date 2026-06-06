package evaluation

import (
	"os"
	"path/filepath"
	"testing"
)

func TestOPAEvaluator_LoadPoliciesErrors(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(t *testing.T) string
		wantErr bool
	}{
		{
			name: "Non-existent directory",
			setup: func(t *testing.T) string {
				return "/does/not/exist/surely"
			},
			wantErr: true,
		},
		{
			name: "Unreadable directory",
			setup: func(t *testing.T) string {
				tmpDir, err := os.MkdirTemp("", "unreadable-*")
				if err != nil {
					t.Fatalf("Failed to create temp dir: %v", err)
				}

				// Create a file and make it totally unreadable
				badFile := filepath.Join(tmpDir, "bad.rego")
				if err := os.WriteFile(badFile, []byte("package bad"), 0000); err != nil {
					t.Fatalf("Failed to create bad file: %v", err)
				}

				t.Cleanup(func() {
					os.Chmod(badFile, 0644)
					os.RemoveAll(tmpDir)
				})

				return tmpDir
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			evaluator := NewOPAEvaluator()
			dirPath := tt.setup(t)

			err := evaluator.LoadPolicies(dirPath)
			if (err != nil) != tt.wantErr {
				t.Errorf("LoadPolicies() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
