package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"jula-governor/internal/aiutil"
)

func TestGetEnvStr(t *testing.T) {
	tests := []struct {
		name     string
		envKey   string
		envValue string
		want     string
	}{
		{
			name:     "existing environment variable",
			envKey:   "TEST_ENV_STR",
			envValue: "hello_world",
			want:     "hello_world",
		},
		{
			name:     "environment variable with quotes",
			envKey:   "TEST_ENV_STR_QUOTES",
			envValue: "\"quoted_value\"",
			want:     "quoted_value",
		},
		{
			name:     "non-existent environment variable",
			envKey:   "TEST_ENV_NON_EXISTENT",
			envValue: "", // Set env but empty
			want:     "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup environment variable
			if tt.name != "non-existent environment variable" {
				t.Setenv(tt.envKey, tt.envValue)
			} else {
				os.Unsetenv(tt.envKey) // Ensure it's unset
			}

			if got := aiutil.GetEnvStr(tt.envKey); got != tt.want {
				t.Errorf("GetEnvStr() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetEnvInt(t *testing.T) {
	tests := []struct {
		name       string
		envKey     string
		envValue   string
		defaultVal int
		want       int
	}{
		{
			name:       "valid integer",
			envKey:     "TEST_ENV_INT_VALID",
			envValue:   "42",
			defaultVal: 10,
			want:       42,
		},
		{
			name:       "valid integer with quotes",
			envKey:     "TEST_ENV_INT_VALID_QUOTES",
			envValue:   "\"42\"",
			defaultVal: 10,
			want:       42,
		},
		{
			name:       "invalid integer",
			envKey:     "TEST_ENV_INT_INVALID",
			envValue:   "not_an_int",
			defaultVal: 10,
			want:       10,
		},
		{
			name:       "non-existent integer",
			envKey:     "TEST_ENV_INT_NON_EXISTENT",
			envValue:   "",
			defaultVal: 99,
			want:       99,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.name != "non-existent integer" {
				t.Setenv(tt.envKey, tt.envValue)
			} else {
				os.Unsetenv(tt.envKey)
			}

			if got := aiutil.GetEnvInt(tt.envKey, tt.defaultVal); got != tt.want {
				t.Errorf("GetEnvInt() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSanitizeFilename(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "uppercase to lowercase",
			in:   "CONTROL_ID_123",
			want: "control_id_123",
		},
		{
			name: "hyphens to underscores",
			in:   "control-id-123",
			want: "control_id_123",
		},
		{
			name: "dots to underscores",
			in:   "control.id.123",
			want: "control_id_123",
		},
		{
			name: "mixed characters",
			in:   "ConTrOl-iD.123",
			want: "control_id_123",
		},
		{
			name: "already sanitized",
			in:   "control_id_123",
			want: "control_id_123",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := sanitizeFilename(tt.in); got != tt.want {
				t.Errorf("sanitizeFilename() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestExtractRegoBlock(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "fenced rego block",
			input: "Here is the output:\n```rego\npackage test\n\ndefault allow = false\n```\nDone.",
			want:  "package test\n\ndefault allow = false",
		},
		{
			name:  "fenced generic block",
			input: "```\npackage test\n```",
			want:  "package test",
		},
		{
			name:  "no fence at all",
			input: "package test\n\ndefault allow = true",
			want:  "package test\n\ndefault allow = true",
		},
		{
			name:  "empty input",
			input: "",
			want:  "",
		},
		{
			name:  "triple backtick wrapping only",
			input: "```rego\npackage raw\n```",
			want:  "package raw",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractRegoBlock(tt.input)
			if got != tt.want {
				t.Errorf("extractRegoBlock() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestLoadTranslators(t *testing.T) {
	t.Run("returns fallback when directory does not exist", func(t *testing.T) {
		oldDir := translatorsDir
		defer func() { translatorsDir = oldDir }()
		translatorsDir = "nonexistent_provider_xyz"

		result := loadTranslators("aws")
		if result != "No translators loaded." {
			t.Errorf("expected fallback string, got: %q", result)
		}
	})
}

func TestRunBuild_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		resp := map[string]interface{}{
			"choices": []map[string]interface{}{
				{
					"message": map[string]interface{}{
						"content": "```rego\npackage rules.ac_1\ndefault compliant := true\n```",
					},
				},
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	// Backup global vars
	oldWorkspace := workspaceFile
	oldReqFile := requirementsFile
	oldPrompt := promptFile
	oldTranslatorsDir := translatorsDir
	oldPoliciesDir := policiesDir
	defer func() {
		workspaceFile = oldWorkspace
		requirementsFile = oldReqFile
		promptFile = oldPrompt
		translatorsDir = oldTranslatorsDir
		policiesDir = oldPoliciesDir
		os.Unsetenv("JULA_PRIMARY_ENDPOINT")
		os.Unsetenv("JULA_PRIMARY_KEY")
		os.Unsetenv("JULA_PRIMARY_MODEL")
	}()

	tmpDir := t.TempDir()
	workspaceFile = filepath.Join(tmpDir, "workspace.yaml")
	requirementsFile = filepath.Join(tmpDir, "requirements.csv")
	promptFile = filepath.Join(tmpDir, "setup_04_generate_policy.md")
	translatorsDir = filepath.Join(tmpDir, "translators")
	policiesDir = filepath.Join(tmpDir, "policies")

	// Write temp files
	if err := os.WriteFile(workspaceFile, []byte("organization: Acme\nactive_providers:\n  gcp:\n    doc_root: gcp_docs"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(promptFile, []byte("Prompt definition: {{REQUIREMENT_DEFINITION}} -- {{AVAILABLE_TRANSLATOR_FIELDS}}"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(translatorsDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(translatorsDir, "gcp_storage.rego"), []byte("package translators.gcp_storage"), 0644); err != nil {
		t.Fatal(err)
	}

	csvData := "control_id,requirement_id,target_provider,parameter_field,operator,expected_value,status\nAC-1,REQ-01,gcp,storage.versioning,EQUALS,true,APPROVED\nAC-2,REQ-02,gcp,kms.rotation,EQUALS,90,PENDING\n"
	if err := os.WriteFile(requirementsFile, []byte(csvData), 0644); err != nil {
		t.Fatal(err)
	}

	t.Setenv("JULA_PRIMARY_ENDPOINT", server.URL)
	t.Setenv("JULA_PRIMARY_KEY", "dummy-key")
	t.Setenv("JULA_PRIMARY_MODEL", "dummy-model")

	err := runBuild()
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	// Verify policy output file exists
	outputFile := filepath.Join(policiesDir, "core_ac_1.rego")
	content, err := os.ReadFile(outputFile)
	if err != nil {
		t.Fatalf("expected policy output file, got read error: %v", err)
	}
	expectedCode := "package rules.ac_1\ndefault compliant := true"
	if string(content) != expectedCode {
		t.Errorf("expected generated Rego code: %q, got: %q", expectedCode, string(content))
	}

	// Verify pending control AC-2 has no output file
	pendingFile := filepath.Join(policiesDir, "core_ac_2.rego")
	if _, err := os.Stat(pendingFile); !os.IsNotExist(err) {
		t.Error("expected pending control AC-2 file to NOT exist")
	}
}

func TestRunBuild_Errors(t *testing.T) {
	oldWorkspace := workspaceFile
	oldReqFile := requirementsFile
	oldPrompt := promptFile
	defer func() {
		workspaceFile = oldWorkspace
		requirementsFile = oldReqFile
		promptFile = oldPrompt
		os.Unsetenv("JULA_PRIMARY_ENDPOINT")
		os.Unsetenv("JULA_FALLBACK_ENDPOINT")
	}()

	tmpDir := t.TempDir()
	workspaceFile = filepath.Join(tmpDir, "workspace.yaml")
	requirementsFile = filepath.Join(tmpDir, "requirements.csv")
	promptFile = filepath.Join(tmpDir, "setup_04_generate_policy.md")

	// 1. Missing AI config
	os.Unsetenv("JULA_PRIMARY_ENDPOINT")
	os.Unsetenv("JULA_FALLBACK_ENDPOINT")
	err := runBuild()
	if err == nil {
		t.Error("expected error for missing AI config, got nil")
	}

	t.Setenv("JULA_PRIMARY_ENDPOINT", "http://dummy")

	// 2. Missing workspace.yaml
	err = runBuild()
	if err == nil {
		t.Error("expected error for missing workspace.yaml, got nil")
	}

	if err := os.WriteFile(workspaceFile, []byte("organization: Acme"), 0644); err != nil {
		t.Fatal(err)
	}

	// 3. Missing prompt file
	err = runBuild()
	if err == nil {
		t.Error("expected error for missing prompt file, got nil")
	}

	if err := os.WriteFile(promptFile, []byte("prompt"), 0644); err != nil {
		t.Fatal(err)
	}

	// 4. Missing requirements.csv
	err = runBuild()
	if err == nil {
		t.Error("expected error for missing requirements.csv, got nil")
	}

	// Write bad requirements.csv header
	if err := os.WriteFile(requirementsFile, []byte("bad,header,columns\n"), 0644); err != nil {
		t.Fatal(err)
	}

	// 5. Malformed/missing columns requirements.csv
	err = runBuild()
	if err == nil {
		t.Error("expected error for bad CSV header, got nil")
	}
}

func TestMain_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		resp := map[string]interface{}{
			"choices": []map[string]interface{}{
				{
					"message": map[string]interface{}{
						"content": "package dummy",
					},
				},
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	oldWorkspace := workspaceFile
	oldReqFile := requirementsFile
	oldPrompt := promptFile
	oldTranslatorsDir := translatorsDir
	oldExit := exitFunc
	defer func() {
		workspaceFile = oldWorkspace
		requirementsFile = oldReqFile
		promptFile = oldPrompt
		translatorsDir = oldTranslatorsDir
		exitFunc = oldExit
		os.Unsetenv("JULA_PRIMARY_ENDPOINT")
		os.Unsetenv("JULA_PRIMARY_KEY")
		os.Unsetenv("JULA_PRIMARY_MODEL")
	}()

	tmpDir := t.TempDir()
	workspaceFile = filepath.Join(tmpDir, "workspace.yaml")
	requirementsFile = filepath.Join(tmpDir, "requirements.csv")
	promptFile = filepath.Join(tmpDir, "setup_04_generate_policy.md")
	translatorsDir = filepath.Join(tmpDir, "translators")

	if err := os.WriteFile(workspaceFile, []byte("organization: Acme"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(promptFile, []byte("prompt"), 0644); err != nil {
		t.Fatal(err)
	}
	csvData := "control_id,requirement_id,target_provider,parameter_field,operator,expected_value,status\n"
	if err := os.WriteFile(requirementsFile, []byte(csvData), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(translatorsDir, 0755); err != nil {
		t.Fatal(err)
	}

	t.Setenv("JULA_PRIMARY_ENDPOINT", server.URL)
	t.Setenv("JULA_PRIMARY_KEY", "dummy-key")
	t.Setenv("JULA_PRIMARY_MODEL", "dummy-model")

	exitCalled := false
	exitFunc = func(code int) {
		exitCalled = true
	}

	main()

	if exitCalled {
		t.Error("expected main() to succeed without calling exitFunc")
	}
}

func TestMain_Error(t *testing.T) {
	oldWorkspace := workspaceFile
	oldExit := exitFunc
	defer func() {
		workspaceFile = oldWorkspace
		exitFunc = oldExit
	}()

	workspaceFile = "nonexistent_workspace.yaml"

	exitCalled := false
	var exitCode int
	exitFunc = func(code int) {
		exitCalled = true
		exitCode = code
	}

	main()

	if !exitCalled {
		t.Error("expected exitFunc to be called on error")
	}
	if exitCode != 1 {
		t.Errorf("expected exit code 1, got %d", exitCode)
	}
}
