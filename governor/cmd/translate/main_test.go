package main

import (
	"encoding/json"
	"flag"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

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
			name:  "triple backtick wrapping only",
			input: "```rego\npackage raw\n```",
			want:  "package raw",
		},
		{
			name:  "empty input",
			input: "",
			want:  "",
		},
		{
			name:  "multiple blocks returns first",
			input: "```rego\npackage first\n```\n\n```rego\npackage second\n```",
			want:  "package first",
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

func TestRunTranslate_Success(t *testing.T) {
	// Start mock HTTP server representing the AI endpoint
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		content := "```rego\npackage translators.gcp_storage\ndefault compliant := false\n```"
		resp := map[string]interface{}{
			"choices": []map[string]interface{}{
				{
					"message": map[string]interface{}{
						"content": content,
					},
				},
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	// Backup global vars and env
	oldBuildPrompt := buildPromptFile
	oldHealPrompt := healPromptFile
	oldTranslatorsDir := translatorsDir
	defer func() {
		buildPromptFile = oldBuildPrompt
		healPromptFile = oldHealPrompt
		translatorsDir = oldTranslatorsDir
		os.Unsetenv("JULA_PRIMARY_ENDPOINT")
		os.Unsetenv("JULA_PRIMARY_KEY")
		os.Unsetenv("JULA_PRIMARY_MODEL")
	}()

	// Set up workspace directories/files in temp dir
	tmpDir := t.TempDir()
	buildPromptFile = filepath.Join(tmpDir, "setup_02_build_translator.md")
	healPromptFile = filepath.Join(tmpDir, "remediate_01_heal_translator.md")
	translatorsDir = filepath.Join(tmpDir, "translators")

	if err := os.WriteFile(buildPromptFile, []byte("provider: {{TARGET_PROVIDER}}, service: {{TARGET_SERVICE}}, response: {{RAW_API_RESPONSE}}"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(healPromptFile, []byte("heal provider: {{TARGET_PROVIDER}}"), 0644); err != nil {
		t.Fatal(err)
	}

	samplePath := filepath.Join(tmpDir, "sample.json")
	if err := os.WriteFile(samplePath, []byte(`{"id": "bucket"}`), 0644); err != nil {
		t.Fatal(err)
	}

	// Configure environment to point to mock server
	t.Setenv("JULA_PRIMARY_ENDPOINT", server.URL)
	t.Setenv("JULA_PRIMARY_KEY", "dummy-key")
	t.Setenv("JULA_PRIMARY_MODEL", "dummy-model")

	// Call runTranslate (build path)
	err := runTranslate("gcp", "storage", samplePath, false)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	// Verify output file exists and has correct contents
	outputFile := filepath.Join(translatorsDir, "gcp_storage.rego")
	content, err := os.ReadFile(outputFile)
	if err != nil {
		t.Fatalf("expected rego output file, got read error: %v", err)
	}

	expectedCode := "package translators.gcp_storage\ndefault compliant := false"
	if string(content) != expectedCode {
		t.Errorf("expected generated Rego code: %q, got: %q", expectedCode, string(content))
	}

	// Call runTranslate (heal path)
	err = runTranslate("gcp", "storage", samplePath, true)
	if err != nil {
		t.Fatalf("expected no error for heal path, got: %v", err)
	}
}

func TestRunTranslate_Errors(t *testing.T) {
	// Backup
	oldBuildPrompt := buildPromptFile
	oldTranslatorsDir := translatorsDir
	defer func() {
		buildPromptFile = oldBuildPrompt
		translatorsDir = oldTranslatorsDir
		os.Unsetenv("JULA_PRIMARY_ENDPOINT")
		os.Unsetenv("JULA_PRIMARY_KEY")
		os.Unsetenv("JULA_PRIMARY_MODEL")
	}()

	tmpDir := t.TempDir()
	buildPromptFile = filepath.Join(tmpDir, "setup_02_build_translator.md")
	translatorsDir = filepath.Join(tmpDir, "translators")

	samplePath := filepath.Join(tmpDir, "sample.json")

	// Test 1: Missing sample file
	err := runTranslate("gcp", "storage", samplePath, false)
	if err == nil {
		t.Error("expected error for missing sample file, got nil")
	}

	// Write sample file
	if err := os.WriteFile(samplePath, []byte(`{"id": "bucket"}`), 0644); err != nil {
		t.Fatal(err)
	}

	// Test 2: Missing prompt file
	err = runTranslate("gcp", "storage", samplePath, false)
	if err == nil {
		t.Error("expected error for missing prompt template, got nil")
	}

	// Write prompt file
	if err := os.WriteFile(buildPromptFile, []byte("prompt"), 0644); err != nil {
		t.Fatal(err)
	}

	// Test 3: Missing AI config
	os.Unsetenv("JULA_PRIMARY_ENDPOINT")
	os.Unsetenv("JULA_FALLBACK_ENDPOINT")
	err = runTranslate("gcp", "storage", samplePath, false)
	if err == nil {
		t.Error("expected error for missing AI config, got nil")
	}
}

func TestMain_FlagErrors(t *testing.T) {
	oldExit := exitFunc
	defer func() { exitFunc = oldExit }()

	exitCalled := false
	var exitCode int
	exitFunc = func(code int) {
		exitCalled = true
		exitCode = code
	}

	// Reset flags and parse invalid args
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	os.Args = []string{"translate", "--provider", "", "--service", "", "--sample-path", ""}

	main()

	if !exitCalled {
		t.Error("expected exitFunc to be called for empty flags, but it wasn't")
	}
	if exitCode != 2 {
		t.Errorf("expected exit code 2, got %d", exitCode)
	}
}

func TestMain_RunSuccess(t *testing.T) {
	// Start mock server
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

	// Backup
	oldBuildPrompt := buildPromptFile
	oldTranslatorsDir := translatorsDir
	oldExit := exitFunc
	defer func() {
		buildPromptFile = oldBuildPrompt
		translatorsDir = oldTranslatorsDir
		exitFunc = oldExit
		os.Unsetenv("JULA_PRIMARY_ENDPOINT")
		os.Unsetenv("JULA_PRIMARY_KEY")
		os.Unsetenv("JULA_PRIMARY_MODEL")
	}()

	tmpDir := t.TempDir()
	buildPromptFile = filepath.Join(tmpDir, "setup_02_build_translator.md")
	translatorsDir = filepath.Join(tmpDir, "translators")

	if err := os.WriteFile(buildPromptFile, []byte("prompt"), 0644); err != nil {
		t.Fatal(err)
	}

	samplePath := filepath.Join(tmpDir, "sample.json")
	if err := os.WriteFile(samplePath, []byte(`{}`), 0644); err != nil {
		t.Fatal(err)
	}

	t.Setenv("JULA_PRIMARY_ENDPOINT", server.URL)
	t.Setenv("JULA_PRIMARY_KEY", "dummy-key")
	t.Setenv("JULA_PRIMARY_MODEL", "dummy-model")

	exitCalled := false
	exitFunc = func(code int) {
		exitCalled = true
	}

	// Reset flags and set correct args
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	os.Args = []string{"translate", "--provider", "aws", "--service", "s3", "--sample-path", samplePath}

	main()

	if exitCalled {
		t.Error("expected main() to run successfully without calling exitFunc, but it was called")
	}

	// Verify generated file exists
	outputFile := filepath.Join(translatorsDir, "aws_s3.rego")
	if _, err := os.Stat(outputFile); os.IsNotExist(err) {
		t.Error("expected aws_s3.rego to be created, but it was not")
	}
}

func TestMain_RunFailure(t *testing.T) {
	// Backup
	oldBuildPrompt := buildPromptFile
	oldExit := exitFunc
	defer func() {
		buildPromptFile = oldBuildPrompt
		exitFunc = oldExit
		os.Unsetenv("JULA_PRIMARY_ENDPOINT")
		os.Unsetenv("JULA_PRIMARY_KEY")
		os.Unsetenv("JULA_PRIMARY_MODEL")
	}()

	tmpDir := t.TempDir()
	buildPromptFile = filepath.Join(tmpDir, "setup_02_build_translator.md")

	if err := os.WriteFile(buildPromptFile, []byte("prompt"), 0644); err != nil {
		t.Fatal(err)
	}

	samplePath := filepath.Join(tmpDir, "sample.json")
	if err := os.WriteFile(samplePath, []byte(`{}`), 0644); err != nil {
		t.Fatal(err)
	}

	// Point to bad endpoint
	t.Setenv("JULA_PRIMARY_ENDPOINT", "http://127.0.0.1:9999/bad")
	t.Setenv("JULA_PRIMARY_KEY", "dummy-key")
	t.Setenv("JULA_PRIMARY_MODEL", "dummy-model")

	exitCalled := false
	var exitCode int
	exitFunc = func(code int) {
		exitCalled = true
		exitCode = code
	}

	// Reset flags and set correct args
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	os.Args = []string{"translate", "--provider", "aws", "--service", "s3", "--sample-path", samplePath}

	main()

	if !exitCalled {
		t.Error("expected exitFunc to be called due to translation failure, but it was not")
	}
	if exitCode != 1 {
		t.Errorf("expected exit code 1, got %d", exitCode)
	}
}
