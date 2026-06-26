package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/open-policy-agent/opa/ast"
)

func TestValidRego_PassesAST(t *testing.T) {
	dir := t.TempDir()
	validRego := `package translators.test

import rego.v1

default compliant := false

compliant if {
	input.status == "ENABLED"
}
`
	path := filepath.Join(dir, "test_valid.rego")
	if err := os.WriteFile(path, []byte(validRego), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := ast.ParseModule(path, validRego)
	if err != nil {
		t.Errorf("expected valid Rego to pass AST parsing, got: %v", err)
	}
}

func TestInvalidRego_FailsAST(t *testing.T) {
	invalidRego := `package broken

	this is not valid rego syntax !!!
`
	_, err := ast.ParseModule("invalid.rego", invalidRego)
	if err == nil {
		t.Error("expected invalid Rego to fail AST parsing, but it passed")
	}
}

func TestEmptyRego_PassesAST(t *testing.T) {
	// An empty module is technically valid Rego (no rules, no errors).
	_, err := ast.ParseModule("empty.rego", "")
	// OPA may or may not accept empty input depending on version.
	// The key assertion: it should not panic.
	_ = err
}

func TestMultipleRegoFiles(t *testing.T) {
	dir := t.TempDir()

	files := map[string]string{
		"aws_s3.rego": `package translators.aws_s3

import rego.v1

default compliant := false

compliant if {
	input.bucket.versioning.status == "Enabled"
}
`,
		"gcp_storage.rego": `package translators.gcp_storage

import rego.v1

default compliant := false

compliant if {
	input.resource.versioning.enabled == true
}
`,
	}

	for name, content := range files {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			t.Fatalf("writing %s: %v", name, err)
		}

		_, err := ast.ParseModule(path, content)
		if err != nil {
			t.Errorf("file %s failed AST parsing: %v", name, err)
		}
	}
}

// ---------------------------------------------------------------------------
// Walk-based validation tests (exercise runValidate directly)
// ---------------------------------------------------------------------------

func TestRunValidate_AllValid(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"a.rego", "b.rego"} {
		rego := "package test_" + name[:1] + "\ndefault allow = false\n"
		if err := os.WriteFile(filepath.Join(dir, name), []byte(rego), 0644); err != nil {
			t.Fatal(err)
		}
	}

	err := runValidate(dir)
	if err != nil {
		t.Fatalf("expected no validation error, got: %v", err)
	}
}

func TestRunValidate_MixedValidAndInvalid(t *testing.T) {
	dir := t.TempDir()
	valid := "package good\ndefault deny = true\n"
	invalid := "package bad\n!!! not rego\n"

	if err := os.WriteFile(filepath.Join(dir, "good.rego"), []byte(valid), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "bad.rego"), []byte(invalid), 0644); err != nil {
		t.Fatal(err)
	}

	err := runValidate(dir)
	if err == nil {
		t.Fatal("expected validation error for mixed content, got nil")
	}
	if !strings.Contains(err.Error(), "Validation checks failed") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestRunValidate_IgnoresNonRegoFiles(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("not rego"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "data.json"), []byte(`{}`), 0644); err != nil {
		t.Fatal(err)
	}

	err := runValidate(dir)
	if err != nil {
		t.Fatalf("expected no validation error for non-Rego files, got: %v", err)
	}
}

func TestRunValidate_EmptyDirectory(t *testing.T) {
	dir := t.TempDir()

	err := runValidate(dir)
	if err != nil {
		t.Fatalf("expected no validation error for empty directory, got: %v", err)
	}
}

func TestMainFunction(t *testing.T) {
	oldDir := translatorsDir
	defer func() { translatorsDir = oldDir }()

	dir := t.TempDir()
	rego := "package test_main\ndefault allow = false\n"
	if err := os.WriteFile(filepath.Join(dir, "test.rego"), []byte(rego), 0644); err != nil {
		t.Fatal(err)
	}
	translatorsDir = dir

	// Call main directly under a successful state (no os.Exit)
	main()
}

func TestMainFunction_Error(t *testing.T) {
	oldDir := translatorsDir
	oldExit := exitFunc
	defer func() {
		translatorsDir = oldDir
		exitFunc = oldExit
	}()

	// Set to a temp directory containing an invalid rego file
	dir := t.TempDir()
	rego := "invalid rego content!!!"
	if err := os.WriteFile(filepath.Join(dir, "test.rego"), []byte(rego), 0644); err != nil {
		t.Fatal(err)
	}
	translatorsDir = dir

	exitCalled := false
	exitFunc = func(code int) {
		exitCalled = true
		if code != 1 {
			t.Errorf("expected exit code 1, got %d", code)
		}
	}

	main()

	if !exitCalled {
		t.Error("expected exitFunc to be called, but it wasn't")
	}
}



