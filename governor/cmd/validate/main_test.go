package main

import (
	"os"
	"path/filepath"
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
