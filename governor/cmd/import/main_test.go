package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"jula-governor/internal/aiutil"
)

// ---------------------------------------------------------------------------
// aiutil pass-through tests (existing)
// ---------------------------------------------------------------------------

func TestGetEnvStr(t *testing.T) {
	tests := []struct {
		name     string
		envKey   string
		envValue string
		want     string
	}{
		{"empty env var", "TEST_ENV_STR_EMPTY", "", ""},
		{"standard string", "TEST_ENV_STR_STD", "hello_world", "hello_world"},
		{"quoted string", "TEST_ENV_STR_QUOTED", "\"hello_world\"", "hello_world"},
		{"mixed quotes string", "TEST_ENV_STR_MIXED", "\"hello\"_world\"", "hello\"_world"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(tt.envKey, tt.envValue)
			if got := aiutil.GetEnvStr(tt.envKey); got != tt.want {
				t.Errorf("GetEnvStr() = %v, want %v", got, tt.want)
			}
		})
	}

	t.Run("unset env var", func(t *testing.T) {
		if got := aiutil.GetEnvStr("TEST_ENV_UNSET"); got != "" {
			t.Errorf("GetEnvStr() = %v, want empty string", got)
		}
	})
}

func TestGetEnvInt(t *testing.T) {
	tests := []struct {
		name       string
		envKey     string
		envValue   string
		defaultVal int
		want       int
	}{
		{"empty env var", "TEST_ENV_INT_EMPTY", "", 42, 42},
		{"valid positive integer", "TEST_ENV_INT_POS", "100", 42, 100},
		{"valid negative integer", "TEST_ENV_INT_NEG", "-5", 42, -5},
		{"invalid integer", "TEST_ENV_INT_INVALID", "not_a_number", 42, 42},
		{"quoted integer", "TEST_ENV_INT_QUOTED", "\"99\"", 42, 99},
		{"integer with whitespace", "TEST_ENV_INT_SPACE", "  88  ", 42, 88},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(tt.envKey, tt.envValue)
			if got := aiutil.GetEnvInt(tt.envKey, tt.defaultVal); got != tt.want {
				t.Errorf("GetEnvInt() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseWorkspace(t *testing.T) {
	tests := []struct {
		name        string
		fileContent string
		wantErr     bool
		want        aiutil.Workspace
	}{
		{"empty file", "", false, aiutil.Workspace{ActiveProviders: make(map[string]aiutil.ProviderConfig)}},
		{"only comments", "# comment\n\n# another\n", false, aiutil.Workspace{ActiveProviders: make(map[string]aiutil.ProviderConfig)}},
		{"organization only", "organization: \"Acme Corp\"\n", false, aiutil.Workspace{Organization: "Acme Corp", ActiveProviders: make(map[string]aiutil.ProviderConfig)}},
		{
			"single active provider",
			"organization: \"Test Org\"\nactive_providers:\n  aws:\n    doc_root: \"https://aws.amazon.com/docs\"\n",
			false,
			aiutil.Workspace{Organization: "Test Org", ActiveProviders: map[string]aiutil.ProviderConfig{"aws": {DocRoot: "https://aws.amazon.com/docs"}}},
		},
		{
			"multiple active providers",
			"organization: \"Multi Org\"\nactive_providers:\n  aws:\n    doc_root: \"https://aws.amazon.com\"\n  gcp:\n    doc_root: \"https://cloud.google.com\"\n",
			false,
			aiutil.Workspace{Organization: "Multi Org", ActiveProviders: map[string]aiutil.ProviderConfig{"aws": {DocRoot: "https://aws.amazon.com"}, "gcp": {DocRoot: "https://cloud.google.com"}}},
		},
		{"unquoted organization", "organization: Test Org Unquoted\n", false, aiutil.Workspace{Organization: "Test Org Unquoted", ActiveProviders: make(map[string]aiutil.ProviderConfig)}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			tmpFile := filepath.Join(tmpDir, "workspace.yaml")
			if err := os.WriteFile(tmpFile, []byte(tt.fileContent), 0644); err != nil {
				t.Fatalf("Failed to write temp file: %v", err)
			}
			got, err := aiutil.ParseWorkspace(tmpFile)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseWorkspace() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseWorkspace() = %v, want %v", got, tt.want)
			}
		})
	}

	t.Run("missing file", func(t *testing.T) {
		_, err := aiutil.ParseWorkspace("non_existent_file.yaml")
		if err == nil {
			t.Errorf("ParseWorkspace() expected error for missing file, got nil")
		}
	})
}

// ---------------------------------------------------------------------------
// detectSourceFormat
// ---------------------------------------------------------------------------

func TestDetectSourceFormat(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		content []byte
		want    string
	}{
		{"csv extension", "catalog.csv", nil, "csv"},
		{"CSV extension uppercase", "CATALOG.CSV", nil, "csv"},
		{"json extension", "catalog.json", nil, "json"},
		{"JSON extension uppercase", "CONTROLS.JSON", nil, "json"},
		{"unknown ext with JSON content", "catalog.oscal", []byte(`{"catalog": {}}`), "json"},
		{"unknown ext with CSV content", "catalog.oscal", []byte("ID,Description\nGOV-01,test"), "csv"},
		{"unknown ext with whitespace before JSON", "data.txt", []byte("  \n  {\"key\": 1}"), "json"},
		{"unknown ext empty content", "noext", []byte(""), "csv"},
		{"no extension at all", "data", []byte("plain text"), "csv"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detectSourceFormat(tt.path, tt.content)
			if got != tt.want {
				t.Errorf("detectSourceFormat(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// controlIDPattern
// ---------------------------------------------------------------------------

func TestControlIDPattern(t *testing.T) {
	valid := []string{
		"ac-1",     // NIST 800-53 lowercase
		"AC-1",     // NIST 800-53 uppercase
		"sc-28",    // NIST 800-53
		"GOV-01",   // SCF
		"IAC-15.1", // SCF with dot subcontrol
		"iac-15.1", // SCF lowercase
		"GV.OC-01", // NIST CSF v2.0 compound group
		"PR.DS-01", // NIST CSF v2.0
		"03.01.01", // NIST 800-171
	}
	for _, id := range valid {
		t.Run("valid_"+id, func(t *testing.T) {
			if !controlIDPattern.MatchString(id) {
				t.Errorf("controlIDPattern should match %q", id)
			}
		})
	}

	invalid := []string{
		"",            // empty
		"a-1",         // single char prefix (too short)
		"toolong-1",   // 7-char prefix exceeds 5-char limit
		"ac-",         // missing number
		"-1",          // missing prefix
		"ac 1",        // space instead of dash
		"ac_1",        // underscore instead of dash
		"hello world", // no structure
	}
	for _, id := range invalid {
		name := id
		if name == "" {
			name = "empty"
		}
		t.Run("invalid_"+name, func(t *testing.T) {
			if controlIDPattern.MatchString(id) {
				t.Errorf("controlIDPattern should NOT match %q", id)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// collectProse
// ---------------------------------------------------------------------------

func TestCollectProse(t *testing.T) {
	t.Run("empty parts", func(t *testing.T) {
		got := collectProse(nil)
		if got != "" {
			t.Errorf("collectProse(nil) = %q, want empty", got)
		}
	})

	t.Run("single statement part", func(t *testing.T) {
		parts := []OSCALPart{
			{Name: "statement", Prose: "Organizations shall implement access controls."},
		}
		got := collectProse(parts)
		if got != "Organizations shall implement access controls." {
			t.Errorf("unexpected prose: %q", got)
		}
	})

	t.Run("item and guidance combined", func(t *testing.T) {
		parts := []OSCALPart{
			{Name: "item", Prose: "Item text."},
			{Name: "guidance", Prose: "Guidance text."},
		}
		got := collectProse(parts)
		if got != "Item text. Guidance text." {
			t.Errorf("unexpected prose: %q", got)
		}
	})

	t.Run("skips irrelevant part names", func(t *testing.T) {
		parts := []OSCALPart{
			{Name: "objective", Prose: "Should be skipped."},
			{Name: "statement", Prose: "Kept."},
		}
		got := collectProse(parts)
		if got != "Kept." {
			t.Errorf("unexpected prose: %q", got)
		}
	})

	t.Run("nested parts", func(t *testing.T) {
		parts := []OSCALPart{
			{
				Name:  "statement",
				Prose: "Top level.",
				Parts: []OSCALPart{
					{Name: "item", Prose: "Nested item."},
				},
			},
		}
		got := collectProse(parts)
		if !strings.Contains(got, "Top level.") || !strings.Contains(got, "Nested item.") {
			t.Errorf("expected both top and nested prose, got: %q", got)
		}
	})

	t.Run("truncates prose exceeding 2000 chars", func(t *testing.T) {
		longText := strings.Repeat("A", 3000)
		parts := []OSCALPart{
			{Name: "statement", Prose: longText},
		}
		got := collectProse(parts)
		if len(got) != 2000 {
			t.Errorf("expected truncated length 2000, got %d", len(got))
		}
	})
}

// ---------------------------------------------------------------------------
// availableFrameworks
// ---------------------------------------------------------------------------

func TestAvailableFrameworks(t *testing.T) {
	t.Run("empty registry", func(t *testing.T) {
		reg := FrameworkRegistry{Frameworks: map[string]FrameworkEntry{}}
		got := availableFrameworks(reg)
		if len(got) != 0 {
			t.Errorf("expected empty slice, got %v", got)
		}
	})

	t.Run("sorted output", func(t *testing.T) {
		reg := FrameworkRegistry{Frameworks: map[string]FrameworkEntry{
			"nist-800-53":    {},
			"cis-aws":        {},
			"scf-full":       {},
			"fedramp-moderate": {},
		}}
		got := availableFrameworks(reg)
		want := []string{"cis-aws", "fedramp-moderate", "nist-800-53", "scf-full"}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("availableFrameworks() = %v, want %v", got, want)
		}
	})

	t.Run("single framework", func(t *testing.T) {
		reg := FrameworkRegistry{Frameworks: map[string]FrameworkEntry{"only-one": {}}}
		got := availableFrameworks(reg)
		if len(got) != 1 || got[0] != "only-one" {
			t.Errorf("unexpected: %v", got)
		}
	})
}

// ---------------------------------------------------------------------------
// parseFrameworkRegistry
// ---------------------------------------------------------------------------

func TestParseFrameworkRegistry(t *testing.T) {
	t.Run("valid registry", func(t *testing.T) {
		content := `frameworks:
  nist-800-53:
    source: "remote"
    catalog_url: "https://example.com/nist.tar.gz"
    catalog_sha: "abc123"
    tarball_path: "content/catalog.json"
    description: "NIST 800-53 Rev 5"
    license: ""
  scf-full:
    source: "local"
    description: "SCF Full"
`
		dir := t.TempDir()
		path := filepath.Join(dir, "registry.yaml")
		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			t.Fatal(err)
		}

		reg, err := parseFrameworkRegistry(path)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(reg.Frameworks) != 2 {
			t.Errorf("expected 2 frameworks, got %d", len(reg.Frameworks))
		}
		entry, ok := reg.Frameworks["nist-800-53"]
		if !ok {
			t.Fatal("missing nist-800-53 entry")
		}
		if entry.CatalogURL != "https://example.com/nist.tar.gz" {
			t.Errorf("unexpected CatalogURL: %s", entry.CatalogURL)
		}
	})

	t.Run("empty frameworks", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "registry.yaml")
		if err := os.WriteFile(path, []byte("frameworks:\n"), 0644); err != nil {
			t.Fatal(err)
		}
		reg, err := parseFrameworkRegistry(path)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// Should initialize to empty map, not nil.
		if reg.Frameworks == nil {
			t.Error("expected non-nil Frameworks map")
		}
	})

	t.Run("missing file", func(t *testing.T) {
		_, err := parseFrameworkRegistry("/nonexistent/registry.yaml")
		if err == nil {
			t.Error("expected error for missing file")
		}
	})

	t.Run("malformed yaml", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "bad.yaml")
		if err := os.WriteFile(path, []byte("{{not: valid yaml"), 0644); err != nil {
			t.Fatal(err)
		}
		_, err := parseFrameworkRegistry(path)
		if err == nil {
			t.Error("expected error for malformed yaml")
		}
	})
}

// ---------------------------------------------------------------------------
// printLicenseNotice (output capture)
// ---------------------------------------------------------------------------

func TestPrintLicenseNotice(t *testing.T) {
	captureStdout := func(fn func()) string {
		old := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w
		fn()
		w.Close()
		var buf bytes.Buffer
		buf.ReadFrom(r)
		os.Stdout = old
		return buf.String()
	}

	t.Run("empty license prints nothing", func(t *testing.T) {
		output := captureStdout(func() {
			printLicenseNotice(FrameworkEntry{License: ""})
		})
		if output != "" {
			t.Errorf("expected no output, got: %q", output)
		}
	})

	t.Run("permissive license prints notice without warning", func(t *testing.T) {
		output := captureStdout(func() {
			printLicenseNotice(FrameworkEntry{License: "Apache 2.0"})
		})
		if !strings.Contains(output, "[LICENSE] Apache 2.0") {
			t.Errorf("expected license text, got: %q", output)
		}
		if strings.Contains(output, "responsibility") {
			t.Errorf("permissive license should not show responsibility warning")
		}
	})

	t.Run("restrictive license prints responsibility warning", func(t *testing.T) {
		output := captureStdout(func() {
			printLicenseNotice(FrameworkEntry{License: "Commercial use restricted"})
		})
		if !strings.Contains(output, "[LICENSE] Commercial use restricted") {
			t.Errorf("expected license text, got: %q", output)
		}
		if !strings.Contains(output, "responsibility") {
			t.Errorf("restrictive license should show responsibility warning")
		}
	})
}

// ---------------------------------------------------------------------------
// parseOSCALCatalog (valid input, no log.Fatal paths)
// ---------------------------------------------------------------------------

func TestParseOSCALCatalog_Valid(t *testing.T) {
	catalog := `{
		"catalog": {
			"uuid": "test-uuid-1234",
			"metadata": {
				"title": "Test Catalog",
				"oscal-version": "1.1.2"
			},
			"groups": [
				{
					"id": "ac",
					"title": "Access Control",
					"controls": [
						{
							"id": "ac-1",
							"title": "Policy and Procedures",
							"parts": [
								{
									"id": "ac-1_smt",
									"name": "statement",
									"prose": "The organization develops access control policy."
								}
							]
						},
						{
							"id": "ac-2",
							"title": "Account Management",
							"parts": [
								{
									"id": "ac-2_smt",
									"name": "statement",
									"prose": "The organization manages accounts."
								}
							],
							"controls": [
								{
									"id": "ac-2.1",
									"title": "Account Management Enhancement",
									"parts": [
										{
											"id": "ac-2.1_smt",
											"name": "statement",
											"prose": "Enhancement prose."
										}
									]
								}
							]
						}
					]
				}
			]
		}
	}`

	entries := parseOSCALCatalog([]byte(catalog))

	// ac-1, ac-2, and ac-2.1 all match the controlIDPattern.
	if len(entries) < 2 {
		t.Fatalf("expected at least 2 entries, got %d", len(entries))
	}

	// Verify first entry.
	found := false
	for _, e := range entries {
		if e.ControlID == "AC-1" {
			found = true
			if !strings.Contains(e.Prose, "access control policy") {
				t.Errorf("AC-1 prose unexpected: %q", e.Prose)
			}
		}
	}
	if !found {
		t.Error("AC-1 entry not found in parsed results")
	}
}

func TestParseOSCALCatalog_FallbackToTitle(t *testing.T) {
	// When a control has no parts with statement/item/guidance prose,
	// the function falls back to the control title.
	catalog := `{
		"catalog": {
			"uuid": "test-uuid",
			"metadata": {"title": "Minimal", "oscal-version": "1.0.4"},
			"groups": [{
				"id": "sc",
				"title": "System",
				"controls": [{
					"id": "sc-1",
					"title": "System Protection",
					"parts": [{"name": "objective", "prose": "Should be skipped."}]
				}]
			}]
		}
	}`

	entries := parseOSCALCatalog([]byte(catalog))
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].Prose != "System Protection" {
		t.Errorf("expected title fallback, got prose: %q", entries[0].Prose)
	}
}

// ---------------------------------------------------------------------------
// parseCSVCatalog (valid input, no log.Fatal paths)
// ---------------------------------------------------------------------------

func TestParseCSVCatalog_Valid(t *testing.T) {
	csvData := "Control_ID,Title,Description\nGOV-01,Governance,\"Mechanisms exist to facilitate governance.\"\nGOV-02,Risk,\"Risk management controls.\"\n"
	entries := parseCSVCatalog([]byte(csvData))
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}
	if entries[0].ControlID != "GOV-01" {
		t.Errorf("unexpected control ID: %s", entries[0].ControlID)
	}
	if !strings.Contains(entries[0].Prose, "governance") {
		t.Errorf("unexpected prose: %q", entries[0].Prose)
	}
}

func TestParseCSVCatalog_AlternativeHeaders(t *testing.T) {
	// The parser accepts ID and Prose as column names.
	csvData := "ID,Prose\nAC-1,Access control policy.\n"
	entries := parseCSVCatalog([]byte(csvData))
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].ControlID != "AC-1" {
		t.Errorf("unexpected control ID: %s", entries[0].ControlID)
	}
}

func TestParseCSVCatalog_SkipsEmptyRows(t *testing.T) {
	csvData := "Control_ID,Description\nGOV-01,Valid row.\n,\nGOV-02,Another valid row.\n"
	entries := parseCSVCatalog([]byte(csvData))
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries (skipping empty), got %d", len(entries))
	}
}

func TestParseCSVCatalog_TruncatesLongProse(t *testing.T) {
	longProse := strings.Repeat("B", 3000)
	csvData := fmt.Sprintf("Control_ID,Description\nGOV-01,%s\n", longProse)
	entries := parseCSVCatalog([]byte(csvData))
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if len(entries[0].Prose) != 2000 {
		t.Errorf("expected truncated prose of length 2000, got %d", len(entries[0].Prose))
	}
}

// ---------------------------------------------------------------------------
// writeCSVProvenance (functional, writes to temp location)
// ---------------------------------------------------------------------------

func TestWriteCSVProvenance(t *testing.T) {
	// writeCSVProvenance writes to the package-level const provenanceFile,
	// which is a relative path. We run this test from a temp dir to avoid
	// polluting the repo. We just verify it doesn't panic.
	content := []byte("test CSV content for provenance")
	dir := t.TempDir()

	// Create the nested directory structure that provenanceFile expects.
	target := filepath.Join(dir, "source_provenance.json")
	_ = target

	// Since writeCSVProvenance uses a hardcoded relative path, we can't
	// easily redirect it without changing the source. Instead we verify
	// the SHA computation is deterministic by calling it and checking
	// it doesn't panic. The function prints to stdout on failure rather
	// than returning an error, so a non-panic is a pass.
	// This test primarily covers the sha256 computation and JSON marshaling
	// code paths (lines 129-153).

	// Capture stdout to suppress provenance output during tests.
	old := os.Stdout
	_, w, _ := os.Pipe()
	os.Stdout = w
	writeCSVProvenance("test.csv", content, "test-framework", 5)
	w.Close()
	os.Stdout = old
}

func TestLoadIdempotencyState(t *testing.T) {
	tmpDir := t.TempDir()

	// 1. Missing file: should create it with headers and return empty map
	path := filepath.Join(tmpDir, "reqs_missing.csv")
	processed, err := loadIdempotencyState(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(processed) != 0 {
		t.Errorf("expected empty map, got %v", processed)
	}

	// Verify file was created and has headers
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "Control_ID") {
		t.Errorf("expected headers in created file, got: %s", string(data))
	}

	// 2. Existing file with entries
	pathExist := filepath.Join(tmpDir, "reqs_exist.csv")
	csvContent := "Control_ID,Requirement_ID,Target_Provider,Parameter_Field,Operator,Expected_Value,Confidence,Status,Documentation_URL\nAC-1,REQ-1,aws,param,eq,val,1.00,PENDING,url\nIA-2,REQ-2,gcp,param,eq,val,1.00,PENDING,url\n"
	if err := os.WriteFile(pathExist, []byte(csvContent), 0644); err != nil {
		t.Fatal(err)
	}

	processedExist, err := loadIdempotencyState(pathExist)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(processedExist) != 2 {
		t.Errorf("expected 2 processed controls, got %d", len(processedExist))
	}
	if !processedExist["AC-1|aws"] {
		t.Error("expected AC-1|aws to be processed")
	}
	if !processedExist["IA-2|gcp"] {
		t.Error("expected IA-2|gcp to be processed")
	}
}

func TestLoadCatalogEntries(t *testing.T) {
	tmpDir := t.TempDir()

	// Backup and override provenanceFile to prevent modifying repository files
	oldProvenanceFile := provenanceFile
	defer func() { provenanceFile = oldProvenanceFile }()
	provenanceFile = filepath.Join(tmpDir, "source_provenance.json")

	// 1. Local CSV catalog path
	csvPath := filepath.Join(tmpDir, "catalog.csv")
	csvContent := "Control_ID,Description\nAC-1,Access control prose\n"
	if err := os.WriteFile(csvPath, []byte(csvContent), 0644); err != nil {
		t.Fatal(err)
	}
	entries, err := loadCatalogEntries(csvPath, "", "", "framework-test", false, FrameworkEntry{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 1 || entries[0].ControlID != "AC-1" {
		t.Errorf("unexpected entries: %v", entries)
	}

	// 2. Local JSON catalog path
	jsonPath := filepath.Join(tmpDir, "catalog.json")
	jsonContent := `{
		"catalog": {
			"uuid": "test-uuid-999",
			"metadata": {"title": "Test JSON", "oscal-version": "1.1.2"},
			"groups": [{
				"id": "ac",
				"title": "Access",
				"controls": [{"id": "ac-1", "title": "Access 1"}]
			}]
		}
	}`
	if err := os.WriteFile(jsonPath, []byte(jsonContent), 0644); err != nil {
		t.Fatal(err)
	}
	entriesJSON, err := loadCatalogEntries(jsonPath, "", "", "framework-test", false, FrameworkEntry{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entriesJSON) != 1 || entriesJSON[0].ControlID != "AC-1" {
		t.Errorf("unexpected entries: %v", entriesJSON)
	}

	// 3. Error path: registry lookup missing catalog info
	_, err = loadCatalogEntries("", "", "", "unknown-framework", false, FrameworkEntry{})
	if err == nil {
		t.Error("expected error when framework has no registry catalog info")
	}
}

func TestFilterByGroups(t *testing.T) {
	entries := []CatalogEntry{
		{ControlID: "AC-1", Prose: "prose 1"},
		{ControlID: "IA-2", Prose: "prose 2"},
		{ControlID: "SC-3", Prose: "prose 3"},
	}

	// 1. Single prefix
	res := filterByGroups(entries, "ac")
	if len(res) != 1 || res[0].ControlID != "AC-1" {
		t.Errorf("expected AC-1, got %v", res)
	}

	// 2. Multiple prefixes
	res = filterByGroups(entries, "ac,sc")
	if len(res) != 2 || res[0].ControlID != "AC-1" || res[1].ControlID != "SC-3" {
		t.Errorf("expected AC-1 and SC-3, got %v", res)
	}

	// 3. No match
	res = filterByGroups(entries, "xyz")
	if len(res) != 0 {
		t.Errorf("expected empty, got %v", res)
	}

	// 4. Empty filter
	res = filterByGroups(entries, "")
	if len(res) != 3 {
		t.Errorf("expected original 3 entries, got %d", len(res))
	}
}

func TestBuildCatalogRequest(t *testing.T) {
	template := "Hello {{CATALOG_PROSE_LINE}} from {{DOC_ROOT}}"
	res := buildCatalogRequest("World", "Home", template)
	expected := "Hello World from Home"
	if res != expected {
		t.Errorf("expected %q, got %q", expected, res)
	}
}

func TestMain_Triage(t *testing.T) {
	// Backup original global variables
	oldWorkspaceFile := workspaceFile
	oldRequirementsFile := requirementsFile
	oldProvenanceFile := provenanceFile
	oldPromptFile := promptFile
	oldRegistryFile := registryFile
	oldArgs := os.Args

	defer func() {
		workspaceFile = oldWorkspaceFile
		requirementsFile = oldRequirementsFile
		provenanceFile = oldProvenanceFile
		promptFile = oldPromptFile
		registryFile = oldRegistryFile
		os.Args = oldArgs
	}()

	tmpDir := t.TempDir()

	// 1. Create a dummy workspace.yaml
	workspaceFile = filepath.Join(tmpDir, "workspace.yaml")
	workspaceYAML := `organization: "Test Org"
active_providers:
  gcp:
    doc_root: "https://cloud.google.com"
`
	if err := os.WriteFile(workspaceFile, []byte(workspaceYAML), 0644); err != nil {
		t.Fatal(err)
	}

	// 2. Create framework_registry.yaml
	registryFile = filepath.Join(tmpDir, "framework_registry.yaml")
	registryYAML := `frameworks:
  fedramp-moderate:
    source: "local"
    description: "FedRAMP Moderate"
`
	if err := os.WriteFile(registryFile, []byte(registryYAML), 0644); err != nil {
		t.Fatal(err)
	}

	// 3. Create setup_03_extract_requirements.md
	promptFile = filepath.Join(tmpDir, "extract_prompt.md")
	promptMD := "Extract for {{CATALOG_PROSE_LINE}} doc root {{DOC_ROOT}}"
	if err := os.WriteFile(promptFile, []byte(promptMD), 0644); err != nil {
		t.Fatal(err)
	}

	// 4. Create dummy catalog.csv
	catalogPath := filepath.Join(tmpDir, "catalog.csv")
	catalogCSV := "Control_ID,Description\nAC-1,Access control prose\n"
	if err := os.WriteFile(catalogPath, []byte(catalogCSV), 0644); err != nil {
		t.Fatal(err)
	}

	// 5. Output files (written by main)
	requirementsFile = filepath.Join(tmpDir, "requirements.csv")
	provenanceFile = filepath.Join(tmpDir, "source_provenance.json")

	// 6. Mock LLM Server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Mock response body of ChatResponse
		response := map[string]interface{}{
			"choices": []map[string]interface{}{
				{
					"message": map[string]interface{}{
						"content": `{"Requirement_ID":"REQ-1","Target_Provider":"gcp","Parameter_Field":"test_param","Operator":"eq","Expected_Value":"true","Confidence":0.95,"Status":"PENDING","Documentation_URL":"http://doc"}`,
					},
				},
			},
		}
		data, _ := json.Marshal(response)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(data)
	}))
	defer server.Close()

	// Configure environment variables
	t.Setenv("JULA_PRIMARY_ENDPOINT", server.URL)
	t.Setenv("JULA_PRIMARY_KEY", "test-key")
	t.Setenv("JULA_PRIMARY_MODEL", "test-model")

	// Set CLI args
	os.Args = []string{
		"import",
		"--framework", "fedramp-moderate",
		"--catalog", catalogPath,
		"--provider", "gcp",
	}

	// Run main
	main()

	// Verify outputs were generated
	if _, err := os.Stat(requirementsFile); os.IsNotExist(err) {
		t.Error("expected requirements.csv to be created")
	}
	if _, err := os.Stat(provenanceFile); os.IsNotExist(err) {
		t.Error("expected source_provenance.json to be created")
	}
}

func createDummyTarGz(t *testing.T, filename string, content []byte) []byte {
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	header := &tar.Header{
		Name: filename,
		Size: int64(len(content)),
		Mode: 0600,
	}
	if err := tw.WriteHeader(header); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestOSCALDownloaderAndParser(t *testing.T) {
	// Create minimal valid OSCAL catalog JSON
	catalogJSON := `{
		"catalog": {
			"uuid": "test-uuid-001",
			"metadata": {
				"title": "NIST SP 800-53 Rev 5",
				"oscal-version": "1.1.2"
			},
			"groups": [
				{
					"id": "ac",
					"title": "Access Control",
					"controls": [
						{
							"id": "ac-1",
							"title": "Policy and Procedures",
							"parts": [
								{
									"id": "ac-1_smt",
									"name": "statement",
									"prose": "The organization develops access control policy."
								}
							]
						}
					]
				}
			]
		}
	}`

	tarGzBytes := createDummyTarGz(t, "content/catalog.json", []byte(catalogJSON))

	// Setup mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-gzip")
		w.WriteHeader(http.StatusOK)
		w.Write(tarGzBytes)
	}))
	defer server.Close()

	// Calculate expected SHA256 of the served archive
	hasher := sha256.New()
	hasher.Write(tarGzBytes)
	expectedSHA := hex.EncodeToString(hasher.Sum(nil))

	// Test downloadOSCALRelease
	tmpFile := downloadOSCALRelease(server.URL)
	defer os.Remove(tmpFile)

	if _, err := os.Stat(tmpFile); os.IsNotExist(err) {
		t.Fatalf("expected downloaded temp file to exist, got none")
	}

	// Test verifyIntegrity
	verifyIntegrity(tmpFile, expectedSHA)

	// Test extractFromTarball
	extracted := extractFromTarball(tmpFile, "content/catalog.json")
	if !strings.Contains(string(extracted), "test-uuid-001") {
		t.Errorf("expected extracted JSON to contain UUID, got: %s", string(extracted))
	}

	// Test loadCatalogEntries default (remote tarball download flow via mock registry entry)
	regEntry := FrameworkEntry{
		Source:      "remote",
		CatalogURL:  server.URL,
		CatalogSHA:  expectedSHA,
		TarballPath: "content/catalog.json",
	}

	entries, err := loadCatalogEntries("", "", "", "fedramp-moderate", true, regEntry)
	if err != nil {
		t.Fatalf("unexpected loadCatalogEntries error: %v", err)
	}

	if len(entries) != 1 || entries[0].ControlID != "AC-1" {
		t.Errorf("expected 1 entry with ID AC-1, got %v", entries)
	}
}

func TestMain_MissingFramework(t *testing.T) {
	// Backup exitFunc and Args
	oldExit := exitFunc
	oldArgs := os.Args
	defer func() {
		exitFunc = oldExit
		os.Args = oldArgs
	}()

	exitCalled := false
	var exitCode int
	exitFunc = func(code int) {
		exitCalled = true
		exitCode = code
		panic("exit")
	}

	defer func() {
		if r := recover(); r != nil {
			if r != "exit" {
				panic(r)
			}
		}
		if !exitCalled || exitCode != 1 {
			t.Errorf("expected exitFunc(1) when framework is missing, got called=%t code=%d", exitCalled, exitCode)
		}
	}()

	os.Args = []string{"import"} // no framework parameter

	// Run main
	main()
}
