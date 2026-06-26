package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"jula-governor/internal/aiutil"
	"go.yaml.in/yaml/v4"
)

var (
	workspaceFile    = "../../workspace.yaml"
	requirementsFile = "../../requirements.csv"
	provenanceFile   = "../../source_provenance.json"
	promptFile       = "../../engine/prompts/setup_03_extract_requirements.md"
	registryFile     = "../../framework_registry.yaml"
	exitFunc         = os.Exit
)

// FrameworkEntry represents a single framework in the registry.
type FrameworkEntry struct {
	Source      string `yaml:"source"`
	CatalogURL  string `yaml:"catalog_url"`
	CatalogSHA  string `yaml:"catalog_sha"`
	TarballPath string `yaml:"tarball_path"`
	Description string `yaml:"description"`
	License     string `yaml:"license"`
}

// FrameworkRegistry is the top-level structure of framework_registry.yaml.
type FrameworkRegistry struct {
	Frameworks map[string]FrameworkEntry `yaml:"frameworks"`
}

// parseFrameworkRegistry reads and parses the framework registry YAML.
func parseFrameworkRegistry(path string) (FrameworkRegistry, error) {
	var reg FrameworkRegistry
	data, err := os.ReadFile(path)
	if err != nil {
		return reg, fmt.Errorf("failed to read framework registry: %w", err)
	}
	if err := yaml.Unmarshal(data, &reg); err != nil {
		return reg, fmt.Errorf("failed to parse framework registry: %w", err)
	}
	if reg.Frameworks == nil {
		reg.Frameworks = make(map[string]FrameworkEntry)
	}
	return reg, nil
}

// isRestrictiveLicense checks if a license string contains restrictive terms.
func isRestrictiveLicense(license string) bool {
	lower := strings.ToLower(license)
	return strings.Contains(lower, "commercial") || strings.Contains(lower, "require") || strings.Contains(lower, "restricted")
}

// printLicenseNotice prints a licensing notice if the framework entry has a license field.
// For restrictive licenses, it adds a responsibility warning.
func printLicenseNotice(entry FrameworkEntry) {
	if entry.License == "" {
		return
	}
	fmt.Println("")
	fmt.Println("[LICENSE] " + entry.License)
	if isRestrictiveLicense(entry.License) {
		fmt.Println("[LICENSE] By proceeding, you accept responsibility for licensing compliance.")
	}
	fmt.Println("")
}

// availableFrameworks returns a sorted list of framework names from the registry.
func availableFrameworks(reg FrameworkRegistry) []string {
	names := make([]string, 0, len(reg.Frameworks))
	for name := range reg.Frameworks {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// allowedOSCALVersions is the whitelist of known-good OSCAL specification versions.
var allowedOSCALVersions = map[string]bool{
	"1.0.4": true, // SCF OSCAL catalogs
	"1.1.2": true,
	"1.2.0": true,
	"1.2.2": true,
}

// controlIDPattern validates OSCAL control IDs from any supported framework.
// Matches:
//   - NIST 800-53: ac-1, sc-28
//   - SCF: GOV-01, IAC-15.1
//   - NIST CSF v2.0: GV.OC-01, PR.DS-01
//   - NIST 800-171: 03.01.01
var controlIDPattern = regexp.MustCompile(`(?i)^(?:[a-z]{2,5}(?:\.[a-z]{2,5})?-\d+(?:\.\d+)?|\d{2}\.\d{2}\.\d{2})$`)

// detectSourceFormat determines the catalog format from a file path.
// Returns "csv" for .csv files, "json" for .json files.
// If the extension is unrecognized, it peeks at the content.
func detectSourceFormat(path string, content []byte) string {
	lower := strings.ToLower(path)
	if strings.HasSuffix(lower, ".csv") {
		return "csv"
	}
	if strings.HasSuffix(lower, ".json") {
		return "json"
	}
	// Fallback: peek at the first non-whitespace byte.
	trimmed := bytes.TrimSpace(content)
	if len(trimmed) > 0 && trimmed[0] == '{' {
		return "json"
	}
	return "csv"
}

// writeCSVProvenance computes SHA-256 of the CSV source and writes provenance metadata.
// This file gets included in the signed policy bundle, so Key B transitively covers the source hash.
func writeCSVProvenance(sourcePath string, content []byte, framework string, controlsCount int) {
	hasher := sha256.New()
	hasher.Write(content)
	hash := hex.EncodeToString(hasher.Sum(nil))

	prov := map[string]interface{}{
		"source_file":   filepath.Base(sourcePath),
		"source_sha256": hash,
		"framework":     framework,
		"imported_at":   time.Now().UTC().Format(time.RFC3339),
		"controls_count": controlsCount,
	}

	provJSON, err := json.MarshalIndent(prov, "", "  ")
	if err != nil {
		fmt.Printf("[WARNING] Failed to marshal source provenance: %v\n", err)
		return
	}

	if err := os.WriteFile(provenanceFile, provJSON, 0644); err != nil {
		fmt.Printf("[WARNING] Failed to write source provenance to %s: %v\n", provenanceFile, err)
		return
	}

	fmt.Printf("[PROVENANCE] CSV source hash: %s\n", hash)
	fmt.Printf("[PROVENANCE] Written to %s\n", provenanceFile)
}

// CatalogEntry is the normalized representation of a control from any source.
type CatalogEntry struct {
	ControlID string
	Prose     string
}

// OSCAL JSON structures for deserializing NIST catalog files.
type OSCALDocument struct {
	Catalog OSCALCatalog `json:"catalog"`
}

type OSCALCatalog struct {
	UUID     string         `json:"uuid"`
	Metadata OSCALMetadata  `json:"metadata"`
	Groups   []OSCALGroup   `json:"groups"`
}

type OSCALMetadata struct {
	Title        string `json:"title"`
	OSCALVersion string `json:"oscal-version"`
}

type OSCALGroup struct {
	ID       string         `json:"id"`
	Title    string         `json:"title"`
	Controls []OSCALControl `json:"controls"`
}

type OSCALControl struct {
	ID       string         `json:"id"`
	Title    string         `json:"title"`
	Parts    []OSCALPart    `json:"parts"`
	Controls []OSCALControl `json:"controls"` // control enhancements (nested)
}

type OSCALPart struct {
	ID    string      `json:"id"`
	Name  string      `json:"name"`
	Prose string      `json:"prose"`
	Parts []OSCALPart `json:"parts"` // nested sub-parts
}

// downloadOSCALRelease downloads an OSCAL release tarball to a temp file.
func downloadOSCALRelease(catalogURL string) string {
	fmt.Println("[OSCAL] Downloading catalog from pinned release...")
	fmt.Printf("         URL: %s\n", catalogURL)

	resp, err := http.Get(catalogURL) //nolint:gosec // URL is from framework registry, not arbitrary user input
	if err != nil {
		log.Fatalf("[FATAL] Failed to download OSCAL release: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		log.Fatalf("[FATAL] OSCAL download returned HTTP %d", resp.StatusCode)
	}

	tmpFile, err := os.CreateTemp("", "oscal-content-*.tar.gz")
	if err != nil {
		log.Fatalf("[FATAL] Failed to create temp file: %v", err)
	}

	written, err := io.Copy(tmpFile, resp.Body)
	if err != nil {
		tmpFile.Close()
		os.Remove(tmpFile.Name())
		log.Fatalf("[FATAL] Failed to write OSCAL tarball: %v", err)
	}
	tmpFile.Close()

	// Reject files larger than 100MB as a sanity bound.
	if written > 100*1024*1024 {
		os.Remove(tmpFile.Name())
		log.Fatalf("[FATAL] OSCAL tarball exceeds 100MB size limit (%d bytes)", written)
	}

	fmt.Printf("         Downloaded %d bytes to %s\n", written, tmpFile.Name())
	return tmpFile.Name()
}

// verifyIntegrity computes the SHA-256 hash of the file and compares it against the expected hash.
func verifyIntegrity(path string, expectedSHA string) {
	fmt.Println("[OSCAL] Verifying SHA-256 integrity...")

	f, err := os.Open(path)
	if err != nil {
		log.Fatalf("[FATAL] Failed to open file for hashing: %v", err)
	}
	defer f.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, f); err != nil {
		log.Fatalf("[FATAL] Failed to compute SHA-256: %v", err)
	}

	computed := hex.EncodeToString(hasher.Sum(nil))
	if computed != expectedSHA {
		log.Fatalf("[FATAL] SHA-256 MISMATCH. Expected: %s Got: %s. The file may have been tampered with.", expectedSHA, computed)
	}

	fmt.Printf("         SHA-256: %s ✓\n", computed)
}

// openTarballReader opens a tarball and returns a gzip reader and a tar reader.
func openTarballReader(tarPath string) (*tar.Reader, io.Closer, io.Closer, error) {
	f, err := os.Open(tarPath)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to open tarball: %w", err)
	}

	gzr, err := gzip.NewReader(f)
	if err != nil {
		f.Close()
		return nil, nil, nil, fmt.Errorf("failed to decompress tarball: %w", err)
	}

	tr := tar.NewReader(gzr)
	return tr, gzr, f, nil
}

// findAndExtractEntry searches for a specific file path inside the tar reader and returns its content.
func findAndExtractEntry(tr *tar.Reader, entryPath string) ([]byte, error) {
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("error reading tarball: %w", err)
		}

		if header.Name == entryPath {
			if header.Size > 15*1024*1024 {
				return nil, fmt.Errorf("catalog JSON exceeds 15MB size limit (%d bytes)", header.Size)
			}

			data, err := io.ReadAll(tr)
			if err != nil {
				return nil, fmt.Errorf("failed to read catalog JSON from tarball: %w", err)
			}
			return data, nil
		}
	}
	return nil, fmt.Errorf("entry not found in tarball: %s", entryPath)
}

// extractFromTarball streams through a tar.gz archive and extracts a single file by path.
func extractFromTarball(tarPath, entryPath string) []byte {
	fmt.Printf("[OSCAL] Extracting %s...\n", entryPath)

	tr, gzr, f, err := openTarballReader(tarPath)
	if err != nil {
		log.Fatalf("[FATAL] %v", err)
	}
	defer f.Close()
	defer gzr.Close()

	data, err := findAndExtractEntry(tr, entryPath)
	if err != nil {
		log.Fatalf("[FATAL] %v", err)
	}

	fmt.Printf("         Extracted %d bytes\n", len(data))
	return data
}

// isProsePart checks if an OSCALPart has a name indicating it holds prose.
func isProsePart(name string) bool {
	return name == "statement" || name == "item" || name == "guidance"
}

// collectProse recursively collects prose text from a control's parts tree.
// It concatenates statement and guidance prose, separated by spaces.
func collectProse(parts []OSCALPart) string {
	var segments []string
	for _, p := range parts {
		if p.Prose != "" && isProsePart(p.Name) {
			text := p.Prose
			if len(text) > 2000 {
				text = text[:2000]
			}
			segments = append(segments, text)
		}
		if len(p.Parts) > 0 {
			if nested := collectProse(p.Parts); nested != "" {
				segments = append(segments, nested)
			}
		}
	}
	return strings.Join(segments, " ")
}

// validateOSCALCatalog runs basic schema validation checks on the deserialized catalog.
func validateOSCALCatalog(catalog OSCALCatalog) error {
	if catalog.UUID == "" {
		return fmt.Errorf("OSCAL catalog missing UUID field")
	}
	if !allowedOSCALVersions[catalog.Metadata.OSCALVersion] {
		return fmt.Errorf("unrecognized OSCAL version: %s. Allowed: %v", catalog.Metadata.OSCALVersion, allowedOSCALVersions)
	}
	if len(catalog.Groups) == 0 {
		return fmt.Errorf("OSCAL catalog has no control groups")
	}
	return nil
}

// extractOSCALControls extracts CatalogEntry values from catalog groups.
func extractOSCALControls(groups []OSCALGroup) []CatalogEntry {
	var entries []CatalogEntry
	var extractControls func(controls []OSCALControl)
	extractControls = func(controls []OSCALControl) {
		for _, ctrl := range controls {
			if !controlIDPattern.MatchString(ctrl.ID) {
				continue // skip enhancements like ac-2.1 (only base controls)
			}

			prose := collectProse(ctrl.Parts)
			if prose == "" {
				prose = ctrl.Title
			}

			entries = append(entries, CatalogEntry{
				ControlID: strings.ToUpper(ctrl.ID),
				Prose:     prose,
			})

			if len(ctrl.Controls) > 0 {
				extractControls(ctrl.Controls)
			}
		}
	}

	for _, group := range groups {
		extractControls(group.Controls)
	}
	return entries
}

// parseOSCALCatalog deserializes OSCAL JSON and returns normalized CatalogEntry values.
func parseOSCALCatalog(data []byte) []CatalogEntry {
	var doc OSCALDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		log.Fatalf("[FATAL] Failed to parse OSCAL JSON: %v", err)
	}

	catalog := doc.Catalog

	if err := validateOSCALCatalog(catalog); err != nil {
		log.Fatalf("[FATAL] %v", err)
	}

	fmt.Printf("[OSCAL] Catalog: %s\n", catalog.Metadata.Title)
	fmt.Printf("         OSCAL Version: %s\n", catalog.Metadata.OSCALVersion)
	fmt.Printf("         Groups: %d\n", len(catalog.Groups))

	entries := extractOSCALControls(catalog.Groups)

	if len(entries) > 5000 {
		log.Fatalf("[FATAL] OSCAL catalog has %d controls, exceeding the 5,000 limit.", len(entries))
	}
	if len(entries) > 1500 {
		fmt.Printf("[WARNING] Large catalog: %d controls. This will generate many AI calls.\n", len(entries))
	}

	fmt.Printf("         Controls extracted: %d\n", len(entries))
	return entries
}

// mapCSVHeaderColumns searches for the ID and Description column indices.
func mapCSVHeaderColumns(header []string) (idIdx, proseIdx int, err error) {
	idIdx = -1
	proseIdx = -1
	for i, col := range header {
		normalized := strings.ToLower(strings.TrimSpace(col))
		switch normalized {
		case "control_id", "id", "control id", "controlid":
			idIdx = i
		case "description", "prose", "statement", "control_description":
			if proseIdx == -1 {
				proseIdx = i
			}
		}
	}

	if idIdx == -1 {
		return -1, -1, fmt.Errorf("CSV catalog missing required column: Control_ID (or ID)")
	}
	if proseIdx == -1 {
		return -1, -1, fmt.Errorf("CSV catalog missing required column: Description (or Prose, Statement)")
	}
	return idIdx, proseIdx, nil
}

// parseCSVRecords processes raw CSV records into CatalogEntry values.
func parseCSVRecords(records [][]string, idIdx, proseIdx int) []CatalogEntry {
	var entries []CatalogEntry
	for _, row := range records[1:] {
		if len(row) <= idIdx || len(row) <= proseIdx {
			continue
		}

		controlID := strings.TrimSpace(row[idIdx])
		prose := strings.TrimSpace(row[proseIdx])

		if controlID == "" || prose == "" {
			continue
		}

		if len(prose) > 2000 {
			prose = prose[:2000]
		}

		entries = append(entries, CatalogEntry{
			ControlID: strings.ToUpper(controlID),
			Prose:     prose,
		})
	}
	return entries
}

// parseCSVCatalog reads a CSV file with Control_ID and Description/Prose columns.
func parseCSVCatalog(data []byte) []CatalogEntry {
	reader := csv.NewReader(bytes.NewReader(data))
	reader.LazyQuotes = true
	reader.TrimLeadingSpace = true

	records, err := reader.ReadAll()
	if err != nil {
		log.Fatalf("[FATAL] Failed to parse CSV catalog: %v", err)
	}

	if len(records) < 2 {
		log.Fatal("[FATAL] CSV catalog must have a header row and at least one data row.")
	}

	idIdx, proseIdx, err := mapCSVHeaderColumns(records[0])
	if err != nil {
		log.Fatalf("[FATAL] %v", err)
	}

	if len(records)-1 > 5000 {
		log.Fatalf("[FATAL] CSV catalog has %d rows, exceeding the 5,000 limit.", len(records)-1)
	}

	entries := parseCSVRecords(records, idIdx, proseIdx)

	if len(entries) == 0 {
		log.Fatal("[FATAL] CSV catalog produced zero valid entries. Check column headers and data.")
	}

	if len(entries) > 1500 {
		fmt.Printf("[WARNING] Large catalog: %d controls. This will generate many AI calls.\n", len(entries))
	}

	fmt.Printf("[CSV] Parsed %d controls from CSV catalog\n", len(entries))
	return entries
}

type RequirementExtraction struct {
	RequirementID    string  `json:"Requirement_ID"`
	TargetProvider   string  `json:"Target_Provider"`
	ParameterField   string  `json:"Parameter_Field"`
	Operator         string  `json:"Operator"`
	ExpectedValue    string  `json:"Expected_Value"`
	Confidence       float64 `json:"Confidence"`
	Status           string  `json:"Status"`
	DocumentationURL string  `json:"Documentation_URL"`
}

func processWithRetriesAndFailover(primary, fallback aiutil.AIConfig, maxRetries int, prompt string) (RequirementExtraction, error) {
	req := aiutil.ChatRequest{
		Model: primary.Model, // Model is set per-tier inside aiutil
		Messages: []aiutil.ChatMessage{
			{Role: "user", Content: prompt},
		},
		ResponseFormat: map[string]string{"type": "json_object"},
	}

	rawJSONContent, _, err := aiutil.ProcessWithRetriesAndFailover(primary, fallback, maxRetries, req)
	if err != nil {
		return RequirementExtraction{}, err
	}

	// Strip markdown fences if present.
	if strings.HasPrefix(rawJSONContent, "```json") {
		rawJSONContent = strings.TrimPrefix(rawJSONContent, "```json")
		rawJSONContent = strings.TrimSuffix(rawJSONContent, "```")
		rawJSONContent = strings.TrimSpace(rawJSONContent)
	}

	var extraction RequirementExtraction
	if parseErr := json.Unmarshal([]byte(rawJSONContent), &extraction); parseErr != nil {
		return extraction, fmt.Errorf("failed to parse extracted JSON object: %w. Raw text: %s", parseErr, rawJSONContent)
	}
	return extraction, nil
}

// initializeIdempotencyFile creates a new idempotency CSV file with standard headers.
func initializeIdempotencyFile(path string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to create idempotency file: %w", err)
	}
	defer f.Close()

	writer := csv.NewWriter(f)
	err = writer.Write([]string{"Control_ID", "Requirement_ID", "Target_Provider", "Parameter_Field", "Operator", "Expected_Value", "Confidence", "Status", "Documentation_URL"})
	if err != nil {
		return fmt.Errorf("failed to write headers: %w", err)
	}
	writer.Flush()
	return nil
}

// parseIdempotencyRecords parses CSV records to construct the processed controls map.
func parseIdempotencyRecords(records [][]string) map[string]bool {
	processed := make(map[string]bool)
	if len(records) == 0 {
		return processed
	}

	header := records[0]
	idIdx, provIdx := -1, -1
	for i, col := range header {
		switch strings.TrimSpace(col) {
		case "Control_ID":
			idIdx = i
		case "Target_Provider":
			provIdx = i
		}
	}

	if idIdx != -1 {
		for _, row := range records[1:] {
			if len(row) > idIdx {
				prov := ""
				if provIdx != -1 && len(row) > provIdx {
					prov = row[provIdx]
				}
				processed[row[idIdx]+"|"+prov] = true
			}
		}
	}
	return processed
}

// loadIdempotencyState reads an existing requirements CSV file and returns
// a map of already processed Control_ID|Provider keys. If the file does not exist,
// it initializes it with headers.
func loadIdempotencyState(path string) (map[string]bool, error) {
	if _, err := os.Stat(path); err != nil {
		if initErr := initializeIdempotencyFile(path); initErr != nil {
			return nil, initErr
		}
		return make(map[string]bool), nil
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open idempotency file: %w", err)
	}
	defer f.Close()

	reader := csv.NewReader(f)
	records, err := reader.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("failed to read idempotency records: %w", err)
	}

	return parseIdempotencyRecords(records), nil
}

// loadCatalogFromLocalPath loads catalog entries from a local file.
func loadCatalogFromLocalPath(catalogPath, sourceFormat, framework string, inRegistry bool, registryEntry FrameworkEntry) ([]CatalogEntry, error) {
	jsonBytes, err := os.ReadFile(catalogPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read catalog file %s: %w", catalogPath, err)
	}

	format := sourceFormat
	if format == "" {
		format = detectSourceFormat(catalogPath, jsonBytes)
	} else if format == "oscal" {
		format = "json"
	}
	fmt.Printf("[CATALOG] Loading from local file: %s (format: %s)\n", catalogPath, format)

	if inRegistry && registryEntry.CatalogSHA != "" {
		verifyIntegrity(catalogPath, registryEntry.CatalogSHA)
	}

	switch format {
	case "csv":
		entries := parseCSVCatalog(jsonBytes)
		writeCSVProvenance(catalogPath, jsonBytes, framework, len(entries))
		return entries, nil
	default:
		return parseOSCALCatalog(jsonBytes), nil
	}
}

// loadCatalogFromURL downloads and loads catalog entries from a URL.
func loadCatalogFromURL(catalogURL, sourceFormat string) ([]CatalogEntry, error) {
	fmt.Printf("[CATALOG] Downloading catalog from URL: %s\n", catalogURL)
	resp, httpErr := http.Get(catalogURL) //nolint:gosec
	if httpErr != nil {
		return nil, fmt.Errorf("failed to download catalog from %s: %w", catalogURL, httpErr)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("catalog download returned HTTP %d", resp.StatusCode)
	}
	jsonBytes, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		return nil, fmt.Errorf("failed to read catalog response body: %w", readErr)
	}

	format := sourceFormat
	if format == "" {
		format = detectSourceFormat(catalogURL, jsonBytes)
	} else if format == "oscal" {
		format = "json"
	}
	fmt.Printf("         Detected format: %s\n", format)

	switch format {
	case "csv":
		return parseCSVCatalog(jsonBytes), nil
	default:
		return parseOSCALCatalog(jsonBytes), nil
	}
}

// loadCatalogFromRegistry downloads and loads catalog entries from the registry release URL.
func loadCatalogFromRegistry(framework string, inRegistry bool, registryEntry FrameworkEntry) ([]CatalogEntry, error) {
	if !inRegistry || registryEntry.CatalogURL == "" {
		return nil, fmt.Errorf("framework '%s' has no catalog_url in registry and no --catalog was provided", framework)
	}
	tarPath := downloadOSCALRelease(registryEntry.CatalogURL)
	defer os.Remove(tarPath)
	if registryEntry.CatalogSHA != "" {
		verifyIntegrity(tarPath, registryEntry.CatalogSHA)
	} else {
		fmt.Println("[WARNING] No SHA-256 hash in registry for this framework. Skipping integrity check.")
	}
	if registryEntry.TarballPath == "" {
		return nil, fmt.Errorf("framework '%s' has no tarball_path in registry", framework)
	}
	jsonBytes := extractFromTarball(tarPath, registryEntry.TarballPath)
	return parseOSCALCatalog(jsonBytes), nil
}

// loadCatalogEntries loads and parses a catalog from a local path, URL, or framework registry.
func loadCatalogEntries(catalogPath, catalogURL, sourceFormat, framework string, inRegistry bool, registryEntry FrameworkEntry) ([]CatalogEntry, error) {
	switch {
	case catalogPath != "":
		return loadCatalogFromLocalPath(catalogPath, sourceFormat, framework, inRegistry, registryEntry)
	case catalogURL != "":
		return loadCatalogFromURL(catalogURL, sourceFormat)
	default:
		return loadCatalogFromRegistry(framework, inRegistry, registryEntry)
	}
}

// filterByGroups filters CatalogEntry slices by a list of comma-separated prefixes.
func filterByGroups(entries []CatalogEntry, filterGroups string) []CatalogEntry {
	if filterGroups == "" {
		return entries
	}
	prefixes := strings.Split(strings.ToLower(filterGroups), ",")
	for i := range prefixes {
		prefixes[i] = strings.TrimSpace(prefixes[i])
	}
	var filtered []CatalogEntry
	for _, entry := range entries {
		lowerID := strings.ToLower(entry.ControlID)
		for _, prefix := range prefixes {
			if strings.HasPrefix(lowerID, prefix) {
				filtered = append(filtered, entry)
				break
			}
		}
	}
	fmt.Printf("[FILTER] --filter-group %s: %d of %d controls matched\n", filterGroups, len(filtered), len(entries))
	return filtered
}

// buildCatalogRequest templates the AI prompt with catalog prose and document root.
func buildCatalogRequest(prose, docRoot, promptTemplate string) string {
	hydrated := strings.ReplaceAll(promptTemplate, "{{CATALOG_PROSE_LINE}}", prose)
	hydrated = strings.ReplaceAll(hydrated, "{{DOC_ROOT}}", docRoot)
	return hydrated
}

// CLIArgs holds the parsed CLI command arguments.
type CLIArgs struct {
	resetMode       bool
	defaultProvider string
	framework       string
	catalogPath     string
	catalogURL      string
	sourceFormat    string
	filterGroups    string
}

// parseCLIArgs parses os.Args and returns a populated CLIArgs struct.
func parseCLIArgs(args []string) CLIArgs {
	var cli CLIArgs
	for i := 1; i < len(args); i++ {
		arg := args[i]
		if arg == "--reset" {
			cli.resetMode = true
		} else if arg == "--provider" && i+1 < len(args) {
			i++
			cli.defaultProvider = strings.ToLower(strings.TrimSpace(args[i]))
		} else if strings.HasPrefix(arg, "--provider=") {
			cli.defaultProvider = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(arg, "--provider=")))
		} else if arg == "--framework" && i+1 < len(args) {
			i++
			cli.framework = strings.ToLower(strings.TrimSpace(args[i]))
		} else if strings.HasPrefix(arg, "--framework=") {
			cli.framework = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(arg, "--framework=")))
		} else if arg == "--catalog" && i+1 < len(args) {
			i++
			cli.catalogPath = strings.TrimSpace(args[i])
		} else if strings.HasPrefix(arg, "--catalog=") {
			cli.catalogPath = strings.TrimSpace(strings.TrimPrefix(arg, "--catalog="))
		} else if arg == "--catalog-url" && i+1 < len(args) {
			i++
			cli.catalogURL = strings.TrimSpace(args[i])
		} else if strings.HasPrefix(arg, "--catalog-url=") {
			cli.catalogURL = strings.TrimSpace(strings.TrimPrefix(arg, "--catalog-url="))
		} else if arg == "--source" && i+1 < len(args) {
			i++
			cli.sourceFormat = strings.ToLower(strings.TrimSpace(args[i]))
		} else if strings.HasPrefix(arg, "--source=") {
			cli.sourceFormat = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(arg, "--source=")))
		} else if arg == "--filter-group" && i+1 < len(args) {
			i++
			cli.filterGroups = strings.TrimSpace(args[i])
		} else if strings.HasPrefix(arg, "--filter-group=") {
			cli.filterGroups = strings.TrimSpace(strings.TrimPrefix(arg, "--filter-group="))
		}
	}
	return cli
}

// initializeImport handles framework validation, lookup, licensing, and workspace reset setup.
func initializeImport(args CLIArgs, registry FrameworkRegistry) (FrameworkEntry, bool) {
	if args.framework == "" {
		fmt.Println("[FATAL] --framework is required.")
		fmt.Printf("  Available frameworks: %s\n", strings.Join(availableFrameworks(registry), ", "))
		fmt.Println("  Or use --catalog <path> with any --framework name for custom OSCAL catalogs.")
		fmt.Println("  Example: ./import --framework fedramp-moderate --provider gcp")
		fmt.Println("  Example: ./import --framework scf-full --catalog ./catalogs/scf-oscal.json --provider gcp")
		exitFunc(1)
	}

	entry, inRegistry := registry.Frameworks[args.framework]

	if args.catalogPath == "" && args.catalogURL == "" {
		if !inRegistry {
			log.Fatalf("[FATAL] Unknown framework: %s.\n  Available: %s\n  Or use --catalog <path> for custom OSCAL catalogs.", args.framework, strings.Join(availableFrameworks(registry), ", "))
		}
		if entry.Source == "local" {
			log.Fatalf("[FATAL] Framework '%s' requires a local catalog file. Use --catalog <path>.\n  %s", args.framework, entry.Description)
		}
	}

	if inRegistry {
		printLicenseNotice(entry)
	}

	if args.resetMode {
		fmt.Printf("[INIT] --reset flag detected. Wiping existing %s...\n", requirementsFile)
		os.Remove(requirementsFile)
	}
	if args.defaultProvider != "" {
		fmt.Printf("[INIT] Provider: %s | Framework: %s\n", args.defaultProvider, args.framework)
	} else {
		fmt.Printf("[INIT] Framework: %s\n", args.framework)
	}

	return entry, inRegistry
}

// triageControlEntry triages a single control entry, calling AI and logging results to CSV.
func triageControlEntry(entry CatalogEntry, defaultProvider string, workspace aiutil.Workspace, promptTemplate string, primaryConfig, fallbackConfig aiutil.AIConfig, maxRetries int, processedControls map[string]bool) error {
	controlID := entry.ControlID
	prose := entry.Prose

	resolvedProvider := defaultProvider
	resolutionMethod := "cli_default"

	if resolvedProvider == "" {
		fmt.Printf("[WARNING] No --provider specified for %s. Skipping.\n", controlID)
		return nil
	}

	idempotencyKey := controlID + "|" + resolvedProvider
	if processedControls[idempotencyKey] {
		fmt.Printf("[SKIP] Control %s for %s already triaged.\n", controlID, resolvedProvider)
		return nil
	}

	providerConf, exists := workspace.ActiveProviders[resolvedProvider]
	if !exists {
		fmt.Printf("[IGNORE] Provider '%s' is not enabled in workspace.yaml. Skipping %s.\n", resolvedProvider, controlID)
		return nil
	}

	fmt.Printf("[INGEST] Triaging Control %s (provider: %s, via: %s)...\n", controlID, resolvedProvider, resolutionMethod)

	hydratedPrompt := buildCatalogRequest(prose, providerConf.DocRoot, promptTemplate)

	extraction, err := processWithRetriesAndFailover(primaryConfig, fallbackConfig, maxRetries, hydratedPrompt)
	if err != nil {
		return fmt.Errorf("failed to extract requirements: %w", err)
	}

	if extraction.Status != "MANUAL_AUDIT" && extraction.ParameterField != "N/A" {
		extraction.TargetProvider = resolvedProvider
	}

	status := "PENDING"
	if extraction.Status != "" {
		status = strings.ToUpper(extraction.Status)
	}
	if extraction.Confidence <= 0.01 || extraction.ParameterField == "N/A" || strings.ToUpper(extraction.Operator) == "N/A" {
		status = "MANUAL_AUDIT"
	}

	outF, err := os.OpenFile(requirementsFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("could not open requirements.csv for appending: %w", err)
	}
	defer outF.Close()

	writer := csv.NewWriter(outF)
	err = writer.Write([]string{
		controlID,
		extraction.RequirementID,
		extraction.TargetProvider,
		extraction.ParameterField,
		extraction.Operator,
		extraction.ExpectedValue,
		fmt.Sprintf("%.2f", extraction.Confidence),
		status,
		extraction.DocumentationURL,
	})
	if err != nil {
		return fmt.Errorf("could not write to requirements.csv: %w", err)
	}
	writer.Flush()

	fmt.Printf("         [SUCCESS] Logged %s\n", extraction.RequirementID)
	return nil
}

// triageControls iterates over and triages a list of catalog entries.
func triageControls(entries []CatalogEntry, defaultProvider string, workspace aiutil.Workspace, promptTemplate string, primaryConfig, fallbackConfig aiutil.AIConfig, maxRetries int, processedControls map[string]bool) {
	for _, entry := range entries {
		if err := triageControlEntry(entry, defaultProvider, workspace, promptTemplate, primaryConfig, fallbackConfig, maxRetries, processedControls); err != nil {
			fmt.Printf("         [ERROR] %v\n", err)
		}
	}
}

func main() {
	primaryConfig := aiutil.LoadPrimaryConfig()
	fallbackConfig := aiutil.LoadFallbackConfig()
	maxRetries := aiutil.LoadMaxRetries()

	cliArgs := parseCLIArgs(os.Args)

	registry, regErr := parseFrameworkRegistry(registryFile)
	if regErr != nil {
		log.Printf("[WARNING] Could not load framework registry: %v. Proceeding without registry.", regErr)
		registry = FrameworkRegistry{Frameworks: make(map[string]FrameworkEntry)}
	} else {
		fmt.Printf("[REGISTRY] Loaded %d frameworks from registry\n", len(registry.Frameworks))
	}

	registryEntry, inRegistry := initializeImport(cliArgs, registry)

	aiutil.RequireAIConfig(primaryConfig, fallbackConfig)

	workspace, err := aiutil.ParseWorkspace(workspaceFile)
	if err != nil {
		log.Fatalf("[FATAL] Failed to parse workspace.yaml: %v", err)
	}

	promptBytes, err := os.ReadFile(promptFile)
	if err != nil {
		log.Fatalf("[FATAL] Prompt template not found at %s: %v", promptFile, err)
	}
	promptTemplate := string(promptBytes)

	processedControls, err := loadIdempotencyState(requirementsFile)
	if err != nil {
		log.Fatalf("[FATAL] Failed to load/initialize idempotency state: %v", err)
	}

	entries, err := loadCatalogEntries(cliArgs.catalogPath, cliArgs.catalogURL, cliArgs.sourceFormat, cliArgs.framework, inRegistry, registryEntry)
	if err != nil {
		log.Fatalf("[FATAL] Failed to load catalog entries: %v", err)
	}

	entries = filterByGroups(entries, cliArgs.filterGroups)

	triageControls(entries, cliArgs.defaultProvider, workspace, promptTemplate, primaryConfig, fallbackConfig, maxRetries, processedControls)
}
