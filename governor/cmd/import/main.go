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

// printLicenseNotice prints a licensing notice if the framework entry has a license field.
// For restrictive licenses, it adds a responsibility warning.
func printLicenseNotice(entry FrameworkEntry) {
	if entry.License == "" {
		return
	}
	fmt.Println("")
	fmt.Println("[LICENSE] " + entry.License)
	// Only show the responsibility warning for restrictive licenses.
	lower := strings.ToLower(entry.License)
	if strings.Contains(lower, "commercial") || strings.Contains(lower, "require") || strings.Contains(lower, "restricted") {
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

// extractFromTarball streams through a tar.gz archive and extracts a single file by path.
func extractFromTarball(tarPath, entryPath string) []byte {
	fmt.Printf("[OSCAL] Extracting %s...\n", entryPath)

	f, err := os.Open(tarPath)
	if err != nil {
		log.Fatalf("[FATAL] Failed to open tarball: %v", err)
	}
	defer f.Close()

	gzr, err := gzip.NewReader(f)
	if err != nil {
		log.Fatalf("[FATAL] Failed to decompress tarball: %v", err)
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Fatalf("[FATAL] Error reading tarball: %v", err)
		}

		if header.Name == entryPath {
			// Reject individual files larger than 15MB.
			if header.Size > 15*1024*1024 {
				log.Fatalf("[FATAL] Catalog JSON exceeds 15MB size limit (%d bytes)", header.Size)
			}

			data, err := io.ReadAll(tr)
			if err != nil {
				log.Fatalf("[FATAL] Failed to read catalog JSON from tarball: %v", err)
			}

			fmt.Printf("         Extracted %d bytes\n", len(data))
			return data
		}
	}

	log.Fatalf("[FATAL] Entry not found in tarball: %s", entryPath)
	return nil
}

// collectProse recursively collects prose text from a control's parts tree.
// It concatenates statement and guidance prose, separated by spaces.
func collectProse(parts []OSCALPart) string {
	var segments []string
	for _, p := range parts {
		if p.Prose != "" && (p.Name == "statement" || p.Name == "item" || p.Name == "guidance") {
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

// parseOSCALCatalog deserializes OSCAL JSON and returns normalized CatalogEntry values.
func parseOSCALCatalog(data []byte) []CatalogEntry {
	var doc OSCALDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		log.Fatalf("[FATAL] Failed to parse OSCAL JSON: %v", err)
	}

	catalog := doc.Catalog

	// Schema validation.
	if catalog.UUID == "" {
		log.Fatal("[FATAL] OSCAL catalog missing UUID field.")
	}
	if !allowedOSCALVersions[catalog.Metadata.OSCALVersion] {
		log.Fatalf("[FATAL] Unrecognized OSCAL version: %s. Allowed: %v", catalog.Metadata.OSCALVersion, allowedOSCALVersions)
	}
	if len(catalog.Groups) == 0 {
		log.Fatal("[FATAL] OSCAL catalog has no control groups.")
	}

	fmt.Printf("[OSCAL] Catalog: %s\n", catalog.Metadata.Title)
	fmt.Printf("         OSCAL Version: %s\n", catalog.Metadata.OSCALVersion)
	fmt.Printf("         Groups: %d\n", len(catalog.Groups))

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

			// Recurse into control enhancements.
			if len(ctrl.Controls) > 0 {
				extractControls(ctrl.Controls)
			}
		}
	}

	for _, group := range catalog.Groups {
		extractControls(group.Controls)
	}

	// Bounds check.
	if len(entries) > 5000 {
		log.Fatalf("[FATAL] OSCAL catalog has %d controls, exceeding the 5,000 limit.", len(entries))
	}
	if len(entries) > 1500 {
		fmt.Printf("[WARNING] Large catalog: %d controls. This will generate many AI calls.\n", len(entries))
	}

	fmt.Printf("         Controls extracted: %d\n", len(entries))
	return entries
}

// parseCSVCatalog reads a CSV file with Control_ID and Description/Prose columns
// and returns normalized CatalogEntry values. This supports frameworks that ship
// as spreadsheets (e.g., SCF Excel exports converted to CSV).
//
// Expected CSV format (header row required, column order flexible):
//   Control_ID, Title, Description
//   GOV-01, "Security Program", "Mechanisms exist to facilitate..."
//
// The parser searches for columns named: Control_ID (or ID), Description (or Prose, Statement).
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

	// Find column indices by header name (case-insensitive).
	header := records[0]
	idIdx := -1
	proseIdx := -1

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
		log.Fatal("[FATAL] CSV catalog missing required column: Control_ID (or ID)")
	}
	if proseIdx == -1 {
		log.Fatal("[FATAL] CSV catalog missing required column: Description (or Prose, Statement)")
	}

	// Bounds check.
	if len(records)-1 > 5000 {
		log.Fatalf("[FATAL] CSV catalog has %d rows, exceeding the 5,000 limit.", len(records)-1)
	}

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

		// Truncate overly long prose.
		if len(prose) > 2000 {
			prose = prose[:2000]
		}

		entries = append(entries, CatalogEntry{
			ControlID: strings.ToUpper(controlID),
			Prose:     prose,
		})
	}

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

// loadIdempotencyState reads an existing requirements CSV file and returns
// a map of already processed Control_ID|Provider keys. If the file does not exist,
// it initializes it with headers.
func loadIdempotencyState(path string) (map[string]bool, error) {
	processed := make(map[string]bool)
	if _, err := os.Stat(path); err != nil {
		// Initialize the file with headers if it doesn't exist
		f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return nil, fmt.Errorf("failed to create idempotency file: %w", err)
		}
		writer := csv.NewWriter(f)
		err = writer.Write([]string{"Control_ID", "Requirement_ID", "Target_Provider", "Parameter_Field", "Operator", "Expected_Value", "Confidence", "Status", "Documentation_URL"})
		writer.Flush()
		f.Close()
		if err != nil {
			return nil, fmt.Errorf("failed to write headers: %w", err)
		}
		return processed, nil
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

	if len(records) > 0 {
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
	}
	return processed, nil
}

// loadCatalogEntries loads and parses a catalog from a local path, URL, or framework registry.
func loadCatalogEntries(catalogPath, catalogURL, sourceFormat, framework string, inRegistry bool, registryEntry FrameworkEntry) ([]CatalogEntry, error) {
	var entries []CatalogEntry
	switch {
	case catalogPath != "":
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
			entries = parseCSVCatalog(jsonBytes)
			writeCSVProvenance(catalogPath, jsonBytes, framework, len(entries))
		default:
			entries = parseOSCALCatalog(jsonBytes)
		}

	case catalogURL != "":
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
			entries = parseCSVCatalog(jsonBytes)
		default:
			entries = parseOSCALCatalog(jsonBytes)
		}

	default:
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
		entries = parseOSCALCatalog(jsonBytes)
	}

	return entries, nil
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

func main() {
	primaryConfig := aiutil.LoadPrimaryConfig()
	fallbackConfig := aiutil.LoadFallbackConfig()
	maxRetries := aiutil.LoadMaxRetries()

	// Parse CLI arguments
	defaultProvider := ""
	framework := ""
	catalogPath := ""
	catalogURL := ""
	sourceFormat := ""      // Auto-detect from file extension; "json" or "csv". Override with --source.
	filterGroups := ""      // Comma-separated group prefixes to filter controls
	resetMode := false
	for i := 1; i < len(os.Args); i++ {
		arg := os.Args[i]
		if arg == "--reset" {
			resetMode = true
		} else if arg == "--provider" && i+1 < len(os.Args) {
			i++
			defaultProvider = strings.ToLower(strings.TrimSpace(os.Args[i]))
		} else if strings.HasPrefix(arg, "--provider=") {
			defaultProvider = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(arg, "--provider=")))
		} else if arg == "--framework" && i+1 < len(os.Args) {
			i++
			framework = strings.ToLower(strings.TrimSpace(os.Args[i]))
		} else if strings.HasPrefix(arg, "--framework=") {
			framework = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(arg, "--framework=")))
		} else if arg == "--catalog" && i+1 < len(os.Args) {
			i++
			catalogPath = strings.TrimSpace(os.Args[i])
		} else if strings.HasPrefix(arg, "--catalog=") {
			catalogPath = strings.TrimSpace(strings.TrimPrefix(arg, "--catalog="))
		} else if arg == "--catalog-url" && i+1 < len(os.Args) {
			i++
			catalogURL = strings.TrimSpace(os.Args[i])
		} else if strings.HasPrefix(arg, "--catalog-url=") {
			catalogURL = strings.TrimSpace(strings.TrimPrefix(arg, "--catalog-url="))
		} else if arg == "--source" && i+1 < len(os.Args) {
			i++
			sourceFormat = strings.ToLower(strings.TrimSpace(os.Args[i]))
		} else if strings.HasPrefix(arg, "--source=") {
			sourceFormat = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(arg, "--source=")))
		} else if arg == "--filter-group" && i+1 < len(os.Args) {
			i++
			filterGroups = strings.TrimSpace(os.Args[i])
		} else if strings.HasPrefix(arg, "--filter-group=") {
			filterGroups = strings.TrimSpace(strings.TrimPrefix(arg, "--filter-group="))
		}
	}

	// Load Framework Registry
	registry, regErr := parseFrameworkRegistry(registryFile)
	if regErr != nil {
		log.Printf("[WARNING] Could not load framework registry: %v. Proceeding without registry.", regErr)
		registry = FrameworkRegistry{Frameworks: make(map[string]FrameworkEntry)}
	} else {
		fmt.Printf("[REGISTRY] Loaded %d frameworks from registry\n", len(registry.Frameworks))
	}

	if framework == "" {
		fmt.Println("[FATAL] --framework is required.")
		fmt.Printf("  Available frameworks: %s\n", strings.Join(availableFrameworks(registry), ", "))
		fmt.Println("  Or use --catalog <path> with any --framework name for custom OSCAL catalogs.")
		fmt.Println("  Example: ./import --framework fedramp-moderate --provider gcp")
		fmt.Println("  Example: ./import --framework scf-full --catalog ./catalogs/scf-oscal.json --provider gcp")
		exitFunc(1)
	}

	// Look up framework in registry.
	registryEntry, inRegistry := registry.Frameworks[framework]

	// Only enforce registry lookup when no custom catalog is provided.
	if catalogPath == "" && catalogURL == "" {
		if !inRegistry {
			log.Fatalf("[FATAL] Unknown framework: %s.\n  Available: %s\n  Or use --catalog <path> for custom OSCAL catalogs.", framework, strings.Join(availableFrameworks(registry), ", "))
		}
		if registryEntry.Source == "local" {
			log.Fatalf("[FATAL] Framework '%s' requires a local catalog file. Use --catalog <path>.\n  %s", framework, registryEntry.Description)
		}
	}

	// Print license notice if the framework has licensing terms.
	if inRegistry {
		printLicenseNotice(registryEntry)
	}

	if resetMode {
		fmt.Printf("[INIT] --reset flag detected. Wiping existing %s...\n", requirementsFile)
		os.Remove(requirementsFile)
	}
	if defaultProvider != "" {
		fmt.Printf("[INIT] Provider: %s | Framework: %s\n", defaultProvider, framework)
	} else {
		fmt.Printf("[INIT] Framework: %s\n", framework)
	}

	aiutil.RequireAIConfig(primaryConfig, fallbackConfig)

	// Read Workspace Configuration
	workspace, err := aiutil.ParseWorkspace(workspaceFile)
	if err != nil {
		log.Fatalf("[FATAL] Failed to parse workspace.yaml: %v", err)
	}

	// Load Prompt Template
	promptBytes, err := os.ReadFile(promptFile)
	if err != nil {
		log.Fatalf("[FATAL] Prompt template not found at %s: %v", promptFile, err)
	}
	promptTemplate := string(promptBytes)

	// Load Idempotency State (keyed by Control_ID|Provider for multi-provider support)
	processedControls, err := loadIdempotencyState(requirementsFile)
	if err != nil {
		log.Fatalf("[FATAL] Failed to load/initialize idempotency state: %v", err)
	}

	// Load OSCAL catalog: either from a custom catalog file, a URL, or the default tarball.
	entries, err := loadCatalogEntries(catalogPath, catalogURL, sourceFormat, framework, inRegistry, registryEntry)
	if err != nil {
		log.Fatalf("[FATAL] Failed to load catalog entries: %v", err)
	}

	// Apply --filter-group if specified.
	entries = filterByGroups(entries, filterGroups)

	// Process each control from the OSCAL catalog.
	for _, entry := range entries {
		controlID := entry.ControlID
		prose := entry.Prose

		// Provider Resolution for OSCAL controls:
		// NIST 800-53 controls are cloud-agnostic, so provider comes from --provider flag.
		resolvedProvider := defaultProvider
		resolutionMethod := "cli_default"

		if resolvedProvider == "" {
			fmt.Printf("[WARNING] No --provider specified for %s. Skipping.\n", controlID)
			continue
		}

		// Idempotency check: Control_ID|Provider composite key.
		idempotencyKey := controlID + "|" + resolvedProvider
		if processedControls[idempotencyKey] {
			fmt.Printf("[SKIP] Control %s for %s already triaged.\n", controlID, resolvedProvider)
			continue
		}

		providerConf, exists := workspace.ActiveProviders[resolvedProvider]
		if !exists {
			fmt.Printf("[IGNORE] Provider '%s' is not enabled in workspace.yaml. Skipping %s.\n", resolvedProvider, controlID)
			continue
		}

		fmt.Printf("[INGEST] Triaging Control %s (provider: %s, via: %s)...\n", controlID, resolvedProvider, resolutionMethod)

		hydratedPrompt := buildCatalogRequest(prose, providerConf.DocRoot, promptTemplate)

		extraction, err := processWithRetriesAndFailover(primaryConfig, fallbackConfig, maxRetries, hydratedPrompt)
		if err != nil {
			fmt.Printf("         [ERROR] Failed to extract requirements: %v\n", err)
			continue
		}

		// Override Gate
		if extraction.Status != "MANUAL_AUDIT" && extraction.ParameterField != "N/A" {
			// Force the provider to match workspace mapping to prevent LLM hallucination
			extraction.TargetProvider = resolvedProvider
		}

		status := "PENDING"
		if extraction.Status != "" {
			status = strings.ToUpper(extraction.Status)
		}
		if extraction.Confidence <= 0.01 || extraction.ParameterField == "N/A" || strings.ToUpper(extraction.Operator) == "N/A" {
			status = "MANUAL_AUDIT"
		}

		// Stateful Append
		outF, err := os.OpenFile(requirementsFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			fmt.Printf("         [ERROR] Could not open requirements.csv for appending: %v\n", err)
			continue
		}

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
		writer.Flush()
		outF.Close()

		if err != nil {
			fmt.Printf("         [ERROR] Could not write to requirements.csv: %v\n", err)
		} else {
			fmt.Printf("         [SUCCESS] Logged %s\n", extraction.RequirementID)
		}
	}
}
