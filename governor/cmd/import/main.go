package main

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

const (
	workspaceFile    = "../../workspace.yaml"
	requirementsFile = "../../requirements.csv"
	promptFile       = "../../engine/prompts/setup_03_extract_requirements.md"
	registryFile     = "../../framework_registry.yaml"
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

type ProviderConfig struct {
	DocRoot string `yaml:"doc_root"`
}

type Workspace struct {
	Organization    string                    `yaml:"organization"`
	ActiveProviders map[string]ProviderConfig `yaml:"active_providers"`
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

type ChatRequest struct {
	Model          string            `json:"model"`
	Messages       []ChatMessage     `json:"messages"`
	ResponseFormat map[string]string `json:"response_format,omitempty"`
}

type ChatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type ChatResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
}

type AIConfig struct {
	Endpoint string
	Key      string
	Model    string
	Timeout  time.Duration
}

func getEnvStr(key string) string {
	return strings.Trim(os.Getenv(key), "\"")
}

func getEnvInt(key string, defaultVal int) int {
	valStr := strings.TrimSpace(getEnvStr(key))
	if valStr == "" {
		return defaultVal
	}
	val, err := strconv.Atoi(valStr)
	if err != nil {
		log.Printf("[WARNING] Invalid integer for %s, using default %d", key, defaultVal)
		return defaultVal
	}
	return val
}

func parseWorkspace(path string) (Workspace, error) {
	ws := Workspace{
		ActiveProviders: make(map[string]ProviderConfig),
	}

	f, err := os.Open(path)
	if err != nil {
		return ws, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	inProviders := false
	var currentProvider string

	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		if strings.HasPrefix(trimmed, "organization:") {
			ws.Organization = strings.TrimSpace(strings.Trim(strings.TrimPrefix(trimmed, "organization:"), ` "'`))
		}

		if strings.HasPrefix(line, "active_providers:") {
			inProviders = true
			continue
		} else if inProviders && !strings.HasPrefix(line, " ") {
			inProviders = false
		}

		if inProviders {
			if strings.HasSuffix(trimmed, ":") && !strings.Contains(trimmed, "doc_root") {
				currentProvider = strings.TrimSuffix(trimmed, ":")
			} else if strings.HasPrefix(trimmed, "doc_root:") && currentProvider != "" {
				val := strings.TrimSpace(strings.TrimPrefix(trimmed, "doc_root:"))
				val = strings.Trim(val, `"'`)
				ws.ActiveProviders[currentProvider] = ProviderConfig{DocRoot: val}
			}
		}
	}
	return ws, scanner.Err()
}

func callAIEndpoint(config AIConfig, prompt string) (string, int, http.Header, error) {
	reqPayload := ChatRequest{
		Model: config.Model,
		Messages: []ChatMessage{
			{Role: "user", Content: prompt},
		},
		ResponseFormat: map[string]string{"type": "json_object"},
	}

	payloadBytes, err := json.Marshal(reqPayload)
	if err != nil {
		return "", 0, nil, fmt.Errorf("request marshaling failed: %w", err)
	}

	parsedURL, err := url.Parse(config.Endpoint)
	if err != nil {
		return "", 0, nil, fmt.Errorf("invalid endpoint URL: %w", err)
	}
	if parsedURL.Scheme != "https" && parsedURL.Scheme != "http" {
		return "", 0, nil, fmt.Errorf("endpoint URL must use http or https scheme")
	}

	req, err := http.NewRequest("POST", parsedURL.String(), bytes.NewBuffer(payloadBytes)) //nolint:ssrf // URL from env config, validated above
	if err != nil {
		return "", 0, nil, fmt.Errorf("request creation failed: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	if config.Key != "" {
		req.Header.Set("Authorization", "Bearer "+config.Key)
	}

	client := &http.Client{Timeout: config.Timeout}
	resp, err := client.Do(req)

	if err != nil {
		if err, ok := err.(net.Error); ok && err.Timeout() {
			return "", 408, nil, fmt.Errorf("network timeout")
		}
		return "", 0, nil, fmt.Errorf("http request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", resp.StatusCode, resp.Header, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", resp.StatusCode, resp.Header, fmt.Errorf("API error: %s", string(respBody))
	}

	var chatResp ChatResponse
	if err := json.Unmarshal(respBody, &chatResp); err != nil {
		return "", resp.StatusCode, resp.Header, fmt.Errorf("could not parse API response structure: %w", err)
	}

	if len(chatResp.Choices) == 0 {
		return "", resp.StatusCode, resp.Header, fmt.Errorf("empty response choices from LLM")
	}

	rawJSON := strings.TrimSpace(chatResp.Choices[0].Message.Content)
	if strings.HasPrefix(rawJSON, "```json") {
		rawJSON = strings.TrimPrefix(rawJSON, "```json")
		rawJSON = strings.TrimSuffix(rawJSON, "```")
		rawJSON = strings.TrimSpace(rawJSON)
	}

	return rawJSON, resp.StatusCode, resp.Header, nil
}

func processWithRetriesAndFailover(primary, fallback AIConfig, maxRetries int, prompt string) (RequirementExtraction, error) {
	configs := []struct {
		Name string
		Conf AIConfig
	}{
		{"Primary", primary},
		{"Fallback", fallback},
	}

	for _, tier := range configs {
		if tier.Conf.Endpoint == "" {
			continue
		}

		for attempt := 1; attempt <= maxRetries; attempt++ {
			rawJSONContent, statusCode, headers, err := callAIEndpoint(tier.Conf, prompt)

			if err == nil {
				// Proactive Throttling & Telemetry
				if headers != nil {
					remainingStr := headers.Get("X-RateLimit-Remaining")
					limitStr := headers.Get("X-RateLimit-Limit")
					resetStr := headers.Get("X-RateLimit-Reset")

					if remainingStr != "" {
						resetSuffix := ""
						if resetStr != "" {
							resetSuffix = fmt.Sprintf(" (Resets at %s)", resetStr)
						}

						if limitStr != "" {
							fmt.Printf("         [TELEMETRY] API Quota: %s/%s Requests Remaining%s\n", remainingStr, limitStr, resetSuffix)
						} else {
							fmt.Printf("         [TELEMETRY] API Quota: %s Requests Remaining%s\n", remainingStr, resetSuffix)
						}

						if remaining, parseErr := strconv.Atoi(remainingStr); parseErr == nil && remaining <= 0 {
							log.Printf("[THROTTLE] [%s] Rate limit empty (Remaining: %d). Proactively backing off to avoid 429...", tier.Name, remaining)
							time.Sleep(10 * time.Second)
						}
					}
				}

				var extraction RequirementExtraction
				if parseErr := json.Unmarshal([]byte(rawJSONContent), &extraction); parseErr != nil {
					return extraction, fmt.Errorf("[%s] Failed to parse extracted JSON object: %w. Raw text: %s", tier.Name, parseErr, rawJSONContent)
				}
				return extraction, nil
			}

			if statusCode == 400 || statusCode == 401 {
				log.Fatalf("[FATAL] [%s] Setup error %d. Aborting execution instantly: %v", tier.Name, statusCode, err)
			}

			if statusCode == 429 || statusCode == 503 || statusCode == 408 || statusCode == 0 {
				sleepDuration := 1 * time.Second
				if headers != nil {
					if retryAfter := headers.Get("Retry-After"); retryAfter != "" {
						if secs, convErr := strconv.Atoi(retryAfter); convErr == nil {
							sleepDuration = time.Duration(secs) * time.Second
						}
					}
				}

				log.Printf("[WARNING] [%s] Transient failure (Code %d) on attempt %d/%d. Sleeping %v: %v", tier.Name, statusCode, attempt, maxRetries, sleepDuration, err)
				if attempt < maxRetries {
					time.Sleep(sleepDuration)
					continue
				} else {
					log.Printf("[FAILOVER] %s exhausted retries. Dropping down to next tier...", tier.Name)
					break
				}
			}

			log.Printf("[ERROR] [%s] Unexpected failure (Code %d): %v", tier.Name, statusCode, err)
			break
		}
	}

	return RequirementExtraction{}, fmt.Errorf("all AI engine tiers failed")
}

func main() {
	primaryConfig := AIConfig{
		Endpoint: getEnvStr("JULA_PRIMARY_ENDPOINT"),
		Key:      getEnvStr("JULA_PRIMARY_KEY"),
		Model:    getEnvStr("JULA_PRIMARY_MODEL"),
		Timeout:  time.Duration(getEnvInt("JULA_PRIMARY_TIMEOUT_SEC", 15)) * time.Second,
	}

	fallbackConfig := AIConfig{
		Endpoint: getEnvStr("JULA_FALLBACK_ENDPOINT"),
		Key:      getEnvStr("JULA_FALLBACK_KEY"),
		Model:    getEnvStr("JULA_FALLBACK_MODEL"),
		Timeout:  time.Duration(getEnvInt("JULA_FALLBACK_TIMEOUT_SEC", 45)) * time.Second,
	}

	maxRetries := getEnvInt("JULA_MAX_RETRIES_PER_TIER", 2)

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
		os.Exit(1)
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

	if primaryConfig.Endpoint == "" && fallbackConfig.Endpoint == "" {
		log.Fatal("[FATAL] Neither JULA_PRIMARY_ENDPOINT nor JULA_FALLBACK_ENDPOINT is configured.")
	}

	// Read Workspace Configuration
	workspace, err := parseWorkspace(workspaceFile)
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
	processedControls := make(map[string]bool)
	if _, err := os.Stat(requirementsFile); err == nil {
		f, err := os.Open(requirementsFile)
		if err == nil {
			reader := csv.NewReader(f)
			records, err := reader.ReadAll()
			f.Close()
			if err == nil && len(records) > 0 {
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
							processedControls[row[idIdx]+"|"+prov] = true
						}
					}
				}
			}
		}
	} else {
		// Initialize the file with headers if it doesn't exist
		f, err := os.OpenFile(requirementsFile, os.O_CREATE|os.O_WRONLY, 0644)
		if err == nil {
			writer := csv.NewWriter(f)
			writer.Write([]string{"Control_ID", "Requirement_ID", "Target_Provider", "Parameter_Field", "Operator", "Expected_Value", "Confidence", "Status", "Documentation_URL"})
			writer.Flush()
			f.Close()
		}
	}

	// Load OSCAL catalog: either from a custom catalog file, a URL, or the default tarball.
	var entries []CatalogEntry
	switch {
	case catalogPath != "":
		// User-provided local catalog file.
		jsonBytes, err := os.ReadFile(catalogPath)
		if err != nil {
			log.Fatalf("[FATAL] Failed to read catalog file %s: %v", catalogPath, err)
		}

		// Auto-detect format if not explicitly set via --source.
		format := sourceFormat
		if format == "" {
			format = detectSourceFormat(catalogPath, jsonBytes)
		} else if format == "oscal" {
			format = "json" // Normalize legacy "oscal" to "json"
		}
		fmt.Printf("[CATALOG] Loading from local file: %s (format: %s)\n", catalogPath, format)

		// Verify integrity against registry hash if available.
		if inRegistry && registryEntry.CatalogSHA != "" {
			verifyIntegrity(catalogPath, registryEntry.CatalogSHA)
		}

		switch format {
		case "csv":
			entries = parseCSVCatalog(jsonBytes)
		default:
			entries = parseOSCALCatalog(jsonBytes)
		}

	case catalogURL != "":
		// User-provided URL to a catalog file.
		fmt.Printf("[CATALOG] Downloading catalog from URL: %s\n", catalogURL)
		resp, httpErr := http.Get(catalogURL) //nolint:gosec // URL is from user CLI input, validated by intent
		if httpErr != nil {
			log.Fatalf("[FATAL] Failed to download catalog from %s: %v", catalogURL, httpErr)
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			log.Fatalf("[FATAL] Catalog download returned HTTP %d", resp.StatusCode)
		}
		jsonBytes, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			log.Fatalf("[FATAL] Failed to read catalog response body: %v", readErr)
		}

		// Auto-detect format from URL path or content.
		format := sourceFormat
		if format == "" {
			format = detectSourceFormat(catalogURL, jsonBytes)
		} else if format == "oscal" {
			format = "json" // Normalize legacy "oscal" to "json"
		}
		fmt.Printf("         Detected format: %s\n", format)

		switch format {
		case "csv":
			entries = parseCSVCatalog(jsonBytes)
		default:
			entries = parseOSCALCatalog(jsonBytes)
		}

	default:
		// Default: download from registry-configured source.
		if !inRegistry || registryEntry.CatalogURL == "" {
			log.Fatalf("[FATAL] Framework '%s' has no catalog_url in registry and no --catalog was provided.", framework)
		}
		tarPath := downloadOSCALRelease(registryEntry.CatalogURL)
		defer os.Remove(tarPath)
		if registryEntry.CatalogSHA != "" {
			verifyIntegrity(tarPath, registryEntry.CatalogSHA)
		} else {
			fmt.Println("[WARNING] No SHA-256 hash in registry for this framework. Skipping integrity check.")
		}
		if registryEntry.TarballPath == "" {
			log.Fatalf("[FATAL] Framework '%s' has no tarball_path in registry.", framework)
		}
		jsonBytes := extractFromTarball(tarPath, registryEntry.TarballPath)
		entries = parseOSCALCatalog(jsonBytes)
	}

	// Apply --filter-group if specified.
	if filterGroups != "" {
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
		entries = filtered
	}

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

		hydratedPrompt := strings.ReplaceAll(promptTemplate, "{{CATALOG_PROSE_LINE}}", prose)
		hydratedPrompt = strings.ReplaceAll(hydratedPrompt, "{{DOC_ROOT}}", providerConf.DocRoot)

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
