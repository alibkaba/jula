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
	"strconv"
	"strings"
	"time"
)

const (
	workspaceFile    = "../../workspace.yaml"
	requirementsFile = "../../requirements.csv"
	promptFile       = "../../engine/prompts/setup_03_extract_requirements.md"

	// OSCAL Content Release — pinned version with integrity verification.
	// Source: https://github.com/usnistgov/oscal-content/releases/tag/v1.5.0
	// Commit: 78650f02ad9321bb7b817846f8fbd4f2bcd620de
	oscalReleaseURL = "https://github.com/usnistgov/oscal-content/releases/download/v1.5.0/oscal-content-1.5.0.tar.gz"
	oscalReleaseSHA = "724a4dd665e0901dc314e3ee48bfd62fb361291e360a3e7c45bc56781a030365"
	oscalVersion    = "1.5.0"
)

// frameworkFileMap maps user-facing framework names to the OSCAL JSON file path inside the tarball.
var frameworkFileMap = map[string]string{
	"fedramp-low":      "oscal-content-1.5.0/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_LOW-baseline-resolved-profile_catalog.json",
	"fedramp-moderate": "oscal-content-1.5.0/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_MODERATE-baseline-resolved-profile_catalog.json",
	"fedramp-high":     "oscal-content-1.5.0/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_HIGH-baseline-resolved-profile_catalog.json",
	"soc2":             "oscal-content-1.5.0/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_MODERATE-baseline-resolved-profile_catalog.json",
	"iso27001":         "oscal-content-1.5.0/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_MODERATE-baseline-resolved-profile_catalog.json",
	"hipaa":            "oscal-content-1.5.0/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_MODERATE-baseline-resolved-profile_catalog.json",
	"full":             "oscal-content-1.5.0/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json",
	"privacy":          "oscal-content-1.5.0/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_PRIVACY-baseline-resolved-profile_catalog.json",
}

// allowedOSCALVersions is the whitelist of known-good OSCAL specification versions.
var allowedOSCALVersions = map[string]bool{
	"1.1.2": true,
	"1.2.0": true,
	"1.2.2": true,
}

// controlIDPattern validates NIST 800-53 control IDs (e.g., ac-1, sc-28).
var controlIDPattern = regexp.MustCompile(`^[a-z]{2}-\d+$`)

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

// downloadOSCALRelease downloads the pinned OSCAL release tarball to a temp file.
func downloadOSCALRelease() string {
	fmt.Println("[OSCAL] Downloading NIST SP 800-53 catalog from pinned release...")
	fmt.Printf("         URL: %s\n", oscalReleaseURL)

	resp, err := http.Get(oscalReleaseURL) //nolint:gosec // URL is a hardcoded constant, not user input
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

// verifyIntegrity computes the SHA-256 hash of the file and compares it against the pinned hash.
func verifyIntegrity(path string) {
	fmt.Println("[OSCAL] Verifying SHA-256 integrity...")

	f, err := os.Open(path)
	if err != nil {
		log.Fatalf("[FATAL] Failed to open tarball for hashing: %v", err)
	}
	defer f.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, f); err != nil {
		log.Fatalf("[FATAL] Failed to compute SHA-256: %v", err)
	}

	computed := hex.EncodeToString(hasher.Sum(nil))
	if computed != oscalReleaseSHA {
		log.Fatalf("[FATAL] SHA-256 MISMATCH. Expected: %s Got: %s. The OSCAL tarball may have been tampered with.", oscalReleaseSHA, computed)
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
		}
	}

	if framework == "" {
		fmt.Println("[FATAL] --framework is required.")
		fmt.Println("  Options: fedramp-low, fedramp-moderate, fedramp-high, soc2, iso27001, hipaa, full, privacy")
		fmt.Println("  Example: ./import --framework fedramp-moderate --provider gcp")
		os.Exit(1)
	}
	if _, ok := frameworkFileMap[framework]; !ok {
		log.Fatalf("[FATAL] Unknown framework: %s. Valid options: fedramp-low, fedramp-moderate, fedramp-high, soc2, iso27001, hipaa, full, privacy", framework)
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

	// Download, verify, and parse OSCAL catalog.
	tarPath := downloadOSCALRelease()
	defer os.Remove(tarPath)
	verifyIntegrity(tarPath)
	jsonBytes := extractFromTarball(tarPath, frameworkFileMap[framework])
	entries := parseOSCALCatalog(jsonBytes)

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
