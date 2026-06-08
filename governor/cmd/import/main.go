package main

import (
	"bufio"
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	workspaceFile    = "../../workspace.yaml"
	catalogFile      = "../../catalog.csv"
	requirementsFile = "../../requirements.csv"
	promptFile       = "../../engine/prompts/04_extract_requirements.md"
)

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

	req, err := http.NewRequest("POST", config.Endpoint, bytes.NewBuffer(payloadBytes))
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
		}
	}

	if resetMode {
		fmt.Printf("[INIT] --reset flag detected. Wiping existing %s...\n", requirementsFile)
		os.Remove(requirementsFile)
	}
	if defaultProvider != "" {
		fmt.Printf("[INIT] Default provider set to: %s\n", defaultProvider)
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

	// Load Idempotency State
	processedControls := make(map[string]bool)
	if _, err := os.Stat(requirementsFile); err == nil {
		f, err := os.Open(requirementsFile)
		if err == nil {
			reader := csv.NewReader(f)
			records, err := reader.ReadAll()
			f.Close()
			if err == nil && len(records) > 0 {
				header := records[0]
				idx := -1
				for i, col := range header {
					if strings.TrimSpace(col) == "Control_ID" {
						idx = i
						break
					}
				}
				if idx != -1 {
					for _, row := range records[1:] {
						if len(row) > idx {
							processedControls[row[idx]] = true
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

	// Process Catalog
	f, err := os.Open(catalogFile)
	if err != nil {
		log.Fatalf("[FATAL] Input catalog not found at %s: %v", catalogFile, err)
	}
	defer f.Close()

	reader := csv.NewReader(f)
	header, err := reader.Read()
	if err != nil && err != io.EOF {
		log.Fatalf("[FATAL] Failed to read catalog header: %v", err)
	}

	idIdx, proseIdx, providerIdx := -1, -1, -1
	for i, col := range header {
		colTrimmed := strings.ToLower(strings.TrimSpace(col))
		if strings.Contains(colTrimmed, "control_id") {
			idIdx = i
		}
		if strings.Contains(colTrimmed, "description") || strings.Contains(colTrimmed, "prose") || strings.Contains(colTrimmed, "statement") {
			proseIdx = i
		}
		if colTrimmed == "provider" || colTrimmed == "target_provider" {
			providerIdx = i
		}
	}

	if idIdx == -1 || proseIdx == -1 {
		log.Fatal("[FATAL] catalog.csv is missing required columns (Control_ID and a description column).")
	}
	if providerIdx != -1 {
		fmt.Printf("[INIT] Detected provider column at index %d (%s).\n", providerIdx, header[providerIdx])
	}

	for {
		row, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Printf("[WARNING] Error reading row: %v", err)
			continue
		}
		if len(row) <= idIdx || len(row) <= proseIdx {
			continue
		}

		controlID := row[idIdx]
		prose := row[proseIdx]

		if processedControls[controlID] {
			fmt.Printf("[SKIP] Control %s already triaged.\n", controlID)
			continue
		}

		// Cascading Provider Resolution:
		// 1. Explicit "Provider" column in the CSV row
		// 2. JULA hyphen-split pattern from Control_ID (e.g., CIS-GCP-EASY-1 -> gcp)
		// 3. Default --provider CLI flag
		resolvedProvider := ""
		resolutionMethod := ""

		// Strategy 1: CSV column
		if providerIdx != -1 && len(row) > providerIdx {
			cellVal := strings.ToLower(strings.TrimSpace(row[providerIdx]))
			if cellVal != "" {
				resolvedProvider = cellVal
				resolutionMethod = "csv_column"
			}
		}

		// Strategy 2: JULA hyphen-split from Control_ID
		if resolvedProvider == "" {
			idParts := strings.Split(controlID, "-")
			if len(idParts) >= 3 {
				candidate := strings.ToLower(strings.TrimSpace(idParts[1]))
				if _, knownProvider := workspace.ActiveProviders[candidate]; knownProvider {
					resolvedProvider = candidate
					resolutionMethod = "control_id_parse"
				}
			}
		}

		// Strategy 3: CLI default
		if resolvedProvider == "" && defaultProvider != "" {
			resolvedProvider = defaultProvider
			resolutionMethod = "cli_default"
		}

		// No provider resolved: skip with warning
		if resolvedProvider == "" {
			fmt.Printf("[WARNING] Cannot resolve provider for %s. Use a 'Provider' CSV column or --provider flag. Skipping.\n", controlID)
			continue
		}

		providerConf, exists := workspace.ActiveProviders[resolvedProvider]
		if !exists {
			fmt.Printf("[IGNORE] Provider '%s' (resolved via %s) is not enabled in workspace.yaml. Skipping row %s.\n", resolvedProvider, resolutionMethod, controlID)
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
