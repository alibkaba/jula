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
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	workspaceFile    = "../../workspace.yaml"
	requirementsFile = "../../requirements.csv"
	promptFile       = "../../engine/prompts/06_generate_policy.md"
	translatorsDir   = "../../engine/translators/"
	policiesDir      = "../../policies/rules/"
)

type ProviderConfig struct {
	DocRoot string `yaml:"doc_root"`
}

type Workspace struct {
	Organization    string                    `yaml:"organization"`
	ActiveProviders map[string]ProviderConfig `yaml:"active_providers"`
}

type ChatRequest struct {
	Model    string        `json:"model"`
	Messages []ChatMessage `json:"messages"`
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

	rawContent := strings.TrimSpace(chatResp.Choices[0].Message.Content)

	// Surgical regex extraction to bypass conversational hallucinations
	re := regexp.MustCompile("(?s)```(?:rego)?\n?(.*?)\n?```")
	matches := re.FindStringSubmatch(rawContent)
	if len(matches) > 1 {
		rawContent = strings.TrimSpace(matches[1])
	} else {
		// Fallback to naive stripping if no markdown blocks exist
		rawContent = strings.TrimPrefix(rawContent, "```rego")
		rawContent = strings.TrimPrefix(rawContent, "```")
		rawContent = strings.TrimSuffix(rawContent, "```")
		rawContent = strings.TrimSpace(rawContent)
	}

	return rawContent, resp.StatusCode, resp.Header, nil
}

func processWithRetriesAndFailover(primary, fallback AIConfig, maxRetries int, prompt string) (string, string, error) {
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
			rawContent, statusCode, headers, err := callAIEndpoint(tier.Conf, prompt)

			if err == nil {
				if headers != nil {
					remainingStr := headers.Get("X-RateLimit-Remaining")
					if remaining, parseErr := strconv.Atoi(remainingStr); parseErr == nil && remaining <= 0 {
						time.Sleep(10 * time.Second)
					}
				}
				return rawContent, tier.Name, nil
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

				if attempt < maxRetries {
					time.Sleep(sleepDuration)
					continue
				} else {
					break
				}
			}
			break
		}
	}

	return "", "", fmt.Errorf("all AI engine tiers failed")
}

func sanitizeFilename(controlID string) string {
	name := strings.ToLower(controlID)
	name = strings.ReplaceAll(name, "-", "_")
	name = strings.ReplaceAll(name, ".", "_")
	return name
}

func loadTranslators(provider string) string {
	var builder strings.Builder
	provider = strings.ToLower(provider)

	err := filepath.Walk(translatorsDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Skip errors
		}
		if !info.IsDir() && strings.HasSuffix(strings.ToLower(info.Name()), ".rego") {
			// Check if file path contains the provider name
			if strings.Contains(strings.ToLower(path), provider) {
				content, err := os.ReadFile(path)
				if err == nil {
					builder.WriteString(fmt.Sprintf("--- File: %s ---\n%s\n\n", info.Name(), string(content)))
				}
			}
		}
		return nil
	})

	if err != nil {
		return "No translators loaded."
	}

	res := builder.String()
	if res == "" {
		return "No translators loaded."
	}
	return res
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

	if primaryConfig.Endpoint == "" && fallbackConfig.Endpoint == "" {
		log.Fatal("[FATAL] Neither JULA_PRIMARY_ENDPOINT nor JULA_FALLBACK_ENDPOINT is configured.")
	}

	// 1. Parse Workspace
	_, err := parseWorkspace(workspaceFile)
	if err != nil {
		log.Fatalf("[FATAL] Failed to parse workspace.yaml: %v", err)
	}

	// 2. Load Prompt Template
	promptBytes, err := os.ReadFile(promptFile)
	if err != nil {
		log.Fatalf("[FATAL] Prompt template not found at %s: %v", promptFile, err)
	}
	promptTemplate := string(promptBytes)

	// Create output dir if it doesn't exist
	if err := os.MkdirAll(policiesDir, 0755); err != nil {
		log.Fatalf("[FATAL] Failed to create policies output directory: %v", err)
	}

	// 3. Process Requirements Ledger
	f, err := os.Open(requirementsFile)
	if err != nil {
		log.Fatalf("[FATAL] Input ledger not found at %s: %v", requirementsFile, err)
	}
	defer f.Close()

	reader := csv.NewReader(f)
	header, err := reader.Read()
	if err != nil {
		log.Fatalf("[FATAL] Failed to read ledger header: %v", err)
	}

	colMap := make(map[string]int)
	for i, col := range header {
		colMap[strings.ToLower(strings.TrimSpace(col))] = i
	}

	requiredCols := []string{"control_id", "requirement_id", "target_provider", "parameter_field", "operator", "expected_value", "status"}
	for _, req := range requiredCols {
		if _, ok := colMap[req]; !ok {
			log.Fatalf("[FATAL] ledger is missing required column: %s", req)
		}
	}

	approvedCount := 0

	for {
		row, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Printf("[WARNING] Error reading row: %v", err)
			continue
		}

		status := strings.ToUpper(strings.TrimSpace(row[colMap["status"]]))
		if status != "APPROVED" {
			continue // Skip PENDING and MANUAL_AUDIT
		}
		approvedCount++

		controlID := row[colMap["control_id"]]
		provider := row[colMap["target_provider"]]
		field := row[colMap["parameter_field"]]
		operator := row[colMap["operator"]]
		expected := row[colMap["expected_value"]]

		fmt.Printf("[GENERATE] Compiling policy for Control: %s... ", controlID)

		// Hydrate Context
		reqSummary := fmt.Sprintf("Provider: %s\nField: %s\nOperator: %s\nExpected Value: %s", provider, field, operator, expected)
		hydratedPrompt := strings.ReplaceAll(promptTemplate, "{{REQUIREMENT_DEFINITION}}", reqSummary)

		translators := loadTranslators(provider)
		hydratedPrompt = strings.ReplaceAll(hydratedPrompt, "{{AVAILABLE_TRANSLATOR_FIELDS}}", translators)

		fmt.Printf("Loaded %s translators... ", provider)

		// Invoke AI
		regoCode, tierUsed, err := processWithRetriesAndFailover(primaryConfig, fallbackConfig, maxRetries, hydratedPrompt)
		if err != nil {
			fmt.Printf("Code generation failed: %v\n", err)
			continue
		}

		fmt.Printf("Code generated via %s... ", tierUsed)

		// Save File
		filename := fmt.Sprintf("core_%s.rego", sanitizeFilename(controlID))
		filePath := filepath.Join(policiesDir, filename)

		if err := os.WriteFile(filePath, []byte(regoCode), 0644); err != nil {
			fmt.Printf("Failed to save %s: %v\n", filename, err)
		} else {
			fmt.Printf("Saved %s\n", filename)
		}
	}

	if approvedCount == 0 {
		fmt.Println("[GENERATE] No APPROVED rules found in the ledger. Exiting gracefully.")
	}
}
