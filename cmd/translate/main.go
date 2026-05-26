package main

import (
	"bytes"
	"encoding/json"
	"flag"
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
	promptFile     = "../../engine/prompts/02_build_translator.md"
	translatorsDir = "../../engine/translators/"
)

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
					if remainingStr != "" {
						fmt.Printf("         [TELEMETRY] API Quota: %s Requests Remaining\n", remainingStr)
						if remaining, parseErr := strconv.Atoi(remainingStr); parseErr == nil && remaining <= 0 {
							log.Printf("[THROTTLE] [%s] Rate limit empty. Proactively backing off...", tier.Name)
							time.Sleep(10 * time.Second)
						}
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
					log.Printf("[WARNING] [%s] Transient failure (Code %d). Sleeping %v: %v", tier.Name, statusCode, sleepDuration, err)
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

	return "", "", fmt.Errorf("all AI engine tiers failed")
}

func main() {
	providerFlag := flag.String("provider", "", "The cloud platform key (e.g., \"gcp\", \"aws\")")
	serviceFlag := flag.String("service", "", "The resource service namespace (e.g., \"storage\", \"kms\")")
	samplePathFlag := flag.String("sample-path", "", "The relative path to a raw JSON sample response file")

	flag.Parse()

	if *providerFlag == "" || *serviceFlag == "" || *samplePathFlag == "" {
		fmt.Fprintf(os.Stderr, "Usage: translate --provider <provider> --service <service> --sample-path <path>\n\n")
		fmt.Fprintf(os.Stderr, "All three flags are mandatory.\n")
		os.Exit(2)
	}

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

	fmt.Printf("[TRANSLATE] Loading raw response sample from %s...\n", *samplePathFlag)
	sampleBytes, err := os.ReadFile(*samplePathFlag)
	if err != nil {
		log.Fatalf("[FATAL] Failed to read sample file at %s: %v", *samplePathFlag, err)
	}

	fmt.Printf("[TRANSLATE] Hydrating 02_build_translator.md for %s %s...\n", *providerFlag, *serviceFlag)
	promptBytes, err := os.ReadFile(promptFile)
	if err != nil {
		log.Fatalf("[FATAL] Prompt template not found at %s: %v", promptFile, err)
	}

	providerLower := strings.ToLower(*providerFlag)
	serviceLower := strings.ToLower(*serviceFlag)

	hydratedPrompt := string(promptBytes)
	hydratedPrompt = strings.ReplaceAll(hydratedPrompt, "{{TARGET_PROVIDER}}", providerLower)
	hydratedPrompt = strings.ReplaceAll(hydratedPrompt, "{{TARGET_SERVICE}}", serviceLower)
	hydratedPrompt = strings.ReplaceAll(hydratedPrompt, "{{RAW_API_RESPONSE}}", string(sampleBytes))

	fmt.Println("[TRANSLATE] Directing AI generation run (Tier: Primary/Fallback)...")
	regoCode, tierUsed, err := processWithRetriesAndFailover(primaryConfig, fallbackConfig, maxRetries, hydratedPrompt)
	if err != nil {
		log.Fatalf("[FATAL] Translation generation failed: %v", err)
	}

	fmt.Printf("         [SUCCESS] Generated via %s\n", tierUsed)

	if err := os.MkdirAll(translatorsDir, 0755); err != nil {
		log.Fatalf("[FATAL] Failed to create translators directory: %v", err)
	}

	outputFilename := fmt.Sprintf("%s_%s.rego", providerLower, serviceLower)
	outputPath := filepath.Join(translatorsDir, outputFilename)

	if err := os.WriteFile(outputPath, []byte(regoCode), 0644); err != nil {
		log.Fatalf("[FATAL] Failed to save %s: %v", outputFilename, err)
	}

	fmt.Printf("[SUCCESS] Output saved to engine/translators/%s\n", outputFilename)
}
