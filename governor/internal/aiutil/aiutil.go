// Package aiutil provides shared AI infrastructure for Governor CLI tools.
// It consolidates the duplicated types, environment helpers, workspace parsing,
// OpenAI-compatible HTTP client, and retry/failover logic used by the import,
// translate, and build commands.
package aiutil

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// --- Types ---

// AIConfig holds the connection parameters for a single AI endpoint tier.
type AIConfig struct {
	Endpoint string
	Key      string
	Model    string
	Timeout  time.Duration
}

// ChatRequest is the OpenAI-compatible chat completion request body.
type ChatRequest struct {
	Model          string            `json:"model"`
	Messages       []ChatMessage     `json:"messages"`
	ResponseFormat map[string]string `json:"response_format,omitempty"`
}

// ChatMessage is a single message in the chat completion request.
type ChatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// ChatResponse is the OpenAI-compatible chat completion response body.
type ChatResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
}

// ProviderConfig holds provider-specific workspace configuration.
type ProviderConfig struct {
	DocRoot string `yaml:"doc_root"`
}

// Workspace represents the parsed workspace.yaml configuration.
type Workspace struct {
	Organization    string                    `yaml:"organization"`
	ActiveProviders map[string]ProviderConfig `yaml:"active_providers"`
}

// --- Environment Helpers ---

// GetEnvStr reads an environment variable and trims surrounding quotes.
func GetEnvStr(key string) string {
	return strings.Trim(os.Getenv(key), "\"")
}

// GetEnvInt reads an environment variable as an integer, returning defaultVal on failure.
func GetEnvInt(key string, defaultVal int) int {
	valStr := strings.TrimSpace(GetEnvStr(key))
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

// --- Config Loaders ---

// LoadPrimaryConfig builds an AIConfig from JULA_PRIMARY_* environment variables.
func LoadPrimaryConfig() AIConfig {
	return AIConfig{
		Endpoint: GetEnvStr("JULA_PRIMARY_ENDPOINT"),
		Key:      GetEnvStr("JULA_PRIMARY_KEY"),
		Model:    GetEnvStr("JULA_PRIMARY_MODEL"),
		Timeout:  time.Duration(GetEnvInt("JULA_PRIMARY_TIMEOUT_SEC", 15)) * time.Second,
	}
}

// LoadFallbackConfig builds an AIConfig from JULA_FALLBACK_* environment variables.
func LoadFallbackConfig() AIConfig {
	return AIConfig{
		Endpoint: GetEnvStr("JULA_FALLBACK_ENDPOINT"),
		Key:      GetEnvStr("JULA_FALLBACK_KEY"),
		Model:    GetEnvStr("JULA_FALLBACK_MODEL"),
		Timeout:  time.Duration(GetEnvInt("JULA_FALLBACK_TIMEOUT_SEC", 45)) * time.Second,
	}
}

// LoadMaxRetries reads JULA_MAX_RETRIES_PER_TIER from the environment, defaulting to 2.
func LoadMaxRetries() int {
	return GetEnvInt("JULA_MAX_RETRIES_PER_TIER", 2)
}

// RequireAIConfig exits fatally if neither primary nor fallback endpoint is configured.
func RequireAIConfig(primary, fallback AIConfig) {
	if primary.Endpoint == "" && fallback.Endpoint == "" {
		log.Fatal("[FATAL] Neither JULA_PRIMARY_ENDPOINT nor JULA_FALLBACK_ENDPOINT is configured.")
	}
}

// --- Workspace Parser ---

// ParseWorkspace reads and parses a workspace.yaml file using a line-scanner
// approach that does not require a YAML library dependency.
func ParseWorkspace(path string) (Workspace, error) {
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
			ws.Organization = strings.TrimSpace(strings.Trim(strings.TrimPrefix(trimmed, "organization:"), ` "\'`))
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

// --- AI HTTP Client ---

// CallAIEndpoint sends a chat completion request to an OpenAI-compatible endpoint.
// It returns the raw content string from the first choice, the HTTP status code,
// response headers, and any error. The caller is responsible for post-processing
// the raw content (e.g., JSON parsing, Rego extraction).
func CallAIEndpoint(config AIConfig, req ChatRequest) (string, int, http.Header, error) {
	payloadBytes, err := json.Marshal(req)
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

	httpReq, err := http.NewRequest("POST", parsedURL.String(), bytes.NewBuffer(payloadBytes)) //nolint:ssrf // URL from env config, validated above
	if err != nil {
		return "", 0, nil, fmt.Errorf("request creation failed: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	if config.Key != "" {
		httpReq.Header.Set("Authorization", "Bearer "+config.Key)
	}

	client := &http.Client{Timeout: config.Timeout}
	resp, err := client.Do(httpReq)

	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
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
	return rawContent, resp.StatusCode, resp.Header, nil
}

// --- Retry / Failover Engine ---

// ProcessWithRetriesAndFailover attempts an AI call against the primary config,
// falling back to the fallback config on transient failures. It returns the raw
// content, the tier name that succeeded ("Primary" or "Fallback"), and any error.
//
// The caller builds the ChatRequest (including ResponseFormat if needed) and
// handles post-processing of the raw response content.
func ProcessWithRetriesAndFailover(primary, fallback AIConfig, maxRetries int, req ChatRequest) (string, string, error) {
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
			rawContent, statusCode, headers, err := CallAIEndpoint(tier.Conf, req)

			if err == nil {
				// Proactive throttling based on rate limit headers.
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

	return "", "", fmt.Errorf("all AI engine tiers failed")
}
