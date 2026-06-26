package main

import (
	"encoding/csv"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"jula-governor/internal/aiutil"
)

var (
	workspaceFile    = "../../workspace.yaml"
	requirementsFile = "../../requirements.csv"
	promptFile       = "../../engine/prompts/setup_04_generate_policy.md"
	translatorsDir   = "../../engine/translators/"
	policiesDir      = "../../policies/rules/"
	exitFunc         = os.Exit
)

// extractRegoBlock extracts Rego code from a markdown-fenced response.
func extractRegoBlock(rawContent string) string {
	re := regexp.MustCompile("(?s)```(?:rego)?\n?(.*?)\n?```")
	matches := re.FindStringSubmatch(rawContent)
	if len(matches) > 1 {
		return strings.TrimSpace(matches[1])
	}
	rawContent = strings.TrimPrefix(rawContent, "```rego")
	rawContent = strings.TrimPrefix(rawContent, "```")
	rawContent = strings.TrimSuffix(rawContent, "```")
	return strings.TrimSpace(rawContent)
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
	if err := runBuild(); err != nil {
		log.Printf("[FATAL] %v", err)
		exitFunc(1)
		return
	}
}

// runBuild runs the generation of policies based on requirements.csv approvals and OPA translators.
func runBuild() error {
	primaryConfig := aiutil.LoadPrimaryConfig()
	fallbackConfig := aiutil.LoadFallbackConfig()
	maxRetries := aiutil.LoadMaxRetries()

	if primaryConfig.Endpoint == "" && fallbackConfig.Endpoint == "" {
		return fmt.Errorf("neither primary nor fallback AI endpoint is configured")
	}

	// 1. Parse Workspace
	_, err := aiutil.ParseWorkspace(workspaceFile)
	if err != nil {
		return fmt.Errorf("failed to parse workspace.yaml: %w", err)
	}

	// 2. Load Prompt Template
	promptBytes, err := os.ReadFile(promptFile)
	if err != nil {
		return fmt.Errorf("prompt template not found at %s: %w", promptFile, err)
	}
	promptTemplate := string(promptBytes)

	// Create output dir if it doesn't exist
	if err := os.MkdirAll(policiesDir, 0755); err != nil {
		return fmt.Errorf("failed to create policies output directory: %w", err)
	}

	// 3. Process Requirements Ledger
	f, err := os.Open(requirementsFile)
	if err != nil {
		return fmt.Errorf("input ledger not found at %s: %w", requirementsFile, err)
	}
	defer f.Close()

	reader := csv.NewReader(f)
	header, err := reader.Read()
	if err != nil {
		return fmt.Errorf("failed to read ledger header: %w", err)
	}

	colMap := make(map[string]int)
	for i, col := range header {
		colMap[strings.ToLower(strings.TrimSpace(col))] = i
	}

	requiredCols := []string{"control_id", "requirement_id", "target_provider", "parameter_field", "operator", "expected_value", "status"}
	for _, req := range requiredCols {
		if _, ok := colMap[req]; !ok {
			return fmt.Errorf("ledger is missing required column: %s", req)
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
		aiReq := aiutil.ChatRequest{
			Model: primaryConfig.Model,
			Messages: []aiutil.ChatMessage{
				{Role: "user", Content: hydratedPrompt},
			},
		}

		rawContent, tierUsed, err := aiutil.ProcessWithRetriesAndFailover(primaryConfig, fallbackConfig, maxRetries, aiReq)
		if err != nil {
			fmt.Printf("Code generation failed: %v\n", err)
			continue
		}

		regoCode := extractRegoBlock(rawContent)

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

	return nil
}
