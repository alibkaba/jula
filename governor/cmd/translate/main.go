package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"jula-governor/internal/aiutil"
)

const (
	buildPromptFile = "../../engine/prompts/setup_02_build_translator.md"
	healPromptFile  = "../../engine/prompts/remediate_01_heal_translator.md"
	translatorsDir  = "../../engine/translators/"
)

// extractRegoBlock extracts Rego code from a markdown-fenced response.
func extractRegoBlock(rawContent string) string {
	re := regexp.MustCompile("(?s)```(?:rego)?\n?(.*?)\n?```")
	matches := re.FindStringSubmatch(rawContent)
	if len(matches) > 1 {
		return strings.TrimSpace(matches[1])
	}
	// Fallback to naive stripping if no markdown blocks exist.
	rawContent = strings.TrimPrefix(rawContent, "```rego")
	rawContent = strings.TrimPrefix(rawContent, "```")
	rawContent = strings.TrimSuffix(rawContent, "```")
	return strings.TrimSpace(rawContent)
}

func main() {
	providerFlag := flag.String("provider", "", "The cloud platform key (e.g., \"gcp\", \"aws\")")
	serviceFlag := flag.String("service", "", "The resource service namespace (e.g., \"storage\", \"kms\")")
	samplePathFlag := flag.String("sample-path", "", "The relative path to a raw JSON sample response file")
	healFlag := flag.Bool("heal", false, "Use the heal prompt instead of the build prompt")

	flag.Parse()

	if *providerFlag == "" || *serviceFlag == "" || *samplePathFlag == "" {
		fmt.Fprintf(os.Stderr, "Usage: translate --provider <provider> --service <service> --sample-path <path>\n\n")
		fmt.Fprintf(os.Stderr, "All three flags are mandatory.\n")
		os.Exit(2)
	}

	primaryConfig := aiutil.LoadPrimaryConfig()
	fallbackConfig := aiutil.LoadFallbackConfig()
	maxRetries := aiutil.LoadMaxRetries()

	aiutil.RequireAIConfig(primaryConfig, fallbackConfig)

	fmt.Printf("[TRANSLATE] Loading raw response sample from %s...\n", *samplePathFlag)
	sampleBytes, err := os.ReadFile(*samplePathFlag)
	if err != nil {
		log.Fatalf("[FATAL] Failed to read sample file at %s: %v", *samplePathFlag, err)
	}

	targetPromptFile := buildPromptFile
	if *healFlag {
		targetPromptFile = healPromptFile
		fmt.Printf("[TRANSLATE] Hydrating remediate_01_heal_translator.md for %s %s...\n", *providerFlag, *serviceFlag)
	} else {
		fmt.Printf("[TRANSLATE] Hydrating setup_02_build_translator.md for %s %s...\n", *providerFlag, *serviceFlag)
	}

	promptBytes, err := os.ReadFile(targetPromptFile)
	if err != nil {
		log.Fatalf("[FATAL] Prompt template not found at %s: %v", targetPromptFile, err)
	}

	providerLower := strings.ToLower(*providerFlag)
	serviceLower := strings.ToLower(*serviceFlag)

	hydratedPrompt := string(promptBytes)
	hydratedPrompt = strings.ReplaceAll(hydratedPrompt, "{{TARGET_PROVIDER}}", providerLower)
	hydratedPrompt = strings.ReplaceAll(hydratedPrompt, "{{TARGET_SERVICE}}", serviceLower)
	hydratedPrompt = strings.ReplaceAll(hydratedPrompt, "{{RAW_API_RESPONSE}}", string(sampleBytes))

	fmt.Println("[TRANSLATE] Directing AI generation run (Tier: Primary/Fallback)...")

	req := aiutil.ChatRequest{
		Model: primaryConfig.Model,
		Messages: []aiutil.ChatMessage{
			{Role: "user", Content: hydratedPrompt},
		},
	}

	rawContent, tierUsed, err := aiutil.ProcessWithRetriesAndFailover(primaryConfig, fallbackConfig, maxRetries, req)
	if err != nil {
		log.Fatalf("[FATAL] Translation generation failed: %v", err)
	}

	regoCode := extractRegoBlock(rawContent)

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
