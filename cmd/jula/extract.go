package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
)

func handleExtract(args []string) error {
	extractCmd := flag.NewFlagSet("extract", flag.ContinueOnError)

	providerFlag := extractCmd.String("provider", os.Getenv("JULA_PROVIDER"), "Comma-separated provider(s) to execute (aws, gcp, github)")
	concurrencyFlag := extractCmd.Int("concurrency", 3, "Max concurrent provider goroutines")
	timeoutFlag := extractCmd.String("timeout", "5m", "Per-provider timeout duration")
	outputDirFlag := extractCmd.String("output-dir", "", "Local directory for raw findings output")

	if err := extractCmd.Parse(args); err != nil {
		return fmt.Errorf("parsing extract flags: %w", err)
	}

	if *providerFlag == "" {
		return fmt.Errorf("provider is required: use -provider or set JULA_PROVIDER")
	}

	providers := strings.Split(*providerFlag, ",")
	for _, p := range providers {
		p = strings.TrimSpace(p)
		if !isValidProvider(p) {
			return fmt.Errorf("unknown provider: %q", p)
		}
	}

	// Resolve output directory from flag or env var.
	outputDir := *outputDirFlag
	if outputDir == "" {
		outputDir = os.Getenv("JULA_OUTPUT_DIR")
	}

	_ = concurrencyFlag
	_ = timeoutFlag
	_ = outputDir
	_ = providers

	// Phase 3 will wire this into the engine orchestrator.
	fmt.Fprintf(os.Stderr, "extract: providers=%v (not yet implemented)\n", providers)
	return nil
}

func isValidProvider(name string) bool {
	switch name {
	case "aws", "gcp", "github":
		return true
	default:
		return false
	}
}
