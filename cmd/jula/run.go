package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"
)

func handleRun(args []string) error {
	runCmd := flag.NewFlagSet("run", flag.ContinueOnError)

	providerFlag := runCmd.String("provider", os.Getenv("JULA_PROVIDER"), "Comma-separated provider(s) to execute (aws, gcp, github)")
	frameworkFlag := runCmd.String("framework", os.Getenv("JULA_FRAMEWORK"), "Target compliance framework (soc2, iso27001)")
	targetFlag := runCmd.String("target", os.Getenv("JULA_OUTPUT_TARGET"), "Delivery target: local, s3, gcs")
	pathFlag := runCmd.String("path", os.Getenv("JULA_OUTPUT_PATH"), "Target path or bucket URI")
	concurrencyFlag := runCmd.Int("concurrency", 3, "Max concurrent provider goroutines")
	timeoutFlag := runCmd.String("timeout", "5m", "Per-provider timeout duration")

	if err := runCmd.Parse(args); err != nil {
		return fmt.Errorf("parsing run flags: %w", err)
	}

	// Validate provider.
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

	// Validate framework.
	if *frameworkFlag == "" {
		return fmt.Errorf("framework is required: use -framework or set JULA_FRAMEWORK")
	}
	if !isValidFramework(*frameworkFlag) {
		return fmt.Errorf("unknown framework: %q", *frameworkFlag)
	}

	// Validate target.
	if *targetFlag == "" {
		return fmt.Errorf("target is required: use -target or set JULA_OUTPUT_TARGET")
	}
	if !isValidTarget(*targetFlag) {
		return fmt.Errorf("unknown target: %q", *targetFlag)
	}

	// Validate path.
	if *pathFlag == "" {
		return fmt.Errorf("path is required: use -path or set JULA_OUTPUT_PATH")
	}

	slog.Info("run: full pipeline starting",
		"providers", providers,
		"framework", *frameworkFlag,
		"target", *targetFlag,
		"path", *pathFlag,
		"concurrency", *concurrencyFlag,
		"timeout", *timeoutFlag,
	)

	_ = concurrencyFlag
	_ = timeoutFlag

	// Phase 3-5 will wire this into the full engine pipeline:
	//   1. Extract (providers) -> []Finding
	//   2. Map (framework)     -> []Evidence
	//   3. Deliver (target)    -> Manifest
	fmt.Fprintf(os.Stderr, "run: pipeline not yet implemented\n")
	return nil
}
