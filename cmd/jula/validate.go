package main

import (
	"flag"
	"fmt"
	"os"
)

func handleValidate(args []string) error {
	validateCmd := flag.NewFlagSet("validate", flag.ContinueOnError)

	providerFlag := validateCmd.String("provider", os.Getenv("JULA_PROVIDER"), "Comma-separated provider(s) to validate")

	if err := validateCmd.Parse(args); err != nil {
		return fmt.Errorf("parsing validate flags: %w", err)
	}

	if *providerFlag == "" {
		return fmt.Errorf("provider is required: use -provider or set JULA_PROVIDER")
	}

	// Phase 3 will call provider.Validate() for each requested provider
	// to confirm credentials and connectivity without executing extraction.
	fmt.Fprintf(os.Stderr, "validate: provider=%s (not yet implemented)\n", *providerFlag)
	return nil
}
