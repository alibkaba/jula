package main

import (
	"flag"
	"fmt"
	"os"
)

func handleDeliver(args []string) error {
	deliverCmd := flag.NewFlagSet("deliver", flag.ContinueOnError)

	targetFlag := deliverCmd.String("target", os.Getenv("JULA_OUTPUT_TARGET"), "Delivery target: local, s3, gcs")
	pathFlag := deliverCmd.String("path", os.Getenv("JULA_OUTPUT_PATH"), "Target path or bucket URI")
	inputDirFlag := deliverCmd.String("input-dir", "", "Directory containing mapped evidence to deliver")

	if err := deliverCmd.Parse(args); err != nil {
		return fmt.Errorf("parsing deliver flags: %w", err)
	}

	if *targetFlag == "" {
		return fmt.Errorf("target is required: use -target or set JULA_OUTPUT_TARGET")
	}

	if !isValidTarget(*targetFlag) {
		return fmt.Errorf("unknown target: %q (valid: local, s3, gcs)", *targetFlag)
	}

	if *pathFlag == "" {
		return fmt.Errorf("path is required: use -path or set JULA_OUTPUT_PATH")
	}

	_ = inputDirFlag

	// Phase 5 will wire this into the reporter.
	fmt.Fprintf(os.Stderr, "deliver: target=%s path=%s (not yet implemented)\n", *targetFlag, *pathFlag)
	return nil
}

func isValidTarget(name string) bool {
	switch name {
	case "local", "s3", "gcs":
		return true
	default:
		return false
	}
}
