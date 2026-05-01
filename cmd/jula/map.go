package main

import (
	"flag"
	"fmt"
	"os"
)

func handleMap(args []string) error {
	mapCmd := flag.NewFlagSet("map", flag.ContinueOnError)

	frameworkFlag := mapCmd.String("framework", os.Getenv("JULA_FRAMEWORK"), "Target compliance framework (soc2, iso27001)")
	inputDirFlag := mapCmd.String("input-dir", "", "Directory containing raw extracted findings")
	outputDirFlag := mapCmd.String("output-dir", "", "Directory for mapped evidence output")

	if err := mapCmd.Parse(args); err != nil {
		return fmt.Errorf("parsing map flags: %w", err)
	}

	if *frameworkFlag == "" {
		return fmt.Errorf("framework is required: use -framework or set JULA_FRAMEWORK")
	}

	if !isValidFramework(*frameworkFlag) {
		return fmt.Errorf("unknown framework: %q", *frameworkFlag)
	}

	_ = inputDirFlag
	_ = outputDirFlag

	// Phase 4 will wire this into the mapping engine.
	fmt.Fprintf(os.Stderr, "map: framework=%s (not yet implemented)\n", *frameworkFlag)
	return nil
}

func isValidFramework(name string) bool {
	switch name {
	case "soc2", "iso27001":
		return true
	default:
		return false
	}
}
