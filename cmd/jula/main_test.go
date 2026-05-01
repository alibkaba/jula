package main

import "testing"

func TestInitLogger(t *testing.T) {
	// Test each log level to ensure initLogger does not panic.
	levels := []string{"debug", "warn", "error", "info", ""}
	for _, level := range levels {
		t.Run("level_"+level, func(t *testing.T) {
			t.Setenv("JULA_LOG_LEVEL", level)
			initLogger() // Should not panic.
		})
	}
}

func TestPrintUsage(t *testing.T) {
	// Verify printUsage does not panic.
	printUsage()
}
