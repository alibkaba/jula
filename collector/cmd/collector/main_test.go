package main

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestInitLogger(t *testing.T) {
	levels := []struct {
		name  string
		level string
	}{
		{"debug", "debug"},
		{"warn", "warn"},
		{"error", "error"},
		{"info", "info"},
		{"empty", ""},
	}
	for _, tt := range levels {
		t.Run("level_"+tt.name, func(t *testing.T) {
			t.Setenv("JULA_LOG_LEVEL", tt.level)
			initLogger()
		})
	}
}

func TestPrintUsage(t *testing.T) {
	printUsage()
}

func TestMainCrasher(t *testing.T) {
	if os.Getenv("BE_CRASHER") == "1" {
		// Mock os.Args for the internal run based on an env var to avoid parsing issues
		argsStr := os.Getenv("CRASHER_ARGS")
		if argsStr != "" {
			os.Args = strings.Split(argsStr, ",")
		} else {
			os.Args = []string{"collect"}
		}
		main()
		return
	}

	tests := []struct {
		name           string
		args           []string
		expectedStatus int
		expectedOutput string
	}{
		{"no args", []string{"collect"}, 2, "Usage: collect <command>"},
		{"unknown command", []string{"collect", "unknown_cmd"}, 2, "unknown command: unknown_cmd"},
		{"version command", []string{"collect", "version"}, 0, "collect dev"},
		{"run fail nonexistent config", []string{"collect", "run", "--config", "nonexistent"}, 1, "run failed"},
		{"serve fail invalid port", []string{"collect", "serve"}, 1, "serve failed"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=TestMainCrasher")
			cmd.Env = append(os.Environ(), "BE_CRASHER=1", "CRASHER_ARGS="+strings.Join(tt.args, ","))
			if tt.name == "serve fail invalid port" {
				cmd.Env = append(cmd.Env, "PORT=invalid-port")
			}

			out, err := cmd.CombinedOutput()

			// Check exit status
			if e, ok := err.(*exec.ExitError); ok {
				if e.ExitCode() != tt.expectedStatus {
					t.Errorf("expected exit status %d, got %d. Output: %s", tt.expectedStatus, e.ExitCode(), string(out))
				}
			} else if tt.expectedStatus != 0 {
				t.Errorf("expected process to fail with status %d, but it succeeded", tt.expectedStatus)
			}

			// Check output
			if tt.expectedOutput != "" && !strings.Contains(string(out), tt.expectedOutput) {
				t.Errorf("expected output to contain %q, got %q", tt.expectedOutput, string(out))
			}
		})
	}
}
