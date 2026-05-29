package main

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/alibkaba/jula-collector/pkg/logging"
)

// version is set at build time via -ldflags.
var version = "dev"

func main() {
	initLogger()

	if len(os.Args) < 2 {
		printUsage()
		os.Exit(2)
	}

	switch os.Args[1] {
	case "run":
		if err := handleRun(os.Args[2:]); err != nil {
			slog.Error("run failed", "error", err)
			os.Exit(1)
		}
	case "serve":
		if err := handleServe(os.Args[2:]); err != nil {
			slog.Error("serve failed", "error", err)
			os.Exit(1)
		}
	case "version":
		fmt.Printf("collect %s\n", version)
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", os.Args[1])
		printUsage()
		os.Exit(2)
	}
}

func initLogger() {
	levelStr := os.Getenv("JULA_LOG_LEVEL")
	level := slog.LevelInfo

	switch levelStr {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}

	baseHandler := slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		Level: level,
	})
	capturingHandler := logging.NewCapturingHandler(baseHandler)
	logging.SetGlobalHandler(capturingHandler)
	slog.SetDefault(slog.New(capturingHandler))
}

func printUsage() {
	fmt.Fprintln(os.Stderr, `Usage: collect <command> [flags]

Commands:
  run         Full pipeline: extract -> hash -> deliver (single-pass, in-memory)
  serve       Start HTTP server for Cloud Run deployment
  version     Print binary version and build metadata`)
}
