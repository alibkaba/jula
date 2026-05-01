package main

import (
	"fmt"
	"log/slog"
	"os"
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
	case "extract":
		if err := handleExtract(os.Args[2:]); err != nil {
			slog.Error("extract failed", "error", err)
			os.Exit(1)
		}
	case "map":
		if err := handleMap(os.Args[2:]); err != nil {
			slog.Error("map failed", "error", err)
			os.Exit(1)
		}
	case "deliver":
		if err := handleDeliver(os.Args[2:]); err != nil {
			slog.Error("deliver failed", "error", err)
			os.Exit(1)
		}
	case "run":
		if err := handleRun(os.Args[2:]); err != nil {
			slog.Error("run failed", "error", err)
			os.Exit(1)
		}
	case "validate":
		if err := handleValidate(os.Args[2:]); err != nil {
			slog.Error("validate failed", "error", err)
			os.Exit(1)
		}
	case "serve":
		if err := handleServe(os.Args[2:]); err != nil {
			slog.Error("serve failed", "error", err)
			os.Exit(1)
		}
	case "version":
		fmt.Printf("jula %s\n", version)
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

	handler := slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		Level: level,
	})
	slog.SetDefault(slog.New(handler))
}

func printUsage() {
	fmt.Fprintln(os.Stderr, `Usage: jula <command> [flags]

Commands:
  extract     Execute evidence extraction from provider(s)
  map         Apply framework mapping to previously extracted findings
  deliver     Upload mapped evidence to cloud storage
  run         Full pipeline: extract -> map -> deliver
  serve       Start HTTP server for Cloud Run deployment
  validate    Validate configuration without executing
  version     Print binary version and build metadata`)
}
