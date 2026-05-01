package main

import (
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"
)

// handleServe starts a lightweight HTTP server for Cloud Run.
// POST /run triggers the full evidence collection pipeline.
// GET  /health returns 200 OK for liveness probes.
func handleServe(args []string) error {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, `{"status":"ok"}`)
	})

	mux.HandleFunc("/run", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		slog.Info("serve: /run endpoint invoked, starting pipeline")
		start := time.Now()

		if err := handleRun([]string{}); err != nil {
			slog.Error("serve: pipeline failed", "error", err, "duration", time.Since(start))
			http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusInternalServerError)
			return
		}

		duration := time.Since(start)
		slog.Info("serve: pipeline completed", "duration", duration)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"completed","duration":"%s"}`, duration)
	})

	slog.Info("serve: starting HTTP server", "port", port)
	return http.ListenAndServe(":"+port, mux)
}
