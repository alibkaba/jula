package main

import (
	"fmt"
	"net/http"
	"os"
)

func main() {
	port := "8080"
	if p := os.Getenv("MOCK_PORT"); p != "" {
		port = p
	}

	http.HandleFunc("/mock-db", func(w http.ResponseWriter, r *http.Request) {
		// Validate bearer token to simulate real SaaS auth flow.
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprintln(w, `{"error": "unauthorized"}`)
			return
		}

		w.Header().Set("Content-Type", "application/json")

		// Return a static GCP CAI SQL Instance payload.
		// This returns an opaque, raw JSON structure intended exclusively for
		// dynamic downstream Rego normalization libraries.
		payload := `{
	"resource": {
		"data": {
			"settings": {
				"ipConfiguration": {
					"ipv4Enabled": true,
					"requireSsl": true
				}
			}
		}
	}
}`
		_, _ = w.Write([]byte(payload))
	})

	fmt.Printf("Mock SaaS Server listening on :%s...\n", port)
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		fmt.Printf("Server failed: %v\n", err)
		os.Exit(1)
	}
}
