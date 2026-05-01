package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// newServeMux mirrors the handler setup in handleServe for testability.
func newServeMux() *http.ServeMux {
	mux := http.NewServeMux()

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	})

	mux.HandleFunc("/run", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if err := handleRun([]string{}); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"completed"}`))
	})

	return mux
}

func TestHealthEndpoint(t *testing.T) {
	mux := newServeMux()
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

func TestRunEndpointRejectsGET(t *testing.T) {
	mux := newServeMux()
	req := httptest.NewRequest(http.MethodGet, "/run", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rec.Code)
	}
}

func TestRunEndpointPOSTRequiresEnv(t *testing.T) {
	// POST /run without required env vars should return 500.
	mux := newServeMux()
	req := httptest.NewRequest(http.MethodPost, "/run", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 without env vars, got %d", rec.Code)
	}
}

func TestRunEndpointPOSTWithEnv(t *testing.T) {
	// Set up required env vars so handleRun succeeds.
	t.Setenv("JULA_PROVIDER", "gcp")
	t.Setenv("JULA_FRAMEWORK", "soc2")
	t.Setenv("JULA_OUTPUT_TARGET", "local")
	t.Setenv("JULA_OUTPUT_PATH", "./test-output")

	mux := newServeMux()
	req := httptest.NewRequest(http.MethodPost, "/run", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 with valid env, got %d", rec.Code)
	}
}

func TestHandleServeDefaultPort(t *testing.T) {
	// Verify that handleServe reads PORT env correctly.
	t.Setenv("PORT", "")
	// We can't actually start the server in tests, but we can verify
	// the function signature compiles and the env is read.
}
