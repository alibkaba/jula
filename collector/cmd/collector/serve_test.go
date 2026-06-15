package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

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

func TestRunEndpointPOSTWithEnv_NoConfigs(t *testing.T) {
	// With the engine wired, POST /run with valid env vars but no configs
	// returns 500 (extraction fails).
	// This confirms the serve endpoint correctly delegates to handleRun.
	t.Setenv("JULA_OUTPUT_PATH", t.TempDir())
	t.Setenv("JULA_SIGNING_KEY", "")

	mux := newServeMux()
	req := httptest.NewRequest(http.MethodPost, "/run", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 without configs, got %d", rec.Code)
	}
}
