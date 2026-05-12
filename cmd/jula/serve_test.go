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

func TestRunEndpointPOSTWithEnv_NoGCPCreds(t *testing.T) {
	// With the engine wired, POST /run with valid env vars but no GCP
	// credentials returns 500 (extraction fails at provider validation).
	// This confirms the serve endpoint correctly delegates to handleRun.
	t.Setenv("JULA_PROVIDER", "gcp")
	t.Setenv("JULA_FRAMEWORK", "soc2")
	t.Setenv("JULA_OUTPUT_TARGET", "local")
	t.Setenv("JULA_OUTPUT_PATH", "./test-output")
	t.Setenv("JULA_ENVIRONMENT_ID", "")

	mux := newServeMux()
	req := httptest.NewRequest(http.MethodPost, "/run", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 without GCP creds, got %d", rec.Code)
	}
}
