package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

func TestServeMux_Health(t *testing.T) {
	mux := newServeMux()
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rr := httptest.NewRecorder()

	mux.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

	expected := "{\"status\":\"ok\"}\n"
	if rr.Body.String() != expected {
		t.Errorf("handler returned unexpected body: got %v want %v",
			rr.Body.String(), expected)
	}
}

func TestServeMux_Run_MethodNotAllowed(t *testing.T) {
	mux := newServeMux()
	req := httptest.NewRequest(http.MethodGet, "/run", nil)
	rr := httptest.NewRecorder()

	mux.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusMethodNotAllowed {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusMethodNotAllowed)
	}
}

func TestHandleServe(t *testing.T) {
	os.Setenv("PORT", "0") // Port 0 binds to a random available port
	defer os.Unsetenv("PORT")

	errCh := make(chan error)
	go func() {
		errCh <- handleServe([]string{})
	}()
	
	time.Sleep(100 * time.Millisecond) // Give the server a moment to start
}
