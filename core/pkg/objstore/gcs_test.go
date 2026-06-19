package objstore

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"testing"
	"time"
)

type mockTransport struct {
	roundTripFunc func(req *http.Request) (*http.Response, error)
}

func (m *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return m.roundTripFunc(req)
}

func TestFetchGCSToken(t *testing.T) {
	tests := []struct {
		name         string
		roundTrip    func(req *http.Request) (*http.Response, error)
		wantToken    string
		wantDuration time.Duration
		wantErr      bool
	}{
		{
			name: "successful fetch",
			roundTrip: func(req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewBufferString(`{"access_token": "valid-token", "expires_in": 3600}`)),
				}, nil
			},
			wantToken:    "valid-token",
			wantDuration: 3600 * time.Second,
			wantErr:      false,
		},
		{
			name: "http error",
			roundTrip: func(req *http.Request) (*http.Response, error) {
				return nil, errors.New("network error")
			},
			wantToken:    "",
			wantDuration: 0,
			wantErr:      true,
		},
		{
			name: "non-200 status",
			roundTrip: func(req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusInternalServerError,
					Body:       io.NopCloser(bytes.NewBufferString(`internal server error`)),
				}, nil
			},
			wantToken:    "",
			wantDuration: 0,
			wantErr:      true,
		},
		{
			name: "invalid json",
			roundTrip: func(req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewBufferString(`{invalid json}`)),
				}, nil
			},
			wantToken:    "",
			wantDuration: 0,
			wantErr:      true,
		},
		{
			name: "default ttl",
			roundTrip: func(req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewBufferString(`{"access_token": "token-no-ttl"}`)),
				}, nil
			},
			wantToken:    "token-no-ttl",
			wantDuration: 1 * time.Hour,
			wantErr:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &http.Client{
				Transport: &mockTransport{roundTripFunc: tt.roundTrip},
			}
			token, duration, err := fetchGCSToken(client)
			if (err != nil) != tt.wantErr {
				t.Errorf("fetchGCSToken() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if token != tt.wantToken {
				t.Errorf("fetchGCSToken() token = %v, want %v", token, tt.wantToken)
			}
			if duration != tt.wantDuration {
				t.Errorf("fetchGCSToken() duration = %v, want %v", duration, tt.wantDuration)
			}
		})
	}
}
