package gcp

import (

	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNewTokenSource_ValidKey(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}

	pemData := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})

	saKey := &serviceAccountKey{
		PrivateKey:  string(pemData),
		ClientEmail: "test@example.com",
	}

	ts, err := newTokenSource(saKey, &http.Client{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ts == nil {
		t.Fatal("expected non-nil token source")
	}
}

func TestNewTokenSource_FromJSONKey(t *testing.T) {
	// Generate a valid RSA key
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	pemData := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})

	// Create JSON representation of the key
	jsonKeyData := map[string]string{
		"type":           "service_account",
		"project_id":     "test-project",
		"private_key_id": "1234567890",
		"private_key":    string(pemData),
		"client_email":   "test@test-project.iam.gserviceaccount.com",
		"client_id":      "1111111111",
		"token_uri":      "https://oauth2.googleapis.com/token",
	}

	jsonData, err := json.Marshal(jsonKeyData)
	if err != nil {
		t.Fatalf("failed to marshal json key: %v", err)
	}

	var saKey serviceAccountKey
	if err := json.Unmarshal(jsonData, &saKey); err != nil {
		t.Fatalf("failed to unmarshal json key: %v", err)
	}

	httpClient := &http.Client{}

	ts, err := newTokenSource(&saKey, httpClient)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ts == nil {
		t.Fatal("expected non-nil token source")
	}

	if ts.key.ClientEmail != "test@test-project.iam.gserviceaccount.com" {
		t.Errorf("expected client email test@test-project.iam.gserviceaccount.com, got %s", ts.key.ClientEmail)
	}
	if ts.tokenURL != "https://oauth2.googleapis.com/token" {
		t.Errorf("expected token URL https://oauth2.googleapis.com/token, got %s", ts.tokenURL)
	}
	if ts.httpClient != httpClient {
		t.Errorf("expected HTTP client to be set")
	}
	if len(ts.scopes) != 1 || ts.scopes[0] != "https://www.googleapis.com/auth/cloud-platform.read-only" {
		t.Errorf("expected read-only cloud platform scope, got %v", ts.scopes)
	}
	if ts.privateKey == nil {
		t.Errorf("expected private key to be parsed")
	}
}

func TestNewTokenSource_InvalidPEM(t *testing.T) {
	saKey := &serviceAccountKey{
		PrivateKey: "not-a-pem-block",
	}

	_, err := newTokenSource(saKey, &http.Client{})
	if err == nil {
		t.Fatal("expected error for invalid PEM")
	}
}

func TestNewTokenSource_InvalidPKCS8(t *testing.T) {
	pemData := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("invalid pkcs8 data")})

	saKey := &serviceAccountKey{
		PrivateKey: string(pemData),
	}

	_, err := newTokenSource(saKey, &http.Client{})
	if err == nil {
		t.Fatal("expected error for invalid PKCS8 private key")
	}
}

func TestNewTokenSource_NonRSAKey(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}

	pemData := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})

	saKey := &serviceAccountKey{
		PrivateKey: string(pemData),
	}

	_, err = newTokenSource(saKey, &http.Client{})
	if err == nil {
		t.Fatal("expected error for non-RSA private key")
	}
}

func TestNewTokenSource_CustomTokenURI(t *testing.T) {
	saKey := &serviceAccountKey{
		TokenURI: "https://custom.oauth.endpoint/token",
	}
	// Provide valid RSA key to reach the TokenURI check
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	pemData := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})
	saKey.PrivateKey = string(pemData)

	ts, err := newTokenSource(saKey, &http.Client{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ts.tokenURL != "https://custom.oauth.endpoint/token" {
		t.Errorf("expected custom token URL, got %s", ts.tokenURL)
	}
}

func TestTokenSource_CachedToken(t *testing.T) {
	ts := &tokenSource{
		cachedToken: "cached-token-value",
		tokenExpiry: time.Now().Add(1 * time.Hour),
	}

	token, err := ts.Token()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token != "cached-token-value" {
		t.Errorf("expected cached-token-value, got %s", token)
	}
}

func TestTokenSource_Refresh(t *testing.T) {
	// Set up a mock token endpoint.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(tokenResponse{
			AccessToken: "fresh-token",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		})
	}))
	defer server.Close()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	ts := &tokenSource{
		key: &serviceAccountKey{
			ClientEmail: "test@example.com",
		},
		privateKey:  key,
		scopes:      []string{"https://www.googleapis.com/auth/cloud-platform.read-only"},
		httpClient:  server.Client(),
		tokenURL:    server.URL,
		cachedToken: "",
		tokenExpiry: time.Time{}, // Expired.
	}

	token, err := ts.Token()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token != "fresh-token" {
		t.Errorf("expected fresh-token, got %s", token)
	}
	if ts.cachedToken != "fresh-token" {
		t.Errorf("token was not cached")
	}
}

func TestMetadataTokenSource_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Metadata-Flavor") != "Google" {
			t.Errorf("missing Metadata-Flavor header")
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(tokenResponse{
			AccessToken: "metadata-token",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		})
	}))
	defer server.Close()

	mts := &metadataTokenSource{httpClient: server.Client()}
	// Override the metadata URL to point to our test server.
	origURL := metadataURL
	defer func() { _ = origURL }() // keep reference

	// Use the test server's transport to redirect requests.
	mts.httpClient.Transport = &testTransport{serverURL: server.URL}

	token, err := mts.Token()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token != "metadata-token" {
		t.Errorf("expected metadata-token, got %s", token)
	}
}

func TestMetadataTokenSource_CachedToken(t *testing.T) {
	mts := &metadataTokenSource{
		cachedToken: "cached-metadata-token",
		tokenExpiry: time.Now().Add(1 * time.Hour),
	}

	token, err := mts.Token()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token != "cached-metadata-token" {
		t.Errorf("expected cached-metadata-token, got %s", token)
	}
}

func TestMetadataTokenSource_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte("service unavailable"))
	}))
	defer server.Close()

	mts := &metadataTokenSource{httpClient: server.Client()}
	mts.httpClient.Transport = &testTransport{serverURL: server.URL}

	_, err := mts.Token()
	if err == nil {
		t.Fatal("expected error for 503 response")
	}
}

func TestNewMetadataTokenSource_SetsMetadataField(t *testing.T) {
	ts := newMetadataTokenSource(&http.Client{})
	if ts.metadataSource == nil {
		t.Fatal("expected metadataSource to be set")
	}
}

func TestTokenSource_DelegatesToMetadata(t *testing.T) {
	mts := &metadataTokenSource{
		cachedToken: "delegated-token",
		tokenExpiry: time.Now().Add(1 * time.Hour),
	}
	ts := &tokenSource{metadataSource: mts}

	token, err := ts.Token()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token != "delegated-token" {
		t.Errorf("expected delegated-token, got %s", token)
	}
}


func TestNewTokenSource_StaticJSONKey(t *testing.T) {
	// A hardcoded, static sample JSON key for testing
	// We still need a valid RSA key so the PEM/PKCS8 parsing succeeds.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	pemData := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}))

	// Create JSON representation using map to ensure correct escaping
	jsonKeyData := map[string]string{
		"type":           "service_account",
		"project_id":     "test-project-static",
		"private_key_id": "static-12345",
		"private_key":    pemData,
		"client_email":   "static@test-project.iam.gserviceaccount.com",
		"client_id":      "99999",
		"token_uri":      "https://oauth2.googleapis.com/token",
	}

	jsonData, err := json.Marshal(jsonKeyData)
	if err != nil {
		t.Fatalf("failed to marshal static json key: %v", err)
	}

	// Convert it back to a string to simulate a read file
	staticJSONKeyStr := string(jsonData)

	var saKey serviceAccountKey
	if err := json.Unmarshal([]byte(staticJSONKeyStr), &saKey); err != nil {
		t.Fatalf("failed to unmarshal static json key: %v", err)
	}

	httpClient := &http.Client{}
	ts, err := newTokenSource(&saKey, httpClient)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if ts.key.ProjectID != "test-project-static" {
		t.Errorf("expected test-project-static, got %s", ts.key.ProjectID)
	}
	if ts.key.ClientEmail != "static@test-project.iam.gserviceaccount.com" {
		t.Errorf("expected static@test-project.iam.gserviceaccount.com, got %s", ts.key.ClientEmail)
	}
}

func TestTokenSource_Refresh_HTTPRequestError(t *testing.T) {
	// Use an invalid URL to force an HTTP request failure.
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	ts := &tokenSource{
		key: &serviceAccountKey{
			ClientEmail: "test@example.com",
		},
		privateKey: key,
		scopes:     []string{"scope"},
		httpClient: &http.Client{}, // No transport mapping; URL is invalid.
		tokenURL:   "http://\x00invalid-url",
	}

	_, err := ts.refresh()
	if err == nil {
		t.Fatal("expected error due to invalid token URL")
	}
}

func TestTokenSource_Refresh_Non200Response(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("unauthorized"))
	}))
	defer server.Close()

	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	ts := &tokenSource{
		key: &serviceAccountKey{
			ClientEmail: "test@example.com",
		},
		privateKey: key,
		scopes:     []string{"scope"},
		httpClient: server.Client(),
		tokenURL:   server.URL,
	}

	_, err := ts.refresh()
	if err == nil {
		t.Fatal("expected error for non-200 response")
	}
}

func TestTokenSource_Refresh_JSONUnmarshalError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("invalid json"))
	}))
	defer server.Close()

	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	ts := &tokenSource{
		key: &serviceAccountKey{
			ClientEmail: "test@example.com",
		},
		privateKey: key,
		scopes:     []string{"scope"},
		httpClient: server.Client(),
		tokenURL:   server.URL,
	}

	_, err := ts.refresh()
	if err == nil {
		t.Fatal("expected error for invalid JSON response")
	}
}

func TestMetadataTokenSource_HTTPRequestError(t *testing.T) {
	mts := &metadataTokenSource{httpClient: &http.Client{}}

	// Create a transport that fails all requests
	mts.httpClient.Transport = &testTransport{serverURL: "http://\x00invalid-url"}

	_, err := mts.Token()
	if err == nil {
		t.Fatal("expected error for HTTP request failure")
	}
}

func TestMetadataTokenSource_JSONUnmarshalError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("invalid json"))
	}))
	defer server.Close()

	mts := &metadataTokenSource{httpClient: server.Client()}
	mts.httpClient.Transport = &testTransport{serverURL: server.URL}

	_, err := mts.Token()
	if err == nil {
		t.Fatal("expected error for invalid JSON response")
	}
}

// This tests the failure inside io.ReadAll due to a broken HTTP response body

func TestTokenSource_Refresh_ReadBodyError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Set content length but don't send the body, to cause a read error
		w.Header().Set("Content-Length", "100")
		w.WriteHeader(http.StatusOK)
		// No body written
	}))
	defer server.Close()

	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	ts := &tokenSource{
		key: &serviceAccountKey{ClientEmail: "test@example.com"},
		privateKey: key,
		scopes:     []string{"scope"},
		httpClient: server.Client(),
		tokenURL:   server.URL,
	}

	_, err := ts.refresh()
	if err == nil {
		t.Fatal("expected error due to incomplete response body")
	}
}

func TestMetadataTokenSource_ReadBodyError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "100")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	mts := &metadataTokenSource{httpClient: server.Client()}
	mts.httpClient.Transport = &testTransport{serverURL: server.URL}

	_, err := mts.Token()
	if err == nil {
		t.Fatal("expected error due to incomplete response body")
	}
}
