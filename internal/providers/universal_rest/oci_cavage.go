package universal_rest

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

// SignOCICavage implements asymmetric HTTP request header signing conforming exactly to the Oracle Cloud Infrastructure specification (based on the IETF draft-cavage-http-signatures standard).
func SignOCICavage(req *http.Request, payload []byte) error {
	keyID := os.Getenv("OCI_KEY_ID") // Format: ocid1.tenancy.oc1..xyz/ocid1.user.oc1..xyz/fingerprint
	privateKeyPEM := os.Getenv("OCI_PRIVATE_KEY")

	if keyID == "" || privateKeyPEM == "" {
		return fmt.Errorf("oci_cavage requires OCI_KEY_ID and OCI_PRIVATE_KEY")
	}

	// 1. Parse Private Key
	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		return fmt.Errorf("failed to parse PEM block from OCI_PRIVATE_KEY")
	}

	var privateKey *rsa.PrivateKey
	var err error

	if block.Type == "RSA PRIVATE KEY" {
		privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			// Fallback to PKCS8
			key, err8 := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err8 == nil {
				if rsaKey, ok := key.(*rsa.PrivateKey); ok {
					privateKey = rsaKey
				} else {
					return fmt.Errorf("parsed OCI_PRIVATE_KEY is not an RSA private key")
				}
			} else {
				return fmt.Errorf("parsing PKCS1/PKCS8 private key: %v / %v", err, err8)
			}
		}
	} else if block.Type == "PRIVATE KEY" {
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return fmt.Errorf("parsing PKCS8 private key: %w", err)
		}
		var ok bool
		privateKey, ok = key.(*rsa.PrivateKey)
		if !ok {
			return fmt.Errorf("OCI_PRIVATE_KEY is not an RSA key")
		}
	} else {
		return fmt.Errorf("unsupported OCI_PRIVATE_KEY PEM block type: %s", block.Type)
	}

	// 2. Format Request Target
	req.Header.Set("Host", req.URL.Host)
	requestTarget := req.URL.Path
	if requestTarget == "" {
		requestTarget = "/"
	}
	if req.URL.RawQuery != "" {
		requestTarget += "?" + req.URL.RawQuery
	}

	// 3. Determine Date Header
	dateHeader := "date"
	if req.Header.Get("Date") == "" && req.Header.Get("X-Date") == "" {
		req.Header.Set("Date", time.Now().UTC().Format(http.TimeFormat))
	} else if req.Header.Get("X-Date") != "" {
		dateHeader = "x-date"
	}

	headersToSign := []string{dateHeader, "(request-target)", "host"}

	// 4. Content Headers for POST/PUT
	if len(payload) > 0 || req.Method == http.MethodPost || req.Method == http.MethodPut {
		hash := sha256.Sum256(payload)
		hashBase64 := base64.StdEncoding.EncodeToString(hash[:])
		req.Header.Set("X-Content-Sha256", hashBase64)
		headersToSign = append(headersToSign, "x-content-sha256")
		
		req.Header.Set("Content-Length", fmt.Sprintf("%d", len(payload)))
		headersToSign = append(headersToSign, "content-length")
		
		if req.Header.Get("Content-Type") == "" {
			req.Header.Set("Content-Type", "application/json")
		}
		headersToSign = append(headersToSign, "content-type")
	}

	// 5. Build Canonical String
	var signingString bytes.Buffer
	for i, h := range headersToSign {
		hLower := strings.ToLower(h) // Strict guardrail: enforce lowercase keys
		var val string
		if hLower == "(request-target)" {
			val = fmt.Sprintf("%s %s", strings.ToLower(req.Method), requestTarget)
		} else {
			val = req.Header.Get(hLower)
		}
		signingString.WriteString(fmt.Sprintf("%s: %s", hLower, val))
		if i < len(headersToSign)-1 {
			signingString.WriteString("\n")
		}
	}

	// 6. Sign Canonical String
	hashed := sha256.Sum256(signingString.Bytes())
	signatureBytes, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed[:])
	if err != nil {
		return fmt.Errorf("signing oci cavage string: %w", err)
	}

	signatureBase64 := base64.StdEncoding.EncodeToString(signatureBytes)
	
	// 7. Inject Authorization Header
	authHeader := fmt.Sprintf(`Signature version="1",keyId="%s",algorithm="rsa-sha256",headers="%s",signature="%s"`,
		keyID, strings.Join(headersToSign, " "), signatureBase64)

	req.Header.Set("Authorization", authHeader)
	return nil
}
