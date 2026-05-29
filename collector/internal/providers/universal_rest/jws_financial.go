package universal_rest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
)

// SignJWSFinancial implements high-compliance financial data transport signatures.
// It creates a detached JWS signature of the HTTP payload and attaches it to X-JWS-Signature.
func SignJWSFinancial(req *http.Request, payload []byte) error {
	privateKeyPEM := os.Getenv("JWS_PRIVATE_KEY")
	keyID := os.Getenv("JWS_KEY_ID")

	if privateKeyPEM == "" {
		return fmt.Errorf("jws_financial requires JWS_PRIVATE_KEY")
	}

	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		return fmt.Errorf("failed to parse PEM block from JWS_PRIVATE_KEY")
	}

	var parsedKey any
	var err error

	if block.Type == "RSA PRIVATE KEY" {
		parsedKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			parsedKey, err = x509.ParsePKCS8PrivateKey(block.Bytes)
		}
	} else if block.Type == "EC PRIVATE KEY" {
		parsedKey, err = x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			parsedKey, err = x509.ParsePKCS8PrivateKey(block.Bytes)
		}
	} else if block.Type == "PRIVATE KEY" {
		parsedKey, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	} else {
		return fmt.Errorf("unsupported JWS_PRIVATE_KEY PEM block type: %s", block.Type)
	}

	if err != nil {
		return fmt.Errorf("failed to parse private key: %w", err)
	}

	// 1. Hash the payload
	hashed := sha256.Sum256(payload)
	var signature []byte

	var alg string
	switch key := parsedKey.(type) {
	case *rsa.PrivateKey:
		alg = "RS256"
		signature, err = rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hashed[:])
		if err != nil {
			return fmt.Errorf("rsa signing failed: %w", err)
		}
	case *ecdsa.PrivateKey:
		alg = "ES256"
		signature, err = ecdsa.SignASN1(rand.Reader, key, hashed[:])
		if err != nil {
			return fmt.Errorf("ecdsa signing failed: %w", err)
		}
	default:
		return fmt.Errorf("unsupported private key type for JWS signing")
	}

	// 2. Create the JWS Header
	var jwsHeader string
	if keyID != "" {
		jwsHeader = fmt.Sprintf(`{"alg":"%s","kid":"%s"}`, alg, keyID)
	} else {
		jwsHeader = fmt.Sprintf(`{"alg":"%s"}`, alg)
	}

	encodedHeader := base64.RawURLEncoding.EncodeToString([]byte(jwsHeader))
	encodedSignature := base64.RawURLEncoding.EncodeToString(signature)

	// 3. Assemble Detached JWS (header..signature)
	detachedJWS := fmt.Sprintf("%s..%s", encodedHeader, encodedSignature)
	req.Header.Set("X-JWS-Signature", detachedJWS)

	return nil
}
