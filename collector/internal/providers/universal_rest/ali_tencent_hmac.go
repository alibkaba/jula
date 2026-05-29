package universal_rest

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"
)

// SignAliTencentHMAC implements canonical string sorting and HMAC-SHA256 derivation
// for Alibaba Cloud RPC formatting and Tencent Cloud TC3-HMAC-SHA256 signatures.
func SignAliTencentHMAC(req *http.Request, payload []byte) error {
	secretID := os.Getenv("CLOUD_SECRET_ID")
	secretKey := os.Getenv("CLOUD_SECRET_KEY")

	if secretID == "" || secretKey == "" {
		return fmt.Errorf("ali_tencent_hmac requires CLOUD_SECRET_ID and CLOUD_SECRET_KEY")
	}

	service := extractTencentService(req.URL.Host)
	if service == "" {
		return fmt.Errorf("could not infer service from host %s", req.URL.Host)
	}

	t := time.Now().UTC()
	timestamp := t.Unix()
	dateStamp := t.Format("2006-01-02")

	// 1. Canonical Headers
	req.Header.Set("Host", req.URL.Host)
	if req.Header.Get("X-TC-Timestamp") == "" {
		req.Header.Set("X-TC-Timestamp", fmt.Sprintf("%d", timestamp))
	}

	contentType := req.Header.Get("Content-Type")
	if contentType == "" {
		contentType = "application/json; charset=utf-8"
		req.Header.Set("Content-Type", contentType)
	}

	signedHeadersList := []string{"content-type", "host"}
	var signedHeaders string
	canonicalHeaders := fmt.Sprintf("content-type:%s\nhost:%s\n", strings.ToLower(contentType), strings.ToLower(req.URL.Host))
	signedHeaders = strings.Join(signedHeadersList, ";")

	// 2. Canonical URI and Query
	canonicalURI := req.URL.Path
	if canonicalURI == "" {
		canonicalURI = "/"
	}

	canonicalQueryString := encodeAliTencentQuery(req.URL.Query())

	// 3. Hashed Payload
	hashedPayload := sha256.Sum256(payload)
	hashedPayloadHex := strings.ToLower(hex.EncodeToString(hashedPayload[:]))

	// 4. Canonical Request
	canonicalRequest := fmt.Sprintf("%s\n%s\n%s\n%s\n%s\n%s",
		req.Method,
		canonicalURI,
		canonicalQueryString,
		canonicalHeaders,
		signedHeaders,
		hashedPayloadHex,
	)

	hashedCanonicalRequest := sha256.Sum256([]byte(canonicalRequest))
	hashedCanonicalRequestHex := strings.ToLower(hex.EncodeToString(hashedCanonicalRequest[:]))

	// 5. String to Sign
	credentialScope := fmt.Sprintf("%s/%s/tc3_request", dateStamp, service)
	stringToSign := fmt.Sprintf("TC3-HMAC-SHA256\n%d\n%s\n%s",
		timestamp,
		credentialScope,
		hashedCanonicalRequestHex,
	)

	// 6. Signature
	secretDate := hmacSHA256([]byte("TC3"+secretKey), []byte(dateStamp))
	secretService := hmacSHA256(secretDate, []byte(service))
	secretSigning := hmacSHA256(secretService, []byte("tc3_request"))

	signature := hmacSHA256(secretSigning, []byte(stringToSign))
	signatureHex := strings.ToLower(hex.EncodeToString(signature))

	// 7. Authorization Header
	authHeader := fmt.Sprintf("TC3-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		secretID, credentialScope, signedHeaders, signatureHex)
	req.Header.Set("Authorization", authHeader)

	return nil
}

func encodeAliTencentQuery(v url.Values) string {
	var keys []string
	for k := range v {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var pairs []string
	for _, k := range keys {
		// Strictly escape in RFC3986 format
		escapedKey := strings.ReplaceAll(url.QueryEscape(k), "+", "%20")
		sort.Strings(v[k])
		for _, val := range v[k] {
			escapedVal := strings.ReplaceAll(url.QueryEscape(val), "+", "%20")
			pairs = append(pairs, escapedKey+"="+escapedVal)
		}
	}
	return strings.Join(pairs, "&")
}

func extractTencentService(host string) string {
	parts := strings.Split(host, ".")
	if len(parts) > 0 {
		return parts[0]
	}
	return ""
}
