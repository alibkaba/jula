package objstore

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// Credentials holds temporary AWS (or compatible) credentials.
type Credentials struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
	Expiration      time.Time
}

// IsExpired returns true if the credentials have expired or are within
// the given margin of expiry.
func (c *Credentials) IsExpired(margin time.Duration) bool {
	if c.Expiration.IsZero() {
		return false
	}
	return time.Now().Add(margin).After(c.Expiration)
}

// signV4 signs an http.Request using AWS Signature Version 4.
// This is a pure stdlib implementation with no external dependencies.
//
// The algorithm:
//  1. Create a canonical request string (method, URI, query, headers, signed headers, payload hash).
//  2. Create a string-to-sign (algorithm, timestamp, credential scope, canonical request hash).
//  3. Derive a signing key via HMAC chain: date → region → service → "aws4_request".
//  4. Compute the signature and set the Authorization header.
//
// References:
//   - https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv.html
//   - Compatible with Alibaba Cloud OSS and Tencent Cloud COS (same algorithm, different endpoints).
func signV4(req *http.Request, creds Credentials, region, service string, payloadHash string) {
	now := time.Now().UTC()
	datestamp := now.Format("20060102")
	amzDate := now.Format("20060102T150405Z")

	// Set required headers.
	req.Header.Set("x-amz-date", amzDate)
	req.Header.Set("x-amz-content-sha256", payloadHash)
	if creds.SessionToken != "" {
		req.Header.Set("x-amz-security-token", creds.SessionToken)
	}

	// Ensure Host header is set.
	if req.Header.Get("Host") == "" {
		req.Header.Set("Host", req.Host)
	}

	// Step 1: Canonical request.
	canonicalURI := canonicalizePath(req.URL.Path)
	canonicalQueryString := canonicalizeQuery(req.URL.Query())
	signedHeaders, canonicalHeaders := canonicalizeHeaders(req.Header)

	canonicalRequest := strings.Join([]string{
		req.Method,
		canonicalURI,
		canonicalQueryString,
		canonicalHeaders,
		signedHeaders,
		payloadHash,
	}, "\n")

	// Step 2: String to sign.
	credentialScope := fmt.Sprintf("%s/%s/%s/aws4_request", datestamp, region, service)
	canonicalRequestHash := hashSHA256([]byte(canonicalRequest))

	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		amzDate,
		credentialScope,
		canonicalRequestHash,
	}, "\n")

	// Step 3: Signing key (HMAC chain).
	signingKey := deriveSigningKey(creds.SecretAccessKey, datestamp, region, service)

	// Step 4: Signature.
	signature := hex.EncodeToString(hmacSHA256(signingKey, []byte(stringToSign)))

	// Set the Authorization header.
	authHeader := fmt.Sprintf(
		"AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		creds.AccessKeyID,
		credentialScope,
		signedHeaders,
		signature,
	)
	req.Header.Set("Authorization", authHeader)
}

// hashPayload computes the SHA256 hex digest of a payload.
// For empty or nil bodies, returns the hash of an empty string.
func hashPayload(body []byte) string {
	return hashSHA256(body)
}

// unsignedPayload returns the sentinel value for unsigned payloads,
// used for streaming uploads or when the payload hash is not required.
const unsignedPayload = "UNSIGNED-PAYLOAD"

// deriveSigningKey performs the HMAC chain to derive the signing key.
//
//	kDate    = HMAC("AWS4" + secret, datestamp)
//	kRegion  = HMAC(kDate, region)
//	kService = HMAC(kRegion, service)
//	kSigning = HMAC(kService, "aws4_request")
func deriveSigningKey(secret, datestamp, region, service string) []byte {
	kDate := hmacSHA256([]byte("AWS4"+secret), []byte(datestamp))
	kRegion := hmacSHA256(kDate, []byte(region))
	kService := hmacSHA256(kRegion, []byte(service))
	kSigning := hmacSHA256(kService, []byte("aws4_request"))
	return kSigning
}

// canonicalizePath returns the URI-encoded canonical path.
func canonicalizePath(path string) string {
	if path == "" {
		return "/"
	}

	// URI-encode each path segment, preserving forward slashes.
	segments := strings.Split(path, "/")
	for i, seg := range segments {
		segments[i] = url.PathEscape(seg)
	}
	return strings.Join(segments, "/")
}

// canonicalizeQuery returns the sorted, URI-encoded query string.
func canonicalizeQuery(values url.Values) string {
	if len(values) == 0 {
		return ""
	}

	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var pairs []string
	for _, k := range keys {
		for _, v := range values[k] {
			pairs = append(pairs, url.QueryEscape(k)+"="+url.QueryEscape(v))
		}
	}
	return strings.Join(pairs, "&")
}

// canonicalizeHeaders builds the canonical headers string and signed headers list.
// Only includes headers that start with "host" or "x-amz-" plus content-type if present.
func canonicalizeHeaders(headers http.Header) (signedHeaders, canonical string) {
	type headerEntry struct {
		key   string
		value string
	}

	var entries []headerEntry
	for k, vals := range headers {
		lower := strings.ToLower(k)
		if lower == "host" || strings.HasPrefix(lower, "x-amz-") || lower == "content-type" {
			// Combine multiple values and trim whitespace.
			combined := strings.Join(vals, ",")
			entries = append(entries, headerEntry{
				key:   lower,
				value: strings.TrimSpace(combined),
			})
		}
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].key < entries[j].key
	})

	var headerKeys []string
	var headerLines []string
	for _, e := range entries {
		headerKeys = append(headerKeys, e.key)
		headerLines = append(headerLines, e.key+":"+e.value)
	}

	signedHeaders = strings.Join(headerKeys, ";")
	canonical = strings.Join(headerLines, "\n") + "\n" // trailing newline required
	return signedHeaders, canonical
}

// hmacSHA256 computes HMAC-SHA256.
func hmacSHA256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

// hashSHA256 returns the hex-encoded SHA256 hash of data.
func hashSHA256(data []byte) string {
	h := sha256.New()
	if len(data) > 0 {
		h.Write(data)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// hashReader reads all bytes from r and returns the SHA256 hex digest.
// Returns the hash of an empty string if r is nil.
func hashReader(r io.Reader) (string, []byte, error) {
	if r == nil {
		return hashSHA256(nil), nil, nil
	}
	data, err := io.ReadAll(r)
	if err != nil {
		return "", nil, err
	}
	return hashSHA256(data), data, nil
}
