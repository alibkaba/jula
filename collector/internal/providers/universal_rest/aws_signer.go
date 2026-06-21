package universal_rest

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"
)

// SignAWSv4 strictly signs an HTTP request according to AWS Signature Version 4.
// It relies entirely on standard Go crypto and net/http packages.
// Credentials are resolved in order:
//  1. AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY environment variables
//  2. ECS container credentials endpoint (AWS_CONTAINER_CREDENTIALS_RELATIVE_URI)
func SignAWSv4(req *http.Request, payload []byte) error {
	accessKey := os.Getenv("AWS_ACCESS_KEY_ID")
	secretKey := os.Getenv("AWS_SECRET_ACCESS_KEY")
	region := os.Getenv("AWS_REGION")
	if region == "" {
		region = os.Getenv("AWS_DEFAULT_REGION")
	}
	sessionToken := os.Getenv("AWS_SESSION_TOKEN")

	// Fallback: ECS Fargate injects credentials via a container metadata endpoint.
	if accessKey == "" || secretKey == "" {
		ecsCreds, err := resolveECSCredentials()
		if err == nil {
			accessKey = ecsCreds.AccessKeyID
			secretKey = ecsCreds.SecretAccessKey
			sessionToken = ecsCreds.Token
		}
	}

	if accessKey == "" || secretKey == "" || region == "" {
		return fmt.Errorf("aws_sigv4 requires AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, and AWS_REGION")
	}

	// For standard hyperscaler queries, the service is often inferred or passed.
	// We'll extract service from the host (e.g. config.us-east-1.amazonaws.com -> config)
	service := extractAWSService(req.URL.Host)
	if service == "" {
		return fmt.Errorf("could not infer AWS service from host %s", req.URL.Host)
	}

	t := time.Now().UTC()
	amzDate := t.Format("20060102T150405Z")
	dateStamp := t.Format("20060102")

	// 1. Hash payload
	payloadHash := sha256.Sum256(payload)
	payloadHashHex := hex.EncodeToString(payloadHash[:])

	// 2. Set necessary headers before signing
	req.Header.Set("X-Amz-Date", amzDate)
	if sessionToken != "" {
		req.Header.Set("X-Amz-Security-Token", sessionToken)
	}
	req.Header.Set("Host", req.URL.Host)

	// 3. Create Canonical Request
	canonicalURI := req.URL.Path
	if canonicalURI == "" {
		canonicalURI = "/"
	}

	canonicalQueryString := encodeCanonicalQuery(req.URL.Query())

	// Sort headers
	var signedHeadersList []string
	canonicalHeaders := ""
	for k := range req.Header {
		lk := strings.ToLower(k)
		signedHeadersList = append(signedHeadersList, lk)
	}
	sort.Strings(signedHeadersList)

	for _, k := range signedHeadersList {
		v := req.Header.Get(k)
		canonicalHeaders += k + ":" + strings.TrimSpace(v) + "\n"
	}
	signedHeaders := strings.Join(signedHeadersList, ";")

	canonicalRequest := strings.Join([]string{
		req.Method,
		canonicalURI,
		canonicalQueryString,
		canonicalHeaders,
		signedHeaders,
		payloadHashHex,
	}, "\n")

	canonicalRequestHash := sha256.Sum256([]byte(canonicalRequest))

	// 4. Create String to Sign
	algorithm := "AWS4-HMAC-SHA256"
	credentialScope := fmt.Sprintf("%s/%s/%s/aws4_request", dateStamp, region, service)
	stringToSign := strings.Join([]string{
		algorithm,
		amzDate,
		credentialScope,
		hex.EncodeToString(canonicalRequestHash[:]),
	}, "\n")

	// 5. Calculate Signature
	signingKey := getSignatureKey(secretKey, dateStamp, region, service)
	signature := hmacSHA256(signingKey, []byte(stringToSign))
	signatureHex := hex.EncodeToString(signature)

	// 6. Build Authorization Header
	authHeader := fmt.Sprintf("%s Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		algorithm, accessKey, credentialScope, signedHeaders, signatureHex)

	req.Header.Set("Authorization", authHeader)
	return nil
}

func extractAWSService(host string) string {
	parts := strings.Split(host, ".")
	if len(parts) > 0 {
		return parts[0]
	}
	return ""
}

func encodeCanonicalQuery(v url.Values) string {
	var keys []string
	for k := range v {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var pairs []string
	for _, k := range keys {
		escapedKey := url.QueryEscape(k)
		sort.Strings(v[k])
		for _, val := range v[k] {
			escapedVal := url.QueryEscape(val)
			pairs = append(pairs, escapedKey+"="+escapedVal)
		}
	}
	return strings.Join(pairs, "&")
}

func hmacSHA256(key []byte, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

func getSignatureKey(secret, date, region, service string) []byte {
	kDate := hmacSHA256([]byte("AWS4"+secret), []byte(date))
	kRegion := hmacSHA256(kDate, []byte(region))
	kService := hmacSHA256(kRegion, []byte(service))
	kSigning := hmacSHA256(kService, []byte("aws4_request"))
	return kSigning
}

// ecsCredentials represents the JSON response from the ECS container
// credentials endpoint at 169.254.170.2.
type ecsCredentials struct {
	AccessKeyID     string `json:"AccessKeyId"`
	SecretAccessKey string `json:"SecretAccessKey"`
	Token           string `json:"Token"`
}

var ecsCredentialsEndpointPrefix = "http://169.254.170.2"

// resolveECSCredentials fetches temporary credentials from the ECS container
// metadata endpoint. ECS Fargate sets AWS_CONTAINER_CREDENTIALS_RELATIVE_URI
// to a path like /v2/credentials/<uuid>, which returns IAM role credentials.
func resolveECSCredentials() (*ecsCredentials, error) {
	relativeURI := os.Getenv("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI")
	if relativeURI == "" {
		return nil, fmt.Errorf("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI not set")
	}

	endpoint := ecsCredentialsEndpointPrefix + relativeURI
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(endpoint)
	if err != nil {
		return nil, fmt.Errorf("fetching ECS credentials: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ECS credentials endpoint returned %d", resp.StatusCode)
	}

	var creds ecsCredentials
	if err := json.NewDecoder(resp.Body).Decode(&creds); err != nil {
		return nil, fmt.Errorf("decoding ECS credentials: %w", err)
	}
	return &creds, nil
}
