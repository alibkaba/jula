package objstore

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"time"
)

// credentialProvider resolves and caches cloud credentials.
type credentialProvider interface {
	// Resolve returns valid credentials, refreshing if necessary.
	Resolve() (Credentials, error)
}

// ecsCredentialProvider fetches AWS credentials from the ECS task role endpoint.
// On Fargate, the container runtime injects AWS_CONTAINER_CREDENTIALS_RELATIVE_URI,
// which points to a local HTTP endpoint that returns temporary credentials.
//
// Falls back to AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY for local development.
type ecsCredentialProvider struct {
	httpClient *http.Client
	mu         sync.Mutex
	cached     Credentials
}

// ecsCredentialResponse is the JSON response from the ECS credential endpoint.
type ecsCredentialResponse struct {
	AccessKeyID     string `json:"AccessKeyId"`
	SecretAccessKey string `json:"SecretAccessKey"`
	Token           string `json:"Token"`
	Expiration      string `json:"Expiration"`
}

// newECSCredentialProvider creates a credential provider for AWS environments.
func newECSCredentialProvider(httpClient *http.Client) *ecsCredentialProvider {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 5 * time.Second}
	}
	return &ecsCredentialProvider{httpClient: httpClient}
}

// Resolve returns valid credentials, refreshing from the metadata endpoint if expired.
func (p *ecsCredentialProvider) Resolve() (Credentials, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Return cached credentials if still valid (with 5 minute buffer).
	if p.cached.AccessKeyID != "" && !p.cached.IsExpired(5*time.Minute) {
		return p.cached, nil
	}

	creds, err := p.fetch()
	if err != nil {
		return Credentials{}, err
	}
	p.cached = creds
	return creds, nil
}

// fetch retrieves credentials from the environment or ECS metadata endpoint.
func (p *ecsCredentialProvider) fetch() (Credentials, error) {
	// Strategy 1: ECS task role (Fargate / ECS).
	relativeURI := os.Getenv("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI")
	if relativeURI != "" {
		return p.fetchFromECS(relativeURI)
	}

	// Strategy 2: Full credentials URI (ECS with custom credential provider).
	fullURI := os.Getenv("AWS_CONTAINER_CREDENTIALS_FULL_URI")
	if fullURI != "" {
		return p.fetchFromFullURI(fullURI)
	}

	// Strategy 3: Static environment variables (local development).
	accessKey := os.Getenv("AWS_ACCESS_KEY_ID")
	secretKey := os.Getenv("AWS_SECRET_ACCESS_KEY")
	if accessKey != "" && secretKey != "" {
		return Credentials{
			AccessKeyID:     accessKey,
			SecretAccessKey: secretKey,
			SessionToken:    os.Getenv("AWS_SESSION_TOKEN"),
		}, nil
	}

	return Credentials{}, fmt.Errorf("no AWS credentials found: set AWS_CONTAINER_CREDENTIALS_RELATIVE_URI (Fargate) or AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY (local)")
}

// fetchFromECS calls the ECS container credential endpoint.
func (p *ecsCredentialProvider) fetchFromECS(relativeURI string) (Credentials, error) {
	endpoint := "http://169.254.170.2" + relativeURI
	return p.fetchFromEndpoint(endpoint)
}

// fetchFromFullURI calls a full credentials URI.
func (p *ecsCredentialProvider) fetchFromFullURI(fullURI string) (Credentials, error) {
	return p.fetchFromEndpoint(fullURI)
}

// fetchFromEndpoint makes the HTTP call and parses the credential response.
func (p *ecsCredentialProvider) fetchFromEndpoint(endpoint string) (Credentials, error) {
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return Credentials{}, fmt.Errorf("creating credential request: %w", err)
	}

	// Some credential endpoints require an auth token.
	if token := os.Getenv("AWS_CONTAINER_AUTHORIZATION_TOKEN"); token != "" {
		req.Header.Set("Authorization", token)
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return Credentials{}, fmt.Errorf("credential endpoint unreachable: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return Credentials{}, fmt.Errorf("reading credential response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return Credentials{}, fmt.Errorf("credential endpoint returned HTTP %d: %s", resp.StatusCode, string(body))
	}

	var credResp ecsCredentialResponse
	if err := json.Unmarshal(body, &credResp); err != nil {
		return Credentials{}, fmt.Errorf("parsing credential response: %w", err)
	}

	var expiration time.Time
	if credResp.Expiration != "" {
		expiration, err = time.Parse(time.RFC3339, credResp.Expiration)
		if err != nil {
			// Try alternate format used by some endpoints.
			expiration, err = time.Parse("2006-01-02T15:04:05Z", credResp.Expiration)
			if err != nil {
				return Credentials{}, fmt.Errorf("parsing credential expiration %q: %w", credResp.Expiration, err)
			}
		}
	}

	return Credentials{
		AccessKeyID:     credResp.AccessKeyID,
		SecretAccessKey: credResp.SecretAccessKey,
		SessionToken:    credResp.Token,
		Expiration:      expiration,
	}, nil
}
