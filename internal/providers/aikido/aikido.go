package aikido

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/alibkaba/jula-evidence-collector/internal/providers"
	"github.com/alibkaba/jula-evidence-collector/pkg/types"
)

func init() {
	providers.Register(New())
}

const (
	providerName      = "aikido"
	tokenURL          = "https://app.aikido.dev/api/oauth/token"
	exportURL         = "https://app.aikido.dev/api/public/v1/issues/export?format=json&filter_status=open"
	listCodeReposURL  = "https://app.aikido.dev/api/public/v1/repositories/code"
	listContainersURL = "https://app.aikido.dev/api/public/v1/containers"
	listVMsURL        = "https://app.aikido.dev/api/public/v1/virtual-machines"
	codeSbomURL       = "https://app.aikido.dev/api/public/v1/repositories/code/%s/licenses/export?format=sbom"
	containerSbomURL  = "https://app.aikido.dev/api/public/v1/containers/%s/licenses/export?format=sbom"
	vmSbomURL         = "https://app.aikido.dev/api/public/v1/virtual-machines/%s/export/sbom"
	maxRetries        = 3
)

var (
	defaultBackoff      = 5 * time.Second
	ErrResourceNotFound = errors.New("resource not found")
)

// Provider implements the providers.Provider interface for Aikido Security.
type Provider struct {
	clientID         string
	secretKey        string
	codeRepoIDs      []string
	containerRepoIDs []string
	vmIDs            []string
	client           *http.Client
}

func parseEnvList(key string) []string {
	val := os.Getenv(key)
	if val == "" {
		return nil
	}
	return strings.Split(val, ",")
}

// New initializes a new Aikido provider.
func New() *Provider {
	return &Provider{
		clientID:         os.Getenv("AIK_CLIENT_ID"),
		secretKey:        os.Getenv("AIK_SECRET_KEY"),
		codeRepoIDs:      parseEnvList("AIK_CODE_REPO_IDS"),
		containerRepoIDs: parseEnvList("AIK_CONTAINER_REPO_IDS"),
		vmIDs:            parseEnvList("AIK_VM_IDS"),
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

func (p *Provider) Name() string {
	return providerName
}

func (p *Provider) Validate() error {
	if p.clientID == "" {
		return fmt.Errorf("AIK_CLIENT_ID environment variable is missing")
	}
	if p.secretKey == "" {
		return fmt.Errorf("AIK_SECRET_KEY environment variable is missing")
	}
	return nil
}

func (p *Provider) Extract(ctx context.Context, runID string) ([]types.Finding, error) {
	token, err := p.authenticate(ctx)
	if err != nil {
		return nil, fmt.Errorf("aikido authentication failed: %w", err)
	}

	issues, err := p.fetchIssues(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch aikido issues: %w", err)
	}

	var findings []types.Finding

	if len(issues) == 0 {
		findings = append(findings, types.Finding{
			ID:                 "aikido.open_vulnerability",
			Provider:           providerName,
			Resource:           "aikido_workspace",
			Check:              "open_vulnerability",
			Status:             "PASS",
			RawPayload:         map[string]any{"message": "No open issues found"},
			ResourceIdentifier: "aikido:workspace",
			Timestamp:          time.Now().UTC(),
			RunID:              runID,
		})
	}

	for _, issue := range issues {
		status := "FAIL" // Any open issue in the export is considered a FAIL finding

		rawPayload, ok := issue.(map[string]any)
		if !ok {
			rawPayload = map[string]any{"raw": issue}
		}

		var issueID string
		switch v := rawPayload["id"].(type) {
		case float64:
			issueID = fmt.Sprintf("%.0f", v)
		default:
			issueID = fmt.Sprintf("%v", v)
		}

		finding := types.Finding{
			ID:                 "aikido.open_vulnerability",
			Provider:           providerName,
			Resource:           "aikido_issue",
			Check:              "open_vulnerability",
			Status:             status,
			RawPayload:         rawPayload,
			ResourceIdentifier: fmt.Sprintf("aikido:issue:%s", issueID),
			Timestamp:          time.Now().UTC(),
			RunID:              runID,
		}
		findings = append(findings, finding)
	}

	// --- AUTO DISCOVERY FALLBACKS ---
	if len(p.codeRepoIDs) == 0 {
		fmt.Println("AIK_CODE_REPO_IDS is empty, auto-discovering code repos...")
		discoveredIDs, err := p.autoDiscoverCodeRepos(ctx, token)
		if err == nil {
			p.codeRepoIDs = discoveredIDs
		}
	}

	if len(p.containerRepoIDs) == 0 {
		fmt.Println("AIK_CONTAINER_REPO_IDS is empty, auto-discovering containers...")
		discoveredIDs, err := p.autoDiscoverContainers(ctx, token)
		if err == nil {
			p.containerRepoIDs = discoveredIDs
		}
	}

	if len(p.vmIDs) == 0 {
		fmt.Println("AIK_VM_IDS is empty, auto-discovering VMs...")
		discoveredIDs, err := p.autoDiscoverVMs(ctx, token)
		if err == nil {
			p.vmIDs = discoveredIDs
		}
	}
	// --------------------------------

	for _, id := range p.codeRepoIDs {
		sbom, err := p.fetchCodeSBOM(ctx, token, id)
		findings = append(findings, p.buildSBOMFinding("aikido.sbom.code", "code_repo", "aikido:code_repo:"+id, runID, sbom, err))
	}

	for _, id := range p.containerRepoIDs {
		sbom, err := p.fetchContainerSBOM(ctx, token, id)
		findings = append(findings, p.buildSBOMFinding("aikido.sbom.container", "container", "aikido:container:"+id, runID, sbom, err))
	}

	for _, id := range p.vmIDs {
		sbom, err := p.fetchVMSBOM(ctx, token, id)
		findings = append(findings, p.buildSBOMFinding("aikido.sbom.vm", "virtual_machine", "aikido:virtual_machine:"+id, runID, sbom, err))
	}

	return findings, nil
}

func (p *Provider) authenticate(ctx context.Context) (string, error) {
	data := url.Values{}
	data.Set("grant_type", "client_credentials")

	req, err := http.NewRequestWithContext(ctx, "POST", tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return "", err
	}

	authPayload := base64.StdEncoding.EncodeToString([]byte(p.clientID + ":" + p.secretKey))
	req.Header.Set("Authorization", "Basic "+authPayload)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	var lastErr error
	for i := 0; i < maxRetries; i++ {
		resp, err := p.client.Do(req)
		if err != nil {
			lastErr = err
			time.Sleep(defaultBackoff)
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusTooManyRequests {
			lastErr = fmt.Errorf("rate limited (429)")
			time.Sleep(defaultBackoff * time.Duration(i+1)) // Exponential-ish backoff
			continue
		}

		if resp.StatusCode != http.StatusOK {
			bodyBytes, _ := io.ReadAll(resp.Body)
			return "", fmt.Errorf("unexpected status code %d: %s", resp.StatusCode, string(bodyBytes))
		}

		var result struct {
			AccessToken string `json:"access_token"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			return "", fmt.Errorf("failed to decode token response: %w", err)
		}

		if result.AccessToken == "" {
			return "", fmt.Errorf("received empty access token")
		}

		return result.AccessToken, nil
	}

	return "", fmt.Errorf("max retries exceeded: %v", lastErr)
}

func (p *Provider) fetchIssues(ctx context.Context, token string) ([]any, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", exportURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+token)

	var lastErr error
	for i := 0; i < maxRetries; i++ {
		resp, err := p.client.Do(req)
		if err != nil {
			lastErr = err
			time.Sleep(defaultBackoff)
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusTooManyRequests {
			lastErr = fmt.Errorf("rate limited (429)")
			time.Sleep(defaultBackoff * time.Duration(i+1))
			continue
		}

		if resp.StatusCode != http.StatusOK {
			bodyBytes, _ := io.ReadAll(resp.Body)
			return nil, fmt.Errorf("unexpected status code %d: %s", resp.StatusCode, string(bodyBytes))
		}

		var issues []any
		if err := json.NewDecoder(resp.Body).Decode(&issues); err != nil {
			return nil, fmt.Errorf("failed to decode issues response: %w", err)
		}

		return issues, nil
	}

	return nil, fmt.Errorf("max retries exceeded: %v", lastErr)
}

func (p *Provider) autoDiscoverCodeRepos(ctx context.Context, token string) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", listCodeReposURL, nil)
	if err != nil {
		fmt.Println("Warning: auto-discovery of code repos failed, skipping...")
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := p.client.Do(req)
	if err != nil {
		fmt.Println("Warning: auto-discovery of code repos failed, skipping...")
		return nil, err
	}
	defer resp.Body.Close()

	var repos []map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&repos); err != nil {
		fmt.Println("Warning: auto-discovery of code repos failed, skipping...")
		return nil, fmt.Errorf("failed to decode code repos: %w", err)
	}

	var ids []string
	for _, repo := range repos {
		if id, ok := repo["id"]; ok {
			ids = append(ids, fmt.Sprintf("%v", id))
		}
	}
	return ids, nil
}

func (p *Provider) autoDiscoverContainers(ctx context.Context, token string) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", listContainersURL, nil)
	if err != nil {
		fmt.Println("Warning: auto-discovery of containers failed, skipping...")
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := p.client.Do(req)
	if err != nil {
		fmt.Println("Warning: auto-discovery of containers failed, skipping...")
		return nil, err
	}
	defer resp.Body.Close()

	var containers []map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&containers); err != nil {
		fmt.Println("Warning: auto-discovery of containers failed, skipping...")
		return nil, fmt.Errorf("failed to decode containers: %w", err)
	}

	var ids []string
	for _, container := range containers {
		if id, ok := container["id"]; ok {
			ids = append(ids, fmt.Sprintf("%v", id))
		}
	}
	return ids, nil
}

func (p *Provider) autoDiscoverVMs(ctx context.Context, token string) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", listVMsURL, nil)
	if err != nil {
		fmt.Println("Warning: auto-discovery of VMs failed, skipping...")
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := p.client.Do(req)
	if err != nil {
		fmt.Println("Warning: auto-discovery of VMs failed, skipping...")
		return nil, err
	}
	defer resp.Body.Close()

	var vms []map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&vms); err != nil {
		fmt.Println("Warning: auto-discovery of VMs failed, skipping...")
		return nil, fmt.Errorf("failed to decode VMs: %w", err)
	}

	var ids []string
	for _, vm := range vms {
		if id, ok := vm["id"]; ok {
			ids = append(ids, fmt.Sprintf("%v", id))
		}
	}
	return ids, nil
}

func (p *Provider) fetchCodeSBOM(ctx context.Context, token string, repoID string) (map[string]any, error) {
	url := fmt.Sprintf(codeSbomURL, repoID)
	return p.fetchSBOM(ctx, token, url)
}

func (p *Provider) fetchContainerSBOM(ctx context.Context, token string, repoID string) (map[string]any, error) {
	url := fmt.Sprintf(containerSbomURL, repoID)
	return p.fetchSBOM(ctx, token, url)
}

func (p *Provider) fetchVMSBOM(ctx context.Context, token string, vmID string) (map[string]any, error) {
	url := fmt.Sprintf(vmSbomURL, vmID)
	return p.fetchSBOM(ctx, token, url)
}

func (p *Provider) fetchSBOM(ctx context.Context, token string, targetURL string) (map[string]any, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+token)

	var lastErr error
	for i := 0; i < maxRetries; i++ {
		resp, err := p.client.Do(req)
		if err != nil {
			lastErr = err
			time.Sleep(defaultBackoff)
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusTooManyRequests {
			lastErr = fmt.Errorf("rate limited (429)")
			time.Sleep(defaultBackoff * time.Duration(i+1))
			continue
		}

		if resp.StatusCode == http.StatusNotFound {
			return nil, ErrResourceNotFound
		}

		if resp.StatusCode != http.StatusOK {
			bodyBytes, _ := io.ReadAll(resp.Body)
			return nil, fmt.Errorf("unexpected status code %d: %s", resp.StatusCode, string(bodyBytes))
		}

		var sbom map[string]any
		if err := json.NewDecoder(resp.Body).Decode(&sbom); err != nil {
			return nil, fmt.Errorf("failed to decode sbom response: %w", err)
		}

		return sbom, nil
	}

	return nil, fmt.Errorf("max retries exceeded: %v", lastErr)
}

func (p *Provider) buildSBOMFinding(findingID, resourceType, resourceIdentifier, runID string, sbom map[string]any, err error) types.Finding {
	status := "PASS"
	var payload map[string]any

	if err != nil {
		status = "FAIL"
		errMsg := err.Error()
		if errors.Is(err, ErrResourceNotFound) {
			errMsg = "Resource not found (404)"
		}
		payload = map[string]any{"error": errMsg}
	} else {
		payload = sbom
	}

	return types.Finding{
		ID:                 findingID,
		Provider:           providerName,
		Resource:           resourceType,
		Check:              "sbom_collection",
		Status:             status,
		RawPayload:         payload,
		ResourceIdentifier: resourceIdentifier,
		Timestamp:          time.Now().UTC(),
		RunID:              runID,
	}
}
