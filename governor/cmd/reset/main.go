package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	fmt.Print("[RESET] Truncating requirements.csv... ")
	err := os.WriteFile("../../requirements.csv", []byte("Control_ID,Requirement_ID,Target_Provider,Parameter_Field,Operator,Expected_Value,Confidence,Status,Documentation_URL\n"), 0644)
	if err != nil {
		log.Fatalf("Failed: %v", err)
	}

	fmt.Print("Re-initializing active_rules.json... ")
	indexContent := `{
  "version": "1.0",
  "description": "Active baseline evaluation rules",
  "rules": []
}`
	err = os.WriteFile("../../policies/rules/active_rules.json", []byte(indexContent), 0644)
	if err != nil {
		log.Fatalf("Failed: %v", err)
	}

	fmt.Print("Resetting workspace.yaml... ")
	workspaceContent := `organization: "Enterprise-X"
current_environment: "production"

active_providers:
  # gcp:
  #   doc_root: "https://cloud.google.com/docs"
  # aws:
  #   doc_root: "https://docs.aws.amazon.com"
  # azure:
  #   doc_root: "https://learn.microsoft.com/azure"
  # alicloud:
  #   doc_root: "https://www.alibabacloud.com/help"
  # oci:
  #   doc_root: "https://docs.oracle.com/en-us/iaas/Content/home.htm"
  # tencent:
  #   doc_root: "https://www.tencentcloud.com/document"
`
	err = os.WriteFile("../../workspace.yaml", []byte(workspaceContent), 0644)
	if err != nil {
		log.Fatalf("Failed: %v", err)
	}

	fmt.Print("Purging core rules and translators... ")

	// Purge core_*.rego and core_*.rego_test
	rulesFiles, _ := filepath.Glob("../../policies/rules/core_*.rego")
	testFiles, _ := filepath.Glob("../../policies/rules/core_*.rego_test")
	for _, f := range append(rulesFiles, testFiles...) {
		if err := os.Remove(f); err != nil {
			log.Fatalf("Failed to remove %s: %v", f, err)
		}
	}

	// Purge .rego in scoping
	scopingFiles, _ := filepath.Glob("../../policies/scoping/*.rego")
	for _, f := range scopingFiles {
		if err := os.Remove(f); err != nil {
			log.Fatalf("Failed to remove %s: %v", f, err)
		}
	}

	// Purge translators
	translatorFiles, _ := filepath.Glob("../../engine/translators/*")
	for _, f := range translatorFiles {
		if info, err := os.Stat(f); err == nil && !info.IsDir() {
			if err := os.Remove(f); err != nil {
				log.Fatalf("Failed to remove %s: %v", f, err)
			}
		}
	}

	fmt.Print("Restoring default integration yaml files... ")
	integrations := []string{"alicloud.yaml", "aws.yaml", "azure.yaml", "gcp.yaml", "oci.yaml", "tencent.yaml"}
	// Clear all files in integrations first
	integrationFiles, _ := filepath.Glob("../../engine/integrations/*")
	for _, f := range integrationFiles {
		if info, err := os.Stat(f); err == nil && !info.IsDir() {
			os.Remove(f)
		}
	}

	for _, integration := range integrations {
		provider := integration[:len(integration)-5] // e.g., "gcp", "aws"
		upperProvider := strings.ToUpper(provider)
		var content string

		if provider == "gcp" {
			content = `vendor_name: "gcp"
provider: "gcp"                  # Primary routing discriminator key
auth_flow:
  type: "gcp_native_auth"        # Evaluates environment credential chains at runtime
  token_env: "GCP_ACCESS_TOKEN"
endpoints:
  "https://cloudasset.googleapis.com/v1/projects/${GCP_PROJECT_ID}:searchAllResources":
    method: "GET"
    evidence_id: "EVID-GCP-INVENTORY"
    description: "Search active GCP cloud infrastructure assets via REST"
    query_params:
      assetTypes: "storage.googleapis.com/Bucket,sqladmin.googleapis.com/Instance"
`
		} else {
			content = fmt.Sprintf(`vendor_name: "%[1]s"
provider: "%[1]s"                    # Core routing discriminator token
auth_flow:
  type: "%[1]s_native_auth"        # Evaluates environment credential chains at runtime
  token_env: "%[2]s_ACCESS_TOKEN"  # Local fallback environment override token
endpoints: {}                      # To be populated during platform onboarding modeling
`, provider, upperProvider)
		}

		err := os.WriteFile("../../engine/integrations/"+integration, []byte(content), 0644)
		if err != nil {
			log.Fatalf("Failed to serialize integration asset %s: %v", integration, err)
		}
	}

	fmt.Println("Workspace reset complete.")
}
