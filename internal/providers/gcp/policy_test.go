package gcp

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadPolicy_ValidFile(t *testing.T) {
	content := `{
		"provider": "gcp",
		"version": "1.0",
		"policies": {
			"kms_rotation_max_days": 90,
			"firewall_prohibited_ports": [22, 3389],
			"sql_require_private_ip": true,
			"sql_require_backups": true
		},
		"exceptions": []
	}`

	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "policy.json")
	os.WriteFile(path, []byte(content), 0644)

	policy, err := LoadPolicy(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if policy.Policies.KMSRotationMaxDays != 90 {
		t.Errorf("expected 90 days, got %d", policy.Policies.KMSRotationMaxDays)
	}
	if len(policy.Policies.FirewallProhibitedPorts) != 2 {
		t.Errorf("expected 2 ports, got %d", len(policy.Policies.FirewallProhibitedPorts))
	}
}

func TestLoadPolicy_DefaultRotation(t *testing.T) {
	content := `{
		"provider": "gcp",
		"version": "1.0",
		"policies": {
			"kms_rotation_max_days": 0,
			"firewall_prohibited_ports": [22]
		},
		"exceptions": []
	}`

	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "policy.json")
	os.WriteFile(path, []byte(content), 0644)

	policy, err := LoadPolicy(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if policy.Policies.KMSRotationMaxDays != 90 {
		t.Errorf("expected default 90 days, got %d", policy.Policies.KMSRotationMaxDays)
	}
}

func TestLoadPolicy_MissingFile(t *testing.T) {
	_, err := LoadPolicy("/nonexistent/policy.json")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoadPolicy_InvalidJSON(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "policy.json")
	os.WriteFile(path, []byte("not json"), 0644)

	_, err := LoadPolicy(path)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestPolicy_IsExcepted_Match(t *testing.T) {
	policy := &Policy{
		Exceptions: []Exception{
			{
				ID:        "EXC-001",
				FindingID: "gcp.compute.firewall_ingress",
				Resource:  "allow-ssh-bastion",
				Reason:    "Approved bastion host",
				Expires:   "2099-12-31",
			},
		},
	}

	exc, ok := policy.IsExcepted("gcp.compute.firewall_ingress", "allow-ssh-bastion")
	if !ok {
		t.Fatal("expected exception to match")
	}
	if exc.ID != "EXC-001" {
		t.Errorf("expected EXC-001, got %s", exc.ID)
	}
}

func TestPolicy_IsExcepted_Expired(t *testing.T) {
	policy := &Policy{
		Exceptions: []Exception{
			{
				ID:        "EXC-002",
				FindingID: "gcp.compute.firewall_ingress",
				Resource:  "allow-ssh-bastion",
				Expires:   "2020-01-01",
			},
		},
	}

	_, ok := policy.IsExcepted("gcp.compute.firewall_ingress", "allow-ssh-bastion")
	if ok {
		t.Fatal("expected expired exception to not match")
	}
}

func TestPolicy_IsExcepted_WrongFinding(t *testing.T) {
	policy := &Policy{
		Exceptions: []Exception{
			{
				ID:        "EXC-003",
				FindingID: "gcp.sql.secure_config",
				Resource:  "my-db",
				Expires:   "2099-12-31",
			},
		},
	}

	_, ok := policy.IsExcepted("gcp.compute.firewall_ingress", "my-db")
	if !ok {
		// Expected: finding ID doesn't match.
	}
	if ok {
		t.Fatal("expected no match for wrong finding ID")
	}
}

func TestPolicy_IsExcepted_Wildcard(t *testing.T) {
	policy := &Policy{
		Exceptions: []Exception{
			{
				ID:        "EXC-004",
				FindingID: "gcp.kms.key_rotation",
				Resource:  "",
				Expires:   "2099-12-31",
			},
		},
	}

	_, ok := policy.IsExcepted("gcp.kms.key_rotation", "any-key-name")
	if !ok {
		t.Fatal("expected wildcard exception to match any resource")
	}
}

func TestPolicy_IsProhibitedPort(t *testing.T) {
	policy := &Policy{
		Policies: PolicySettings{
			FirewallProhibitedPorts: []int{22, 3389, 3306},
		},
	}

	if !policy.IsProhibitedPort(22) {
		t.Error("expected port 22 to be prohibited")
	}
	if !policy.IsProhibitedPort(3389) {
		t.Error("expected port 3389 to be prohibited")
	}
	if policy.IsProhibitedPort(443) {
		t.Error("expected port 443 to not be prohibited")
	}
}
