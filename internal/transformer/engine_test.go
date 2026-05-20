package transformer

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/alibkaba/jula-core/pkg/types"
	"github.com/alibkaba/jula-evidence-collector/internal/transformer/schemas"
)

func TestTransformer_DatabaseConfig_GCP(t *testing.T) {
	r := NewRegistry()

	rawGCP := `{
		"resource": {
			"data": {
				"settings": {
					"ipConfiguration": {
						"ipv4Enabled": true,
						"requireSsl": true
					}
				}
			}
		}
	}`

	finding := types.Finding{
		ErlID:    "E-BCM-16",
		Provider: "gcp_cai",
		RawData:  []byte(rawGCP),
	}

	res, err := r.Transform(finding)
	if err != nil {
		t.Fatalf("unexpected error during transformation: %v", err)
	}

	var schema schemas.DatabaseSchema
	if err := json.Unmarshal(res, &schema); err != nil {
		t.Fatalf("failed to unmarshal result: %v", err)
	}

	if !schema.EncryptedAtRest {
		t.Error("expected EncryptedAtRest to be true by default for GCP")
	}
	if !schema.RequireTLS {
		t.Error("expected RequireTLS to be true")
	}
	if !schema.PubliclyAccessible {
		t.Error("expected PubliclyAccessible to be true")
	}
}

func TestTransformer_DatabaseConfig_AWS(t *testing.T) {
	r := NewRegistry()

	rawAWS := `{
		"configuration": {
			"storageEncrypted": true,
			"publiclyAccessible": false,
			"requireTls": true
		}
	}`

	finding := types.Finding{
		ErlID:    "E-BCM-16",
		Provider: "aws_config",
		RawData:  []byte(rawAWS),
	}

	res, err := r.Transform(finding)
	if err != nil {
		t.Fatalf("unexpected error during AWS transformation: %v", err)
	}

	var schema schemas.DatabaseSchema
	if err := json.Unmarshal(res, &schema); err != nil {
		t.Fatalf("failed to unmarshal result: %v", err)
	}

	if !schema.EncryptedAtRest {
		t.Error("expected EncryptedAtRest to be true")
	}
	if schema.RequireTLS == false {
		t.Error("expected RequireTLS to be true")
	}
	if schema.PubliclyAccessible {
		t.Error("expected PubliclyAccessible to be false")
	}
}

func TestTransformer_DefaultPassThrough(t *testing.T) {
	r := NewRegistry()

	finding := types.Finding{
		ErlID:    "E-SOME-OTHER-CONTROL",
		Provider: "gcp_cai",
		RawData:  []byte(`{"some":"data"}`),
	}

	res, err := r.Transform(finding)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if string(res) != "null" {
		t.Errorf("expected pass-through null, got %s", string(res))
	}
}

func TestTransformer_NilSafety(t *testing.T) {
	r := NewRegistry()

	// Empty payload test
	finding := types.Finding{
		ErlID:    "E-BCM-16",
		Provider: "gcp_cai",
		RawData:  []byte(`{}`),
	}

	_, err := r.Transform(finding)
	if err != nil {
		t.Fatalf("expected transform to handle empty JSON gracefully, got error: %v", err)
	}

	// Malformed JSON test
	findingMalformed := types.Finding{
		ErlID:    "E-BCM-16",
		Provider: "aws_config",
		RawData:  []byte(`{invalid-json`),
	}

	_, err = r.Transform(findingMalformed)
	if err == nil {
		t.Fatal("expected error for malformed JSON, got nil")
	}
	if !strings.Contains(err.Error(), "failed to unmarshal AWS database finding") {
		t.Errorf("expected unmarshal failure error message, got: %v", err)
	}
}
