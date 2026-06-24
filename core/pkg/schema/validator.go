// Package schema provides evidence JSON schema validation for the Jula signing pipeline.
// It validates that evidence files conform to the canonical Evidence/Finding structure
// before Key A signs them, ensuring the assessor will receive well-formed input.
//
// The validator uses structural JSON validation (required fields, types, patterns)
// without an external JSON Schema library to keep dependencies minimal.
package schema

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// payloadHashPattern validates SHA-256 hex strings (64 lowercase hex chars).
var payloadHashPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

// evidenceRequiredFields are the top-level fields every evidence file must have.
var evidenceRequiredFields = []string{"evidence_id", "control_id", "source_id", "finding", "payload_hash"}

// findingRequiredFields are the fields the finding object must have.
var findingRequiredFields = []string{"evidence_id", "control_id", "source_id", "provider", "raw_data", "timestamp", "run_id"}

// ValidationError holds a list of validation failures.
type ValidationError struct {
	Errors []string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("schema validation failed (%d errors):\n  - %s", len(e.Errors), strings.Join(e.Errors, "\n  - "))
}

// ValidateEvidence validates a JSON byte slice against the Jula evidence schema.
// Returns nil if valid, or a *ValidationError listing all issues found.
func ValidateEvidence(data []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return &ValidationError{Errors: []string{fmt.Sprintf("invalid JSON: %v", err)}}
	}

	var errs []string

	// Check required top-level fields.
	for _, field := range evidenceRequiredFields {
		if _, ok := raw[field]; !ok {
			errs = append(errs, fmt.Sprintf("missing required field: %q", field))
		}
	}

	// Validate payload_hash format.
	if hashRaw, ok := raw["payload_hash"]; ok {
		var hash string
		if err := json.Unmarshal(hashRaw, &hash); err != nil {
			errs = append(errs, "payload_hash must be a string")
		} else if !payloadHashPattern.MatchString(hash) {
			errs = append(errs, fmt.Sprintf("payload_hash must be a 64-character lowercase hex string, got %q", hash))
		}
	}

	// Validate string fields.
	for _, field := range []string{"evidence_id", "control_id", "source_id"} {
		if fieldRaw, ok := raw[field]; ok {
			var s string
			if err := json.Unmarshal(fieldRaw, &s); err != nil {
				errs = append(errs, fmt.Sprintf("%s must be a string", field))
			} else if s == "" {
				errs = append(errs, fmt.Sprintf("%s must not be empty", field))
			}
		}
	}

	// Validate finding object.
	if findingRaw, ok := raw["finding"]; ok {
		var finding map[string]json.RawMessage
		if err := json.Unmarshal(findingRaw, &finding); err != nil {
			errs = append(errs, fmt.Sprintf("finding must be a JSON object: %v", err))
		} else {
			for _, field := range findingRequiredFields {
				if _, ok := finding[field]; !ok {
					errs = append(errs, fmt.Sprintf("finding: missing required field: %q", field))
				}
			}

			// Validate finding string fields.
			for _, field := range []string{"evidence_id", "control_id", "source_id", "provider", "run_id"} {
				if fieldRaw, ok := finding[field]; ok {
					var s string
					if err := json.Unmarshal(fieldRaw, &s); err != nil {
						errs = append(errs, fmt.Sprintf("finding.%s must be a string", field))
					} else if s == "" {
						errs = append(errs, fmt.Sprintf("finding.%s must not be empty", field))
					}
				}
			}

			// Validate finding.timestamp as a string (RFC 3339).
			if tsRaw, ok := finding["timestamp"]; ok {
				var ts string
				if err := json.Unmarshal(tsRaw, &ts); err != nil {
					errs = append(errs, "finding.timestamp must be a string")
				}
			}
		}
	}

	if len(errs) > 0 {
		return &ValidationError{Errors: errs}
	}
	return nil
}
