package types

import "time"

// Finding represents raw state extracted from a provider.
type Finding struct {
	ID          string         `json:"id"`
	Provider    string         `json:"provider"`
	Resource    string         `json:"resource"`
	Check       string         `json:"check"`
	Status      string         `json:"status"` // "PASS", "FAIL", "ERROR"
	RawPayload  map[string]any `json:"raw_payload,omitempty"`
	ResourceARN string         `json:"resource_arn"`
	Timestamp   time.Time      `json:"timestamp"`
	RunID       string         `json:"run_id"`
}
