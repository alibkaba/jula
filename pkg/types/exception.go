package types

import "time"

// Exception represents a time-bound compliance exception for a specific
// resource and check. If an active exception matches a FAIL finding,
// the finding status is changed to EXCEPTED.
//
// Exceptions expire automatically: once ExpiresAt passes, the finding
// reverts to FAIL on the next run, forcing remediation.
type Exception struct {
	ResourceARN string    `json:"resource_arn"`
	Check       string    `json:"check"`
	Reason      string    `json:"reason"`
	ApprovedBy  string    `json:"approved_by"`
	ExpiresAt   time.Time `json:"expires_at"`
}

// IsActive reports whether the exception is still valid at the given time.
func (e Exception) IsActive(now time.Time) bool {
	return now.Before(e.ExpiresAt)
}
