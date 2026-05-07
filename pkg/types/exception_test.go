package types

import (
	"testing"
	"time"
)

func TestIsActive_NotExpired(t *testing.T) {
	e := Exception{
		ResourceARN: "arn:aws:s3:::public-assets",
		Check:       "gcp.storage.encryption_enabled",
		Reason:      "Static public website bucket, no sensitive data.",
		ApprovedBy:  "ali@julacontrols.com",
		ExpiresAt:   time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
	}

	now := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	if !e.IsActive(now) {
		t.Error("expected IsActive to return true for a non-expired exception")
	}
}

func TestIsActive_Expired(t *testing.T) {
	e := Exception{
		ResourceARN: "arn:aws:s3:::legacy-bucket",
		Check:       "gcp.storage.encryption_enabled",
		Reason:      "Temporary exception for migration.",
		ApprovedBy:  "ali@julacontrols.com",
		ExpiresAt:   time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}

	now := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	if e.IsActive(now) {
		t.Error("expected IsActive to return false for an expired exception")
	}
}

func TestIsActive_ExactExpiry(t *testing.T) {
	expiry := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	e := Exception{
		ResourceARN: "arn:aws:s3:::edge-case-bucket",
		Check:       "gcp.storage.encryption_enabled",
		Reason:      "Boundary test.",
		ApprovedBy:  "ali@julacontrols.com",
		ExpiresAt:   expiry,
	}

	// When now == ExpiresAt, time.Before returns false, so IsActive should be false.
	if e.IsActive(expiry) {
		t.Error("expected IsActive to return false when now equals ExpiresAt exactly")
	}
}
