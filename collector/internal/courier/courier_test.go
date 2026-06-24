package courier

import (
	"testing"
)

func TestSanitizeResourceID(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"", "global_resource"},
		{"valid-id-123", "valid-id-123"},
		{"project:my-project", "project-my-project"},
		{"arn:aws:iam::123:role/MyRole", "arn-aws-iam--123-role-MyRole"},
		{"a space here", "a_space_here"},
		{"path\\with\\slashes", "path-with-slashes"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := SanitizeResourceID(tt.input)
			if result != tt.expected {
				t.Errorf("SanitizeResourceID(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}
