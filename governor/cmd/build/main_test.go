package main

import (
	"os"
	"testing"
)

func TestGetEnvStr(t *testing.T) {
	tests := []struct {
		name     string
		envKey   string
		envValue string
		want     string
	}{
		{
			name:     "existing environment variable",
			envKey:   "TEST_ENV_STR",
			envValue: "hello_world",
			want:     "hello_world",
		},
		{
			name:     "environment variable with quotes",
			envKey:   "TEST_ENV_STR_QUOTES",
			envValue: "\"quoted_value\"",
			want:     "quoted_value",
		},
		{
			name:     "non-existent environment variable",
			envKey:   "TEST_ENV_NON_EXISTENT",
			envValue: "", // Set env but empty
			want:     "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup environment variable
			if tt.name != "non-existent environment variable" {
				t.Setenv(tt.envKey, tt.envValue)
			} else {
				os.Unsetenv(tt.envKey) // Ensure it's unset
			}

			if got := getEnvStr(tt.envKey); got != tt.want {
				t.Errorf("getEnvStr() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetEnvInt(t *testing.T) {
	tests := []struct {
		name       string
		envKey     string
		envValue   string
		defaultVal int
		want       int
	}{
		{
			name:       "valid integer",
			envKey:     "TEST_ENV_INT_VALID",
			envValue:   "42",
			defaultVal: 10,
			want:       42,
		},
		{
			name:       "valid integer with quotes",
			envKey:     "TEST_ENV_INT_VALID_QUOTES",
			envValue:   "\"42\"",
			defaultVal: 10,
			want:       42,
		},
		{
			name:       "invalid integer",
			envKey:     "TEST_ENV_INT_INVALID",
			envValue:   "not_an_int",
			defaultVal: 10,
			want:       10,
		},
		{
			name:       "non-existent integer",
			envKey:     "TEST_ENV_INT_NON_EXISTENT",
			envValue:   "",
			defaultVal: 99,
			want:       99,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup environment variable
			if tt.name != "non-existent integer" {
				t.Setenv(tt.envKey, tt.envValue)
			} else {
				os.Unsetenv(tt.envKey) // Ensure it's unset
			}

			if got := getEnvInt(tt.envKey, tt.defaultVal); got != tt.want {
				t.Errorf("getEnvInt() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSanitizeFilename(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "uppercase to lowercase",
			in:   "CONTROL_ID_123",
			want: "control_id_123",
		},
		{
			name: "hyphens to underscores",
			in:   "control-id-123",
			want: "control_id_123",
		},
		{
			name: "dots to underscores",
			in:   "control.id.123",
			want: "control_id_123",
		},
		{
			name: "mixed characters",
			in:   "ConTrOl-iD.123",
			want: "control_id_123",
		},
		{
			name: "already sanitized",
			in:   "control_id_123",
			want: "control_id_123",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := sanitizeFilename(tt.in); got != tt.want {
				t.Errorf("sanitizeFilename() = %v, want %v", got, tt.want)
			}
		})
	}
}
