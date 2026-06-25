package main

import "testing"

func TestExtractRegoBlock(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "fenced rego block",
			input: "Here is the output:\n```rego\npackage test\n\ndefault allow = false\n```\nDone.",
			want:  "package test\n\ndefault allow = false",
		},
		{
			name:  "fenced generic block",
			input: "```\npackage test\n```",
			want:  "package test",
		},
		{
			name:  "no fence at all",
			input: "package test\n\ndefault allow = true",
			want:  "package test\n\ndefault allow = true",
		},
		{
			name:  "triple backtick wrapping only",
			input: "```rego\npackage raw\n```",
			want:  "package raw",
		},
		{
			name:  "empty input",
			input: "",
			want:  "",
		},
		{
			name:  "multiple blocks returns first",
			input: "```rego\npackage first\n```\n\n```rego\npackage second\n```",
			want:  "package first",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractRegoBlock(tt.input)
			if got != tt.want {
				t.Errorf("extractRegoBlock() = %q, want %q", got, tt.want)
			}
		})
	}
}
