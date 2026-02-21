package main

import "testing"

func TestNormalizeGCPSecretName(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "already valid",
			input:    "MySecret_123",
			expected: "MySecret_123",
		},
		{
			name:     "starts with number",
			input:    "1secret",
			expected: "ssecret",
		},
		{
			name:     "starts with special char",
			input:    "@secret",
			expected: "ssecret",
		},
		{
			name:     "invalid chars inside",
			input:    "my$secret#name",
			expected: "my_secret_name",
		},
		{
			name:     "mixed invalid and valid",
			input:    "9my secret!*",
			expected: "smy_secret__",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "s",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := normalizeGCPSecretName(tt.input)
			if result != tt.expected {
				t.Fatalf("expected %q, got %q", tt.expected, result)
			}
		})
	}
}
