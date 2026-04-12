package main

import (
	"fmt"
	"os"
	"strings"
	"time"
)

// getEnvOrDefault returns environment variable value or default
func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// parseDurationOrDefault parses duration string or returns default
func parseDurationOrDefault(durationStr string) time.Duration {
	if duration, err := time.ParseDuration(durationStr); err == nil {
		return duration
	}
	return 5 * time.Minute // Default to 5 minutes
}

// parseIntOrDefault parses integer string or returns default
func parseIntOrDefault(intStr string) int {
	if val, err := fmt.Sscanf(intStr, "%d", new(int)); err == nil && val == 1 {
		var result int
		_, err := fmt.Sscanf(intStr, "%d", &result)
		if err == nil {
			// Successfully parsed integer
			if result > 0 && result <= 65535 {
				return result
			}
		}
	}
	return 8080 // Default port
}

// normalizeGCPSecretName ensures the name matches GCP's requirements: [a-zA-Z][a-zA-Z0-9_-]*
func normalizeGCPSecretName(secretName string) string {
	if len(secretName) == 0 {
		return "s"
	}

	var result strings.Builder
	result.Grow(len(secretName))

	for i, char := range secretName {
		if i == 0 {
			result.WriteRune(normalizedGCPFirstChar(char))
			continue
		}
		result.WriteRune(normalizedGCPChar(char))
	}
	return result.String()
}

func normalizedGCPFirstChar(char rune) rune {
	if isASCIIAlpha(char) {
		return char
	}
	return 's'
}

func normalizedGCPChar(char rune) rune {
	if isASCIIAlphaNumeric(char) || char == '_' || char == '-' {
		return char
	}
	return '_'
}

func isASCIIAlpha(char rune) bool {
	return (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z')
}

func isASCIIAlphaNumeric(char rune) bool {
	return isASCIIAlpha(char) || (char >= '0' && char <= '9')
}
