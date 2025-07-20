package main

import (
	"fmt"
	"os"
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
