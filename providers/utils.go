package providers

import "os"

// getConfigOrDefault returns config value or environment variable or default
func getConfigOrDefault(config map[string]string, key, defaultValue string) string {
	if value, exists := config[key]; exists && value != "" {
		return value
	}
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
