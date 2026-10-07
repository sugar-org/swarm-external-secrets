package utils

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// SecretInfo tracks information about secrets being managed.
type SecretInfo struct {
	DockerSecretName string
	SecretPath       string
	SecretField      string
	ServiceNames     []string
	LastHash         string
	LastUpdated      time.Time
	Provider         string
	Labels           map[string]string
}

// getEnvOrDefault returns environment variable value or default
func GetEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// getConfigOrDefault returns config value or environment variable or default
func GetConfigOrDefault(config map[string]string, key, defaultValue string) string {
	if value, exists := config[key]; exists && value != "" {
		return value
	}
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// parseDurationOrDefault parses duration string or returns default
func ParseDurationOrDefault(durationStr string) time.Duration {
	if duration, err := time.ParseDuration(durationStr); err == nil {
		return duration
	}
	return 5 * time.Minute // Default to 5 minutes
}

// parseIntOrDefault parses integer string or returns default
func ParseIntOrDefault(intStr string) int {
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

func ExtractSecretValueFromMap(data map[string]interface{}, field string) ([]byte, error) {
	if field != "" {
		if value, ok := data[field]; ok {
			return []byte(fmt.Sprintf("%v", value)), nil
		}

		keys := make([]string, 0, len(data))
		for k := range data {
			keys = append(keys, k)
		}

		return nil, fmt.Errorf("field %s not found in secret; available fields: %v", field, keys)
	}

	defaultFields := []string{"value", "password", "secret", "data"}
	for _, f := range defaultFields {
		if value, ok := data[f]; ok {
			return []byte(fmt.Sprintf("%v", value)), nil
		}
	}

	for _, value := range data {
		if strValue, ok := value.(string); ok {
			return []byte(strValue), nil
		}
	}

	return nil, fmt.Errorf("no suitable secret value found")
}

// ExtractSecretValueFromKV unwraps a KV v2 nested "data" key (if present)
// and then extracts the field value from the resulting map.
func ExtractSecretValueFromKV(data map[string]interface{}, field string) ([]byte, error) {
	return ExtractSecretValueFromKVWithVersion(data, field, "2")
}

// ExtractSecretValueFromKVWithVersion extracts a field for a given KV version.
// KV v1 responses carry fields at the top level, so a literal "data" entry is
// a valid secret value and must never be unwrapped. KV v2 responses nest
// values under "data", which is unwrapped when present. Empty version means
// v2 for backward compatibility.
func ExtractSecretValueFromKVWithVersion(data map[string]interface{}, field, kvVersion string) ([]byte, error) {
	if kvVersion != "1" {
		if nested, ok := data["data"]; ok {
			if m, ok := nested.(map[string]interface{}); ok {
				data = m
			}
		}
	}
	return ExtractSecretValueFromMap(data, field)
}

func ExtractSecretValue(secretString, field string) ([]byte, error) {
	var data map[string]interface{}

	if err := json.Unmarshal([]byte(secretString), &data); err == nil {
		return ExtractSecretValueFromMap(data, field)
	}

	if field != "" && field != "value" {
		return nil, fmt.Errorf("field %s not found in non-json secret", field)
	}

	return []byte(secretString), nil
}
