package providers

import (
	"encoding/json"
	"fmt"
)

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
	if nested, ok := data["data"]; ok {
		if m, ok := nested.(map[string]interface{}); ok {
			data = m
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
