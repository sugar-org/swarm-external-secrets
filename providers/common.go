package providers

import (
	"encoding/json"
	"fmt"
)

func ExtractSecretValueFromMap(data map[string]interface{}, field string) ([]byte, error) {
	if field == "" {
		return json.Marshal(data)
	}

	if value, ok := data[field]; ok {
		return []byte(fmt.Sprintf("%v", value)), nil
	}

	keys := make([]string, 0, len(data))
	for k := range data {
		keys = append(keys, k)
	}

	return nil, fmt.Errorf("field %s not found in secret; available fields: %v", field, keys)
}

// ExtractSecretValueFromVaultKVv2 extracts a field value from a Vault/OpenBao KV v2 secret.
func ExtractSecretValueFromVaultKVv2(data map[string]interface{}, field string) ([]byte, error) {
	outer, ok := data["data"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid kv v2 response: missing top-level data field")
	}

	inner, ok := outer["data"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid kv v2 response: missing nested data.data field")
	}

	return ExtractSecretValueFromMap(inner, field)
}

func ExtractSecretValue(secretString, field string) ([]byte, error) {
	if field == "" {
		return []byte(secretString), nil
	}

	var data map[string]interface{}

	if err := json.Unmarshal([]byte(secretString), &data); err == nil {
		return ExtractSecretValueFromMap(data, field)
	}

	return nil, fmt.Errorf("expected secret to be a json object with field %s", field)
}
