package providers

import "github.com/sugar-org/swarm-external-secrets/internal/utils"

func ExtractSecretValueFromMap(data map[string]interface{}, field string) ([]byte, error) {
	return utils.ExtractSecretValueFromMap(data, field)
}

// ExtractSecretValueFromKV unwraps a KV v2 nested "data" key (if present)
// and then extracts the field value from the resulting map.
func ExtractSecretValueFromKV(data map[string]interface{}, field string) ([]byte, error) {
	return utils.ExtractSecretValueFromKV(data, field)
}

// ExtractSecretValueFromKVWithVersion extracts a field for a given KV version.
// KV v1 reads fields directly so a literal "data" entry is preserved;
// KV v2 (including empty version for backward compatibility) unwraps it.
func ExtractSecretValueFromKVWithVersion(data map[string]interface{}, field, kvVersion string) ([]byte, error) {
	return utils.ExtractSecretValueFromKVWithVersion(data, field, kvVersion)
}

func ExtractSecretValue(secretString, field string) ([]byte, error) {
	return utils.ExtractSecretValue(secretString, field)
}
