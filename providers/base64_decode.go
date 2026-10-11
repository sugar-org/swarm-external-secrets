package providers

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strings"
)

// shouldBase64Decode checks if the base64_decode label is explicitly set to true.
func shouldBase64Decode(secretInfo *SecretInfo) bool {
	if secretInfo.Labels == nil {
		return false
	}

	val, ok := secretInfo.Labels["base64_decode"]
	if !ok {
		return false
	}

	return strings.EqualFold(strings.TrimSpace(val), "true")
}

// decodeBase64Secret decodes a base64-encoded secret value into its raw bytes.
func decodeBase64Secret(value []byte, secretInfo *SecretInfo) ([]byte, error) {
	trimmed := bytes.TrimSpace(value)
	decoded, err := base64.StdEncoding.DecodeString(string(trimmed))
	if err != nil {
		switch {
		case secretInfo.DockerSecretName != "":
			return nil, fmt.Errorf("failed to base64-decode secret %q: %w", secretInfo.DockerSecretName, err)
		case secretInfo.SecretField != "":
			return nil, fmt.Errorf("failed to base64-decode secret field %q: %w", secretInfo.SecretField, err)
		default:
			return nil, fmt.Errorf("failed to base64-decode secret: %w", err)
		}
	}

	return decoded, nil
}
