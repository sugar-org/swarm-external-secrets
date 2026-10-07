package providers

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"path"
	"strings"

	"github.com/docker/go-plugins-helpers/secrets"
	log "github.com/sirupsen/logrus"

	"github.com/sugar-org/swarm-external-secrets/internal/kvpath"
	"github.com/sugar-org/swarm-external-secrets/internal/vaultcompat"
)

// VaultProvider implements the SecretsProvider interface for HashiCorp Vault.
type VaultProvider struct {
	backend *vaultcompat.Backend
	config  vaultcompat.Config
}

// Initialize sets up the Vault provider with the given configuration.
func (v *VaultProvider) Initialize(config map[string]string) error {
	cfg := vaultcompat.ParseVaultConfig(config)

	backend, err := vaultcompat.New(cfg)
	if err != nil {
		return fmt.Errorf("failed to authenticate with vault: %v", err)
	}

	v.backend = backend
	v.config = cfg
	return nil
}

// GetSecret retrieves a secret value from Vault.
func (v *VaultProvider) GetSecret(ctx context.Context, secretInfo *SecretInfo) ([]byte, error) {
	val, err := v.backend.GetSecret(ctx, secretInfo)
	if err != nil {
		return nil, err
	}

	if shouldBase64Decode(secretInfo) {
		return decodeBase64Secret(val, secretInfo)
	}

	return val, nil
}

func shouldBase64Decode(secretInfo *SecretInfo) bool {
	if secretInfo == nil || secretInfo.Labels == nil {
		return false
	}

	val, ok := secretInfo.Labels["base64_decode"]
	if !ok {
		return false
	}

	return strings.EqualFold(strings.TrimSpace(val), "true")
}

func decodeBase64Secret(value []byte, secretInfo *SecretInfo) ([]byte, error) {
	trimmed := bytes.TrimSpace(value)
	decoded, err := base64.StdEncoding.DecodeString(string(trimmed))
	if err != nil {
		if secretInfo != nil && secretInfo.DockerSecretName != "" {
			return nil, fmt.Errorf("failed to base64-decode secret %q: %w", secretInfo.DockerSecretName, err)
		}
		if secretInfo != nil && secretInfo.SecretField != "" {
			return nil, fmt.Errorf("failed to base64-decode secret field %q: %w", secretInfo.SecretField, err)
		}
		return nil, fmt.Errorf("failed to base64-decode secret: %w", err)
	}

	return decoded, nil
}

// SupportsRotation indicates that Vault supports secret rotation monitoring.
func (v *VaultProvider) SupportsRotation() bool {
	return true
}

// GetSecretFieldLabel returns the label key used by Vault for the secret field.
func (v *VaultProvider) GetSecretFieldLabel() string {
	return v.config.FieldLabel
}

// BuildSecretPath constructs the Vault secret path based on request labels and service information.
func (v *VaultProvider) BuildSecretPath(req secrets.Request) string {
	if customPath, exists := req.SecretLabels[v.config.PathLabel]; exists && customPath != "" {
		return kvpath.BuildMountedKVv2SecretPath(v.config.MountPath, customPath, "")
	}

	secretName := req.SecretName
	if req.ServiceName != "" {
		secretName = path.Join(req.ServiceName, req.SecretName)
	}

	return kvpath.BuildMountedKVv2SecretPath(v.config.MountPath, "", secretName)
}

// GetProviderName returns the name of this provider.
func (v *VaultProvider) GetProviderName() string {
	return "vault"
}

// Close performs cleanup for the Vault provider.
func (v *VaultProvider) Close() error {
	if v.backend == nil {
		return nil
	}

	if err := v.backend.Close(); err != nil {
		log.Printf("Error closing Vault provider: %v", err)
		return err
	}

	return nil
}
