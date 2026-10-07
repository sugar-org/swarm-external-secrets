package providers

import (
	"context"
	"fmt"
	"path"

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

	kvVersion, err := vaultcompat.NormalizeVaultKVVersion(cfg.KVVersion)
	if err != nil {
		return err
	}
	cfg.KVVersion = kvVersion

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
	return v.backend.GetSecret(ctx, secretInfo)
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
//
// KV v2 paths use the "<mount>/data/<secret-path>" form while KV v1 paths use
// "<mount>/<secret-path>". The version comes from VAULT_KV_VERSION ("1" or
// "2", default "2"); an empty version also means v2 so configs built without
// Initialize keep the historical behaviour. A literal "data/" folder is
// preserved for KV v1 since it is a valid secret name.
func (v *VaultProvider) BuildSecretPath(req secrets.Request) string {
	if customPath, exists := req.SecretLabels[v.config.PathLabel]; exists && customPath != "" {
		if v.config.KVVersion == "1" {
			return kvpath.BuildMountedKVv1SecretPath(v.config.MountPath, customPath, "")
		}
		return kvpath.BuildMountedKVv2SecretPath(v.config.MountPath, customPath, "")
	}

	secretName := req.SecretName
	if req.ServiceName != "" {
		secretName = path.Join(req.ServiceName, req.SecretName)
	}

	if v.config.KVVersion == "1" {
		return kvpath.BuildMountedKVv1SecretPath(v.config.MountPath, "", secretName)
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
