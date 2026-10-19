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

// OpenBaoProvider implements the SecretsProvider interface for OpenBao.
type OpenBaoProvider struct {
	backend *vaultcompat.Backend
	config  vaultcompat.Config
}

// Initialize sets up the OpenBao provider with the given configuration.
func (o *OpenBaoProvider) Initialize(config map[string]string) error {
	cfg := vaultcompat.ParseOpenBaoConfig(config)

	kvVersion, err := vaultcompat.NormalizeOpenBaoKVVersion(cfg.KVVersion)
	if err != nil {
		return err
	}
	cfg.KVVersion = kvVersion

	backend, err := vaultcompat.New(cfg)
	if err != nil {
		return fmt.Errorf("failed to authenticate with OpenBao: %v", err)
	}

	o.backend = backend
	o.config = cfg
	return nil
}

// GetSecret retrieves a secret value from OpenBao.
func (o *OpenBaoProvider) GetSecret(ctx context.Context, secretInfo *SecretInfo) ([]byte, error) {
	return o.backend.GetSecret(ctx, secretInfo)
}

// SupportsRotation indicates that OpenBao supports secret rotation monitoring.
func (o *OpenBaoProvider) SupportsRotation() bool {
	return true
}

// GetSecretFieldLabel returns the label key used by OpenBao for the secret field.
func (o *OpenBaoProvider) GetSecretFieldLabel() string {
	return o.config.FieldLabel
}

// BuildSecretPath constructs the OpenBao secret path based on request labels and service information.
//
// KV v2 paths use the "<mount>/data/<secret-path>" form while KV v1 paths use
// "<mount>/<secret-path>". The version comes from OPENBAO_KV_VERSION ("1" or
// "2", default "2"); an empty version also means v2 so configs built without
// Initialize keep the historical behaviour.
func (o *OpenBaoProvider) BuildSecretPath(req secrets.Request) string {
	if customPath, exists := req.SecretLabels[o.config.PathLabel]; exists && customPath != "" {
		if o.config.KVVersion == "1" {
			return kvpath.BuildMountedKVv1SecretPath(o.config.MountPath, customPath, "")
		}
		return kvpath.BuildMountedKVv2SecretPath(o.config.MountPath, customPath, "")
	}

	secretName := req.SecretName
	if req.ServiceName != "" {
		secretName = path.Join(req.ServiceName, req.SecretName)
	}

	if o.config.KVVersion == "1" {
		return kvpath.BuildMountedKVv1SecretPath(o.config.MountPath, "", secretName)
	}
	return kvpath.BuildMountedKVv2SecretPath(o.config.MountPath, "", secretName)
}

// GetProviderName returns the name of this provider.
func (o *OpenBaoProvider) GetProviderName() string {
	return "openbao"
}

// Close performs cleanup for the OpenBao provider.
func (o *OpenBaoProvider) Close() error {
	if o.backend == nil {
		return nil
	}

	if err := o.backend.Close(); err != nil {
		log.Printf("Error closing OpenBao provider: %v", err)
		return err
	}

	return nil
}
