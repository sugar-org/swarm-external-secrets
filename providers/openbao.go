package providers

import (
	"context"
	"fmt"
	"path"

	"github.com/docker/go-plugins-helpers/secrets"
	log "github.com/sirupsen/logrus"

	"github.com/sugar-org/swarm-external-secrets/internal/kvpath"
	"github.com/sugar-org/swarm-external-secrets/internal/utils"
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
	val, err := o.backend.GetSecret(ctx, secretInfo)
	if err != nil {
		return nil, err
	}

	if utils.ShouldBase64Decode(secretInfo.Labels) {
		return utils.DecodeBase64Secret(val, secretInfo.DockerSecretName, secretInfo.SecretField)
	}

	return val, nil
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
func (o *OpenBaoProvider) BuildSecretPath(req secrets.Request) string {
	if customPath, exists := req.SecretLabels[o.config.PathLabel]; exists && customPath != "" {
		return kvpath.BuildMountedKVv2SecretPath(o.config.MountPath, customPath, "")
	}

	secretName := req.SecretName
	if req.ServiceName != "" {
		secretName = path.Join(req.ServiceName, req.SecretName)
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
