package providers

import (
	"fmt"

	log "github.com/sirupsen/logrus"

	"github.com/sugar-org/swarm-external-secrets/internal/vaultcompat"
)

// OpenBaoProvider implements the SecretsProvider interface for OpenBao.
type OpenBaoProvider struct {
	VaultProvider
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
