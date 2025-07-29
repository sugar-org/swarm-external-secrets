package providers

import (
	"context"
	"time"

	"github.com/docker/go-plugins-helpers/secrets"
)

// SecretInfo tracks information about secrets being managed
type SecretInfo struct {
	DockerSecretName string
	SecretPath       string
	SecretField      string
	ServiceNames     []string
	LastHash         string // Hash of the secret value for change detection
	LastUpdated      time.Time
	Provider         string // Which provider manages this secret
}

// SecretsProvider defines the interface that all secret providers must implement
type SecretsProvider interface {
	// Initialize sets up the provider with the given configuration
	Initialize(config map[string]string) error

	// GetSecret retrieves a secret value from the provider
	GetSecret(ctx context.Context, req secrets.Request) ([]byte, error)

	// SupportsRotation indicates if this provider supports secret rotation monitoring
	SupportsRotation() bool

	// CheckSecretChanged checks if a secret has changed since last retrieval
	CheckSecretChanged(ctx context.Context, secretInfo *SecretInfo) (bool, error)

	// GetProviderName returns the name of this provider
	GetProviderName() string

	// Close performs any cleanup needed by the provider
	Close() error
}

// ProviderConfig holds common configuration for all providers
type ProviderConfig struct {
	ProviderType     string            `json:"provider_type"`
	EnableRotation   bool              `json:"enable_rotation"`
	RotationInterval time.Duration     `json:"rotation_interval"`
	Settings         map[string]string `json:"settings"`
}
