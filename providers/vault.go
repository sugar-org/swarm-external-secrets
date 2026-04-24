package providers

import (
	"context"
	"fmt"
	"os"

	"github.com/docker/go-plugins-helpers/secrets"
	"github.com/hashicorp/vault/api"
	log "github.com/sirupsen/logrus"
)

// VaultProvider implements the SecretsProvider interface for HashiCorp Vault
type VaultProvider struct {
	client *api.Client
	config *SecretsConfig
}

// SecretsConfig holds the configuration for the Vault client
type SecretsConfig struct {
	Address    string
	Token      string
	MountPath  string
	RoleID     string
	SecretID   string
	AuthMethod string
	CACert     string
	ClientCert string
	ClientKey  string // #nosec G117
	SkipVerify bool
}

// Initialize sets up the Vault provider with the given configuration
func (v *VaultProvider) Initialize(config map[string]string) error {
	v.config = &SecretsConfig{
		Address:    getConfigOrDefault(config, "VAULT_ADDR", ""),
		Token:      getConfigOrDefault(config, "VAULT_TOKEN", ""),
		MountPath:  getConfigOrDefault(config, "VAULT_MOUNT_PATH", "secret"),
		RoleID:     config["VAULT_ROLE_ID"],
		SecretID:   config["VAULT_SECRET_ID"],
		AuthMethod: getConfigOrDefault(config, "VAULT_AUTH_METHOD", "token"),
		CACert:     config["VAULT_CACERT"],
		ClientCert: config["VAULT_CLIENT_CERT"],
		ClientKey:  config["VAULT_CLIENT_KEY"],
		SkipVerify: getConfigOrDefault(config, "VAULT_SKIP_VERIFY", "false") == "true",
	}

	// Configure Vault client
	SecretsConfig := api.DefaultConfig()
	SecretsConfig.Address = v.config.Address

	// Configure TLS if certificates are provided or verification is skipped
	if v.config.CACert != "" || v.config.ClientCert != "" || v.config.SkipVerify {
		tlsConfig := &api.TLSConfig{
			CACert:     v.config.CACert,
			ClientCert: v.config.ClientCert,
			ClientKey:  v.config.ClientKey,
			Insecure:   v.config.SkipVerify,
		}
		if err := SecretsConfig.ConfigureTLS(tlsConfig); err != nil {
			return fmt.Errorf("failed to configure TLS: %v", err)
		}
	}

	client, err := api.NewClient(SecretsConfig)
	if err != nil {
		return fmt.Errorf("failed to create vault client: %v", err)
	}

	v.client = client

	// Authenticate with Vault
	if err := v.authenticate(); err != nil {
		return fmt.Errorf("failed to authenticate with vault: %v", err)
	}

	log.Printf("Successfully initialized Vault provider using %s method", v.config.AuthMethod)
	return nil
}

// GetSecret retrieves a secret value from Vault
func (v *VaultProvider) GetSecret(ctx context.Context, secretInfo *SecretInfo) ([]byte, error) {
	log.Printf("Reading secret from Vault/OpenBao path: %s", secretInfo.SecretPath)

	// Read secret from Vault
	secret, err := v.client.Logical().ReadWithContext(ctx, secretInfo.SecretPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read secret from vault: %v", err)
	}

	if secret == nil {
		return nil, fmt.Errorf("secret not found at path: %s", secretInfo.SecretPath)
	}

	// Extract the secret value (unwraps KV v2 nested data if present)
	value, err := ExtractSecretValueFromKV(secret.Data, secretInfo.SecretField)
	if err != nil {
		return nil, fmt.Errorf("failed to extract secret value: %v", err)
	}

	log.Printf("Successfully retrieved secret from Vault")
	return value, nil
}

// SupportsRotation indicates that Vault supports secret rotation monitoring
func (v *VaultProvider) SupportsRotation() bool {
	return true
}

// GetSecretFieldLabel returns the label key used by Vault for the secret field
func (v *VaultProvider) GetSecretFieldLabel() string {
	return "vault_field"
}

// BuildSecretPath constructs the Vault secret path based on request labels and service information
func (v *VaultProvider) BuildSecretPath(req secrets.Request) string {
	// Use custom path from labels if provided
	if customPath, exists := req.SecretLabels["vault_path"]; exists {
		// For KV v2, ensure we have the /data/ prefix
		if v.config.MountPath == "secret" {
			return fmt.Sprintf("%s/data/%s", v.config.MountPath, customPath)
		}
		return fmt.Sprintf("%s/%s", v.config.MountPath, customPath)
	}

	// Default path structure for KV v2
	if v.config.MountPath == "secret" {
		if req.ServiceName != "" {
			return fmt.Sprintf("%s/data/%s/%s", v.config.MountPath, req.ServiceName, req.SecretName)
		}
		return fmt.Sprintf("%s/data/%s", v.config.MountPath, req.SecretName)
	}

	// For other mount paths
	if req.ServiceName != "" {
		return fmt.Sprintf("%s/%s/%s", v.config.MountPath, req.ServiceName, req.SecretName)
	}
	return fmt.Sprintf("%s/%s", v.config.MountPath, req.SecretName)
}

// GetProviderName returns the name of this provider
func (v *VaultProvider) GetProviderName() string {
	return "vault"
}

// Close performs cleanup for the Vault provider
func (v *VaultProvider) Close() error {
	// Vault client doesn't require explicit cleanup
	return nil
}

// authenticate handles various Vault authentication methods
func (v *VaultProvider) authenticate() error {
	switch v.config.AuthMethod {
	case "token":
		if v.config.Token == "" {
			return fmt.Errorf("VAULT_TOKEN is required for token authentication")
		}
		v.client.SetToken(v.config.Token)

	case "approle":
		if v.config.RoleID == "" || v.config.SecretID == "" {
			return fmt.Errorf("VAULT_ROLE_ID and VAULT_SECRET_ID are required for approle authentication")
		}

		data := map[string]interface{}{
			"role_id":   v.config.RoleID,
			"secret_id": v.config.SecretID,
		}

		resp, err := v.client.Logical().Write("auth/approle/login", data)
		if err != nil {
			return fmt.Errorf("approle authentication failed: %v", err)
		}

		if resp.Auth == nil {
			return fmt.Errorf("no auth info returned from approle login")
		}

		v.client.SetToken(resp.Auth.ClientToken)

	default:
		return fmt.Errorf("unsupported authentication method: %s", v.config.AuthMethod)
	}

	return nil
}

// getConfigOrDefault returns config value or environment variable or default
func getConfigOrDefault(config map[string]string, key, defaultValue string) string {
	if value, exists := config[key]; exists && value != "" {
		return value
	}
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
