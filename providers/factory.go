package providers

import (
	"fmt"
	"strings"
)

// CreateProvider creates a new provider instance based on the provider type
func CreateProvider(providerType string) (SecretsProvider, error) {
	switch strings.ToLower(providerType) {
	case "vault", "hashicorp-vault":
		return &VaultProvider{}, nil
	case "aws", "aws-secrets-manager":
		return &AWSProvider{}, nil
	case "gcp", "gcp-secret-manager", "google":
		return &GCPProvider{}, nil
	case "azure", "azure-key-vault":
		return &AzureProvider{}, nil
	case "openbao":
		return &OpenBaoProvider{}, nil
	default:
		return nil, fmt.Errorf("unsupported provider type: %s", providerType)
	}
}

// GetSupportedProviders returns a list of supported provider types
func GetSupportedProviders() []string {
	return []string{
		"vault",
		"aws",
		"gcp",
		"azure",
		"openbao",
	}
}

// GetProviderInfo returns information about a specific provider
func GetProviderInfo(providerType string) (map[string]string, error) {
	info := make(map[string]string)

	switch strings.ToLower(providerType) {
	case "vault", "hashicorp-vault":
		info["name"] = "HashiCorp Vault"
		info["description"] = "HashiCorp Vault secrets engine"
		info["auth_methods"] = "token, approle"
		info["env_vars"] = "VAULT_ADDR, VAULT_TOKEN, VAULT_MOUNT_PATH, VAULT_AUTH_METHOD, VAULT_ROLE_ID, VAULT_SECRET_ID"

	case "aws", "aws-secrets-manager":
		info["name"] = "AWS Secrets Manager"
		info["description"] = "Amazon Web Services Secrets Manager"
		info["auth_methods"] = "IAM roles, access keys, profiles"
		info["env_vars"] = "AWS_REGION, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_PROFILE"

	case "gcp", "gcp-secret-manager", "google":
		info["name"] = "GCP Secret Manager"
		info["description"] = "Google Cloud Platform Secret Manager"
		info["auth_methods"] = "service account, ADC"
		info["env_vars"] = "GCP_PROJECT_ID, GOOGLE_APPLICATION_CREDENTIALS, GCP_CREDENTIALS_JSON"

	case "azure", "azure-key-vault":
		info["name"] = "Azure Key Vault"
		info["description"] = "Microsoft Azure Key Vault"
		info["auth_methods"] = "service principal, managed identity"
		info["env_vars"] = "AZURE_VAULT_URL, AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET"

	case "openbao":
		info["name"] = "OpenBao"
		info["description"] = "OpenBao secrets engine (Vault-compatible)"
		info["auth_methods"] = "token, approle"
		info["env_vars"] = "OPENBAO_ADDR, OPENBAO_TOKEN, OPENBAO_MOUNT_PATH, OPENBAO_AUTH_METHOD, OPENBAO_ROLE_ID, OPENBAO_SECRET_ID"

	default:
		return nil, fmt.Errorf("unsupported provider type: %s", providerType)
	}

	return info, nil
}
