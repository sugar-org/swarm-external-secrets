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
	case "oci", "oracle", "oci-vault":
		return &OCIProvider{}, nil
	case "infisical":
		return &InfisicalProvider{}, nil
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
		"oci",
		"infisical",
	}
}

// GetProviderInfo returns information about a specific provider
func GetProviderInfo(providerType string) (map[string]string, error) {
	info := make(map[string]string)

	switch strings.ToLower(providerType) {
	case "vault", "hashicorp-vault":
		info["name"] = "HashiCorp Vault"
		info["description"] = "HashiCorp Vault secrets engine"
		info["auth_methods"] = "token, approle, jwt"
		info["env_vars"] = "VAULT_ADDR, VAULT_TOKEN, VAULT_MOUNT_PATH, VAULT_AUTH_METHOD, VAULT_ROLE_ID, VAULT_SECRET_ID, VAULT_APPROLE_AUTH_PATH, VAULT_JWT_ROLE, VAULT_JWT, VAULT_JWT_FILE, VAULT_JWT_AUTH_PATH"

	case "aws", "aws-secrets-manager":
		info["name"] = "AWS Secrets Manager"
		info["description"] = "Amazon Web Services Secrets Manager"
		info["auth_methods"] = "IAM roles, access keys, profiles"
		info["env_vars"] = "AWS_REGION, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_PROFILE"

	case "gcp", "gcp-secret-manager", "google":
		info["name"] = "GCP Secret Manager"
		info["description"] = "Google Cloud Platform Secret Manager"
		info["auth_methods"] = "service account, ADC"
		info["env_vars"] = "GCP_PROJECT_ID, GOOGLE_APPLICATION_CREDENTIALS, GCP_CREDENTIALS_JSON, SECRET_MANAGER_EMULATOR_HOST, GCP_ENDPOINT"

	case "azure", "azure-key-vault":
		info["name"] = "Azure Key Vault"
		info["description"] = "Microsoft Azure Key Vault"
		info["auth_methods"] = "service principal, managed identity"
		info["env_vars"] = "AZURE_VAULT_URL, AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET"

	case "openbao":
		info["name"] = "OpenBao"
		info["description"] = "OpenBao secrets engine (Vault-compatible)"
		info["auth_methods"] = "token, approle, jwt"
		info["env_vars"] = "OPENBAO_ADDR, OPENBAO_TOKEN, OPENBAO_MOUNT_PATH, OPENBAO_AUTH_METHOD, OPENBAO_ROLE_ID, OPENBAO_SECRET_ID, OPENBAO_APPROLE_AUTH_PATH, OPENBAO_JWT_ROLE, OPENBAO_JWT, OPENBAO_JWT_FILE, OPENBAO_JWT_AUTH_PATH"

	case "oci", "oracle", "oci-vault":
		info["name"] = "OCI Vault"
		info["description"] = "Oracle Cloud Infrastructure Vault"
		info["auth_methods"] = "api_key, instance_principal"
		info["env_vars"] = "OCI_REGION, OCI_TENANCY_OCID, OCI_USER_OCID, OCI_FINGERPRINT, OCI_PRIVATE_KEY, OCI_PRIVATE_KEY_PASSPHRASE, OCI_VAULT_OCID, OCI_AUTH_METHOD, OCI_ENDPOINT"

	case "infisical":
		info["name"] = "Infisical"
		info["description"] = "Infisical secrets management platform"
		info["auth_methods"] = "universal auth (machine identity), access token"
		info["env_vars"] = "INFISICAL_TOKEN, INFISICAL_CLIENT_ID, INFISICAL_CLIENT_SECRET, INFISICAL_PROJECT_ID, INFISICAL_ENVIRONMENT, INFISICAL_SECRET_PATH, INFISICAL_SITE_URL"

	default:
		return nil, fmt.Errorf("unsupported provider type: %s", providerType)
	}

	return info, nil
}
