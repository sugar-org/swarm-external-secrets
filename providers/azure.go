package providers

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os" // Imported to read environment variables
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore" // Imported for credentials
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
	"github.com/docker/go-plugins-helpers/secrets"
	log "github.com/sirupsen/logrus"
)

// AzureProvider implements the SecretsProvider interface for Azure Key Vault.
type AzureProvider struct {
	client *azsecrets.Client
	config *AzureConfig
}

// AzureConfig holds the configuration for the Azure Key Vault client.
type AzureConfig struct {
	VaultURL string
}

// SecretInfoAzure stores metadata about a retrieved secret for rotation checks.
type SecretInfoAzure struct {
	SecretPath  string
	SecretField string
	LastHash    string
}

// Initialize sets up the Azure provider with the given configuration.
func (az *AzureProvider) Initialize(config map[string]string) error {
	az.config = &AzureConfig{
		VaultURL: config["AZURE_VAULT_URL"],
	}

	if az.config.VaultURL == "" {
		return fmt.Errorf("AZURE_VAULT_URL is required in the configuration")
	}

	if !strings.HasSuffix(az.config.VaultURL, "/") {
		az.config.VaultURL += "/"
	}

	var cred azcore.TokenCredential
	var err error

	// Prioritize Service Principal credentials from environment variables.
	tenantID := os.Getenv("AZURE_TENANT_ID")
	clientID := os.Getenv("AZURE_CLIENT_ID")
	clientSecret := os.Getenv("AZURE_CLIENT_SECRET")

	if tenantID != "" && clientID != "" && clientSecret != "" {
		log.Info("Authenticating with Azure using Service Principal credentials.")
		cred, err = azidentity.NewClientSecretCredential(tenantID, clientID, clientSecret, nil)
		if err != nil {
			return fmt.Errorf("failed to create Azure credential using Service Principal: %w", err)
		}
	} else {
		// Fallback to default credential chain (Managed Identity, Azure CLI, etc.)
		log.Info("Service Principal credentials not found. Falling back to Default Azure Credential.")
		cred, err = azidentity.NewDefaultAzureCredential(nil)
		if err != nil {
			return fmt.Errorf("failed to create Azure credential using default chain: %w", err)
		}
	}

	// Create a new secret client to interact with the Key Vault.
	client, err := azsecrets.NewClient(az.config.VaultURL, cred, nil)
	if err != nil {
		return fmt.Errorf("failed to create Azure Key Vault client: %w", err)
	}
	az.client = client

	log.Infof("Successfully initialized Azure Key Vault provider for vault: %s", az.config.VaultURL)
	return nil
}

// GetSecret retrieves a secret value from Azure Key Vault based on the request.
func (az *AzureProvider) GetSecret(ctx context.Context, req secrets.Request) ([]byte, error) {
	secretName := az.buildSecretName(req)
	log.Infof("Reading secret '%s' from Azure Key Vault", secretName)

	resp, err := az.client.GetSecret(ctx, secretName, "", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get secret '%s' from Azure Key Vault: %w", secretName, err)
	}

	if resp.Value == nil {
		return nil, fmt.Errorf("secret '%s' was found but has no value", secretName)
	}

	value, err := az.extractSecretValue(*resp.Value, req)
	if err != nil {
		return nil, fmt.Errorf("failed to extract value from secret '%s': %w", secretName, err)
	}

	log.Infof("Successfully retrieved secret '%s' from Azure Key Vault", secretName)
	return value, nil
}

// SupportsRotation indicates that Azure Key Vault supports secret rotation monitoring.
func (az *AzureProvider) SupportsRotation() bool {
	return true
}

// GetProviderName returns the name of this provider
func (az *AzureProvider) GetProviderName() string {
	return "azure"
}

// CheckSecretChanged checks if a secret's value has changed in Azure Key Vault.
func (az *AzureProvider) CheckSecretChanged(ctx context.Context, secretInfo *SecretInfo) (bool, error) {
	resp, err := az.client.GetSecret(ctx, secretInfo.SecretPath, "", nil)
	if err != nil {
		return false, fmt.Errorf("error reading secret '%s' for rotation check: %w", secretInfo.SecretPath, err)
	}

	if resp.Value == nil {
		return false, fmt.Errorf("secret '%s' has no value for rotation check", secretInfo.SecretPath)
	}

	currentValue, err := az.extractSecretValueByField(*resp.Value, secretInfo.SecretField)
	if err != nil {
		return false, fmt.Errorf("failed to extract field '%s' for rotation check: %w", secretInfo.SecretField, err)
	}

	currentHash := fmt.Sprintf("%x", sha256.Sum256(currentValue))
	return currentHash != secretInfo.LastHash, nil
}

// Close performs cleanup for the Azure provider.
func (az *AzureProvider) Close() error {
	// The Azure SDK client does not require an explicit close operation.
	return nil
}

// buildSecretName constructs the Azure secret name based on request labels and service information.
func (az *AzureProvider) buildSecretName(req secrets.Request) string {
	if customName, exists := req.SecretLabels["azure_secret_name"]; exists {
		return customName
	}

	secretName := req.SecretName
	if req.ServiceName != "" {
		secretName = fmt.Sprintf("%s-%s", req.ServiceName, req.SecretName)
	}

	var sanitized strings.Builder
	for _, char := range secretName {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || char == '-' {
			sanitized.WriteRune(char)
		} else {
			sanitized.WriteRune('-')
		}
	}

	result := sanitized.String()
	for strings.Contains(result, "--") {
		result = strings.ReplaceAll(result, "--", "-")
	}
	result = strings.Trim(result, "-")

	if result == "" {
		result = "default-secret"
	}

	return result
}

// extractSecretValue extracts the appropriate value from the Azure secret string.
func (az *AzureProvider) extractSecretValue(secretValue string, req secrets.Request) ([]byte, error) {
	if field, exists := req.SecretLabels["azure_field"]; exists {
		return az.extractSecretValueByField(secretValue, field)
	}

	var data map[string]interface{}
	if err := json.Unmarshal([]byte(secretValue), &data); err == nil {
		defaultFields := []string{"value", "password", "secret", "data"}
		for _, field := range defaultFields {
			if value, ok := data[field]; ok {
				return []byte(fmt.Sprintf("%v", value)), nil
			}
		}

		for _, value := range data {
			if strValue, ok := value.(string); ok {
				return []byte(strValue), nil
			}
		}
		return nil, fmt.Errorf("secret is a JSON object but no suitable value could be extracted")
	}

	return []byte(secretValue), nil
}

// extractSecretValueByField extracts a specific field from a JSON secret string.
func (az *AzureProvider) extractSecretValueByField(secretValue, field string) ([]byte, error) {
	var data map[string]interface{}
	if err := json.Unmarshal([]byte(secretValue), &data); err != nil {
		return nil, fmt.Errorf("cannot extract field '%s' because the secret is not a valid JSON object", field)
	}

	if value, ok := data[field]; ok {
		return []byte(fmt.Sprintf("%v", value)), nil
	}

	return nil, fmt.Errorf("field '%s' not found in the JSON secret", field)
}
