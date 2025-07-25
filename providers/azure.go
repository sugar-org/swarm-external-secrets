package providers

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/docker/go-plugins-helpers/secrets"
	log "github.com/sirupsen/logrus"
)

// AzureProvider implements the SecretsProvider interface for Azure Key Vault
// Note: This is a simplified implementation using HTTP client
type AzureProvider struct {
	config     *AzureConfig
	httpClient *http.Client
}

// AzureConfig holds the configuration for the Azure Key Vault client
type AzureConfig struct {
	VaultURL     string
	TenantID     string
	ClientID     string
	ClientSecret string
	AccessToken  string
}

// Initialize sets up the Azure provider with the given configuration
func (az *AzureProvider) Initialize(config map[string]string) error {
	az.config = &AzureConfig{
		VaultURL:     config["AZURE_VAULT_URL"],
		TenantID:     config["AZURE_TENANT_ID"],
		ClientID:     config["AZURE_CLIENT_ID"],
		ClientSecret: config["AZURE_CLIENT_SECRET"],
		AccessToken:  config["AZURE_ACCESS_TOKEN"], // Direct token for simplified auth
	}

	if az.config.VaultURL == "" {
		return fmt.Errorf("AZURE_VAULT_URL is required")
	}

	// Validate and normalize vault URL
	if !strings.HasPrefix(az.config.VaultURL, "https://") {
		az.config.VaultURL = "https://" + az.config.VaultURL
	}
	if !strings.HasSuffix(az.config.VaultURL, "/") {
		az.config.VaultURL += "/"
	}

	// Create HTTP client
	az.httpClient = &http.Client{
		Timeout: 30 * time.Second,
	}

	// Authenticate if we have credentials
	if az.config.AccessToken == "" && az.config.TenantID != "" && az.config.ClientID != "" && az.config.ClientSecret != "" {
		if err := az.authenticate(); err != nil {
			log.Warnf("Azure authentication failed: %v. You may need to provide AZURE_ACCESS_TOKEN directly", err)
		}
	}

	log.Printf("Successfully initialized Azure Key Vault provider for vault: %s", az.config.VaultURL)
	return nil
}

// GetSecret retrieves a secret value from Azure Key Vault
func (az *AzureProvider) GetSecret(ctx context.Context, req secrets.Request) ([]byte, error) {
	secretName := az.buildSecretName(req)
	log.Printf("Reading secret from Azure Key Vault: %s", secretName)

	// Build API URL
	apiURL := fmt.Sprintf("%ssecrets/%s?api-version=7.3", az.config.VaultURL, url.QueryEscape(secretName))

	// Create HTTP request
	httpReq, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %v", err)
	}

	// Add authorization header
	if az.config.AccessToken != "" {
		httpReq.Header.Set("Authorization", "Bearer "+az.config.AccessToken)
	} else {
		return nil, fmt.Errorf("no access token available for Azure authentication")
	}

	// Make request
	resp, err := az.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to get secret from Azure Key Vault: %v", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Errorf("failed to close response body: %v", err)
		}
	}()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("azure Key Vault returned status %d", resp.StatusCode)
	}

	// Parse response
	var result struct {
		Value string `json:"value"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode Azure response: %v", err)
	}

	// Extract the secret value
	value, err := az.extractSecretValue(result.Value, req)
	if err != nil {
		return nil, fmt.Errorf("failed to extract secret value: %v", err)
	}

	log.Printf("Successfully retrieved secret from Azure Key Vault")
	return value, nil
}

// SupportsRotation indicates that Azure Key Vault supports secret rotation monitoring
func (az *AzureProvider) SupportsRotation() bool {
	return true
}

// CheckSecretChanged checks if a secret has changed in Azure Key Vault
func (az *AzureProvider) CheckSecretChanged(ctx context.Context, secretInfo *SecretInfo) (bool, error) {
	// Build API URL
	apiURL := fmt.Sprintf("%ssecrets/%s?api-version=7.3", az.config.VaultURL, url.QueryEscape(secretInfo.SecretPath))

	// Create HTTP request
	httpReq, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return false, fmt.Errorf("failed to create HTTP request: %v", err)
	}

	// Add authorization header
	if az.config.AccessToken != "" {
		httpReq.Header.Set("Authorization", "Bearer "+az.config.AccessToken)
	} else {
		return false, fmt.Errorf("no access token available for Azure authentication")
	}

	// Make request
	resp, err := az.httpClient.Do(httpReq)
	if err != nil {
		return false, fmt.Errorf("error reading secret from Azure Key Vault: %v", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Errorf("failed to close response body: %v", err)
		}
	}()

	if resp.StatusCode != 200 {
		return false, fmt.Errorf("azure Key Vault returned status %d", resp.StatusCode)
	}

	// Parse response
	var result struct {
		Value string `json:"value"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return false, fmt.Errorf("failed to decode Azure response: %v", err)
	}

	// Extract current value
	currentValue, err := az.extractSecretValueByField(result.Value, secretInfo.SecretField)
	if err != nil {
		return false, fmt.Errorf("failed to extract secret field %s: %v", secretInfo.SecretField, err)
	}

	// Calculate current hash
	currentHash := fmt.Sprintf("%x", sha256.Sum256(currentValue))

	return currentHash != secretInfo.LastHash, nil
}

// GetProviderName returns the name of this provider
func (az *AzureProvider) GetProviderName() string {
	return "azure"
}

// Close performs cleanup for the Azure provider
func (az *AzureProvider) Close() error {
	// HTTP client doesn't require explicit cleanup
	return nil
}

// authenticate performs OAuth2 authentication with Azure
func (az *AzureProvider) authenticate() error {
	// OAuth2 endpoint for Azure
	tokenURL := fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", az.config.TenantID)

	// Prepare form data
	data := url.Values{}
	data.Set("grant_type", "client_credentials")
	data.Set("client_id", az.config.ClientID)
	data.Set("client_secret", az.config.ClientSecret)
	data.Set("scope", "https://vault.azure.net/.default")

	// Create request
	req, err := http.NewRequest("POST", tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return fmt.Errorf("failed to create auth request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Make request
	resp, err := az.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to authenticate with Azure: %v", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Errorf("failed to close response body: %v", err)
		}
	}()

	if resp.StatusCode != 200 {
		return fmt.Errorf("azure authentication failed with status %d", resp.StatusCode)
	}

	// Parse response
	var tokenResp struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return fmt.Errorf("failed to decode auth response: %v", err)
	}

	az.config.AccessToken = tokenResp.AccessToken
	return nil
}

// buildSecretName constructs the Azure secret name based on request labels and service information
func (az *AzureProvider) buildSecretName(req secrets.Request) string {
	// Use custom name from labels if provided
	if customName, exists := req.SecretLabels["azure_secret_name"]; exists {
		return customName
	}

	// Default naming convention (Azure Key Vault secret names must be valid)
	secretName := req.SecretName
	if req.ServiceName != "" {
		secretName = fmt.Sprintf("%s-%s", req.ServiceName, req.SecretName)
	}

	// Azure Key Vault secret names must match regex: ^[0-9a-zA-Z-]+$
	// Replace invalid characters with hyphens
	result := ""
	for _, char := range secretName {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') || char == '-' {
			result += string(char)
		} else {
			result += "-"
		}
	}

	// Remove consecutive hyphens and leading/trailing hyphens
	for strings.Contains(result, "--") {
		result = strings.ReplaceAll(result, "--", "-")
	}
	result = strings.Trim(result, "-")

	// Ensure name is not empty and doesn't start with a number
	if result == "" || (result[0] >= '0' && result[0] <= '9') {
		result = "secret-" + result
	}

	return result
}

// extractSecretValue extracts the appropriate value from the Azure secret string
func (az *AzureProvider) extractSecretValue(secretValue string, req secrets.Request) ([]byte, error) {
	// Check for specific field in labels
	if field, exists := req.SecretLabels["azure_field"]; exists {
		return az.extractSecretValueByField(secretValue, field)
	}

	// Try to parse as JSON first
	var data map[string]interface{}
	if err := json.Unmarshal([]byte(secretValue), &data); err == nil {
		// Default field names to try
		defaultFields := []string{"value", "password", "secret", "data"}

		// Try to find a value using default field names
		for _, field := range defaultFields {
			if value, ok := data[field]; ok {
				return []byte(fmt.Sprintf("%v", value)), nil
			}
		}

		// If no specific field found, return the first string value
		for _, value := range data {
			if strValue, ok := value.(string); ok {
				return []byte(strValue), nil
			}
		}

		return nil, fmt.Errorf("no suitable secret value found in JSON")
	}

	// If not JSON, return the raw string
	return []byte(secretValue), nil
}

// extractSecretValueByField extracts a specific field from the secret string
func (az *AzureProvider) extractSecretValueByField(secretValue, field string) ([]byte, error) {
	// Try to parse as JSON first
	var data map[string]interface{}
	if err := json.Unmarshal([]byte(secretValue), &data); err == nil {
		if value, ok := data[field]; ok {
			return []byte(fmt.Sprintf("%v", value)), nil
		}
		return nil, fmt.Errorf("field %s not found in secret", field)
	}

	// If not JSON and field is requested, return error
	if field != "value" {
		return nil, fmt.Errorf("field %s not found in non-JSON secret", field)
	}

	// If field is "value" and not JSON, return the raw string
	return []byte(secretValue), nil
}
