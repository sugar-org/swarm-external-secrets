package providers

import (
	"context"
	"encoding/json"
	"fmt"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"github.com/docker/go-plugins-helpers/secrets"
	log "github.com/sirupsen/logrus"
	"google.golang.org/api/option"
)

// GCPProvider implements the SecretsProvider interface for GCP Secret Manager
// Note: This is a placeholder implementation
type GCPProvider struct {
	client secretmanager.Client
	config *GCPConfig
	ctx    context.Context
}

// GCPConfig holds the configuration for the GCP Secret Manager client
type GCPConfig struct {
	ProjectID       string
	CredentialsPath string
	CredentialsJSON string
}

// Initialize sets up the GCP provider with the given configuration
func (g *GCPProvider) Initialize(config map[string]string) error {
	g.config = &GCPConfig{
		ProjectID:       getConfigOrDefault(config, "GCP_PROJECT_ID", ""),
		CredentialsPath: getConfigOrDefault(config, "GOOGLE_APPLICATION_CREDENTIALS", ""),
		CredentialsJSON: config["GCP_CREDENTIALS_JSON"],
	}

	// if g.config.ProjectID == "" {
	// 	return fmt.Errorf("GCP_PROJECT_ID is required")
	// }

	var client *secretmanager.Client
	var err error

	if g.config.CredentialsJSON != "" {
		client, err = secretmanager.NewClient(g.ctx, option.WithCredentialsJSON([]byte(g.config.CredentialsJSON)))
	} else if g.config.CredentialsPath != "" {
		client, err = secretmanager.NewClient(g.ctx, option.WithCredentialsFile(g.config.CredentialsPath))
	} else {
		return fmt.Errorf("either GCP_CREDENTIALS_JSON or GOOGLE_APPLICATION_CREDENTIALS must be provided, or rely on Application Default Credentials")
	}

	if err != nil {
		return fmt.Errorf("failed to create secretmanager client: %w", err)
	}
	g.client = *client

	log.Printf("Successfully initialized GCP Secret Manager provider for project: %s (placeholder)", g.config.ProjectID)
	return nil
}

// GetSecret retrieves a secret value from GCP Secret Manager
func (g *GCPProvider) GetSecret(ctx context.Context, req secrets.Request) ([]byte, error) {

	// Extract secert field and name
	secretName := g.buildSecretName(req)
	log.Printf("Reading secret from GCP Secret Manager: %s", secretName)

	secertField, err := g.extractSecretValue(secretName, req)

	if err != nil {
		return nil, fmt.Errorf("failed to extract secret value: %v", err)
	}

	secertrequest := &secretmanagerpb.AccessSecretVersionRequest{
		Name: secretName + "/" + string(secertField),
	}

	// Call the API.
	result, err := g.client.AccessSecretVersion(ctx, secertrequest)
	if err != nil {
		return nil, fmt.Errorf("failed to access secret version: %w", err)
	}

	return result.Payload.Data, nil
}

// buildSecretName constructs the GCP secret name based on request labels and service information
func (g *GCPProvider) buildSecretName(req secrets.Request) string {
	// Use custom path from labels if provided
	if customPath, exists := req.SecretLabels["gcp_secret_name"]; exists {
		return customPath
	}

	// Default naming convention
	if req.ServiceName != "" {
		return fmt.Sprintf("%s/%s", req.ServiceName, req.SecretName)
	}
	return req.SecretName
}

// extractSecretValue extracts the appropriate value from the GCP secret string
func (g *GCPProvider) extractSecretValue(secretString string, req secrets.Request) ([]byte, error) {
	// Check for specific field in labels
	if field, exists := req.SecretLabels["gcp_field"]; exists {
		return g.extractSecretValueByField(secretString, field)
	}

	// Try to parse as JSON first
	var data map[string]interface{}
	if err := json.Unmarshal([]byte(secretString), &data); err == nil {
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
	return []byte(secretString), nil
}

// extractSecretValueByField extracts a specific field from the secret string
func (g *GCPProvider) extractSecretValueByField(secretString, field string) ([]byte, error) {
	// Try to parse as JSON first
	var data map[string]interface{}
	if err := json.Unmarshal([]byte(secretString), &data); err == nil {
		if value, ok := data[field]; ok {
			return []byte(fmt.Sprintf("%v", value)), nil
		}
		// Improved error message: show available keys
		keys := make([]string, 0, len(data))
		for k := range data {
			keys = append(keys, k)
		}
		return nil, fmt.Errorf("field %s not found in secret; available fields: %v", field, keys)
	}

	// If not JSON and field is requested, return error
	if field != "value" {
		return nil, fmt.Errorf("field %s not found in non-JSON secret", field)
	}

	// If field is "value" and not JSON, return the raw string
	return []byte(secretString), nil
}

// SupportsRotation indicates that GCP Secret Manager supports secret rotation monitoring
func (g *GCPProvider) SupportsRotation() bool {
	return false // Disabled for now
}

// CheckSecretChanged checks if a secret has changed in GCP Secret Manager
func (g *GCPProvider) CheckSecretChanged(ctx context.Context, secretInfo *SecretInfo) (bool, error) {
	return false, fmt.Errorf("GCP provider is not yet implemented")
}

// GetProviderName returns the name of this provider
func (g *GCPProvider) GetProviderName() string {
	return "gcp"
}

// Close performs cleanup for the GCP provider
func (g *GCPProvider) Close() error {
	return nil
}
