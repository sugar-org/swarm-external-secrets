package providers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"github.com/docker/go-plugins-helpers/secrets"
	log "github.com/sirupsen/logrus"
	"google.golang.org/api/option"
)

// GCPProvider implements the SecretsProvider interface for GCP Secret Manager
type GCPProvider struct {
	client *secretmanager.Client
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
	g.ctx = context.Background()
	g.config = &GCPConfig{
		ProjectID:       getConfigOrDefault(config, "GCP_PROJECT_ID", ""),
		CredentialsPath: getConfigOrDefault(config, "GOOGLE_APPLICATION_CREDENTIALS", ""),
		CredentialsJSON: config["GCP_CREDENTIALS_JSON"],
	}

	var client *secretmanager.Client
	var err error

	if g.config.CredentialsJSON != "" {
		client, err = secretmanager.NewClient(g.ctx, option.WithCredentialsJSON([]byte(g.config.CredentialsJSON)))
	} else if g.config.CredentialsPath != "" {
		client, err = secretmanager.NewClient(g.ctx, option.WithCredentialsFile(g.config.CredentialsPath))
	} else {
		// Try using Application Default Credentials
		client, err = secretmanager.NewClient(g.ctx)
	}

	if err != nil {
		return fmt.Errorf("failed to create secretmanager client: %w", err)
	}
	g.client = client

	log.Printf("Successfully initialized GCP Secret Manager provider for project: %s", g.config.ProjectID)
	return nil
}

// GetSecret retrieves a secret value from GCP Secret Manager
func (g *GCPProvider) GetSecret(ctx context.Context, req secrets.Request) ([]byte, error) {
	// Build the full secret name for GCP Secret Manager
	secretName := g.buildSecretName(req)
	log.Printf("Reading secret from GCP Secret Manager: %s", secretName)

	// Create the request to access the latest version of the secret
	secretRequest := &secretmanagerpb.AccessSecretVersionRequest{
		Name: secretName + "/versions/latest",
	}

	// Call the API to get the secret
	result, err := g.client.AccessSecretVersion(ctx, secretRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to access secret version: %w", err)
	}

	// Store version information for rotation tracking
	if g.SupportsRotation() {
		log.Printf("Secret version for rotation tracking: %s", result.Name)
	}

	// Extract the specific field from the secret data
	secretData := result.Payload.Data
	extractedValue, err := g.extractSecretValue(string(secretData), req)
	if err != nil {
		return nil, fmt.Errorf("failed to extract secret value: %v", err)
	}

	return extractedValue, nil
}

// buildSecretName constructs the GCP secret name based on request labels and service information
func (g *GCPProvider) buildSecretName(req secrets.Request) string {
	// Use custom path from labels if provided
	if customPath, exists := req.SecretLabels["gcp_secret_name"]; exists {
		return customPath
	}

	// Default naming convention: projects/{project}/secrets/{secret-name}
	projectID := g.config.ProjectID
	if projectID == "" {
		log.Fatal("GCP_PROJECT_ID is required but not configured. Please set the GCP_PROJECT_ID environment variable.")
	}

	secretName := req.SecretName
	if req.ServiceName != "" {
		secretName = fmt.Sprintf("%s-%s", req.ServiceName, req.SecretName)
	}

	return fmt.Sprintf("projects/%s/secrets/%s", projectID, secretName)
}

// extractSecretValue extracts the appropriate value from the GCP secret string
func (g *GCPProvider) extractSecretValue(secretString string, req secrets.Request) ([]byte, error) {
	// Check for specific field in labels
	if field, exists := req.SecretLabels["gcp_field"]; exists {
		return g.extractSecretValueByField(secretString, field)
	}

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
	return true
}

// CheckSecretChanged checks if a secret has changed in GCP Secret Manager
func (g *GCPProvider) CheckSecretChanged(ctx context.Context, secretInfo *SecretInfo) (bool, error) {
	secretName := secretInfo.SecretPath

	// Get the current secret value and compute its hash
	secretRequest := &secretmanagerpb.AccessSecretVersionRequest{
		Name: secretName + "/versions/latest",
	}

	result, err := g.client.AccessSecretVersion(ctx, secretRequest)
	if err != nil {
		return false, fmt.Errorf("failed to access secret version: %w", err)
	}

	// Extract the secret value using the same logic as GetSecret
	secretData := result.Payload.Data
	var extractedValue []byte

	if secretInfo.SecretField != "" {
		extractedValue, err = g.extractSecretValueByField(string(secretData), secretInfo.SecretField)
	} else {
		// Create a dummy request to use existing extraction logic
		dummyReq := secrets.Request{
			SecretName:   secretInfo.DockerSecretName,
			SecretLabels: make(map[string]string),
		}
		extractedValue, err = g.extractSecretValue(string(secretData), dummyReq)
	}

	if err != nil {
		return false, fmt.Errorf("failed to extract secret value: %w", err)
	}

	// Compute hash of current value
	currentHash := computeHash(extractedValue)

	// Compare with stored hash
	if secretInfo.LastHash != currentHash {
		log.Printf("Secret %s has changed: hash mismatch", secretName)
		return true, nil
	}

	return false, nil
}

// GetProviderName returns the name of this provider
func (g *GCPProvider) GetProviderName() string {
	return "gcp"
}

// Close performs cleanup for the GCP provider
func (g *GCPProvider) Close() error {
	if g.client != nil {
		return g.client.Close()
	}
	return nil
}

// computeHash computes SHA256 hash of the given data
func computeHash(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}
