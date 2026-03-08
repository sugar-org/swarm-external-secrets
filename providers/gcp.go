package providers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

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

	ctx := context.Background()
	var client *secretmanager.Client
	var err error

	// Support multiple authentication strategies
	if g.config.CredentialsJSON != "" {
		// nolint:staticcheck // SA1019: WithCredentialsJSON is deprecated but necessary for direct JSON input
		client, err = secretmanager.NewClient(ctx, option.WithCredentialsJSON([]byte(g.config.CredentialsJSON)))
	} else if g.config.CredentialsPath != "" {
		// nolint:staticcheck // SA1019: WithCredentialsFile is deprecated but necessary for path-based config
		client, err = secretmanager.NewClient(ctx, option.WithCredentialsFile(g.config.CredentialsPath))
	} else {
		// Fallback to Application Default Credentials (ADC)
		client, err = secretmanager.NewClient(ctx)
	}

	if err != nil {
		return fmt.Errorf("failed to create GCP secretmanager client: %w", err)
	}
	g.client = client

	log.Infof("Successfully initialized GCP Secret Manager provider for project: %s", g.config.ProjectID)
	return nil
}

// GetSecret retrieves a secret value from GCP Secret Manager
func (g *GCPProvider) GetSecret(ctx context.Context, req secrets.Request) ([]byte, error) {
	// Build the full secret name for GCP Secret Manager
	secretName, err := g.buildSecretName(req)
	if err != nil {
		return nil, fmt.Errorf("failed to build secret path: %v", err)
	}

	log.Infof("Reading secret from GCP Secret Manager: %s", secretName)

	secretRequest := &secretmanagerpb.AccessSecretVersionRequest{
		Name: secretName + "/versions/latest",
	}

	// Call the API to get the secret
	result, err := g.client.AccessSecretVersion(ctx, secretRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to access GCP secret version: %w", err)
	}

	if g.SupportsRotation() {
		log.Infof("Secret version for rotation tracking: %s", result.Name)
	}

	// Extract the specific field from the secret data
	secretData := result.Payload.Data
	extractedValue, err := g.extractSecretValue(string(secretData), req)
	if err != nil {
		return nil, fmt.Errorf("failed to extract secret value: %v", err)
	}

	return extractedValue, nil
}

// buildSecretName constructs the GCP secret name, handling partial or complete paths securely
func (g *GCPProvider) buildSecretName(req secrets.Request) (string, error) {
	projectID := g.config.ProjectID
	var secretName string

	if customPath, exists := req.SecretLabels["gcp_secret_name"]; exists {
		secretName = customPath
	} else {
		secretName = req.SecretName
		if req.ServiceName != "" {
			secretName = fmt.Sprintf("%s-%s", req.ServiceName, req.SecretName)
		}
	}

	if strings.HasPrefix(secretName, "projects/") && strings.Contains(secretName, "/secrets/") {
		return secretName, nil
	}

	if projectID == "" {
		return "", fmt.Errorf("GCP_PROJECT_ID is required but not configured. Cannot resolve short name: %s", secretName)
	}

	return fmt.Sprintf("projects/%s/secrets/%s", projectID, secretName), nil
}

// extractSecretValue extracts the appropriate value from the GCP secret string
func (g *GCPProvider) extractSecretValue(secretString string, req secrets.Request) ([]byte, error) {
	if field, exists := req.SecretLabels["gcp_field"]; exists {
		return g.extractSecretValueByField(secretString, field)
	}

	var data map[string]interface{}
	if err := json.Unmarshal([]byte(secretString), &data); err == nil {
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

		return nil, fmt.Errorf("no suitable secret value found in JSON")
	}

	return []byte(secretString), nil
}

// extractSecretValueByField extracts a specific field from the secret string
func (g *GCPProvider) extractSecretValueByField(secretString, field string) ([]byte, error) {
	var data map[string]interface{}
	if err := json.Unmarshal([]byte(secretString), &data); err == nil {
		if value, ok := data[field]; ok {
			return []byte(fmt.Sprintf("%v", value)), nil
		}
		keys := make([]string, 0, len(data))
		for k := range data {
			keys = append(keys, k)
		}
		return nil, fmt.Errorf("field %s not found in secret; available fields: %v", field, keys)
	}

	if field != "value" {
		return nil, fmt.Errorf("field %s not found in non-JSON secret", field)
	}

	return []byte(secretString), nil
}

func (g *GCPProvider) SupportsRotation() bool {
	return true
}

// CheckSecretChanged checks if a secret has changed in GCP Secret Manager
func (g *GCPProvider) CheckSecretChanged(ctx context.Context, secretInfo *SecretInfo) (bool, error) {
	secretName := secretInfo.SecretPath

	// Safety check: ensure driver.go passed us a fully formatted path
	if !strings.HasPrefix(secretName, "projects/") {
		secretName = fmt.Sprintf("projects/%s/secrets/%s", g.config.ProjectID, secretName)
	}

	secretRequest := &secretmanagerpb.AccessSecretVersionRequest{
		Name: secretName + "/versions/latest",
	}

	result, err := g.client.AccessSecretVersion(ctx, secretRequest)
	if err != nil {
		return false, fmt.Errorf("failed to access secret version: %w", err)
	}

	secretData := result.Payload.Data
	var extractedValue []byte

	if secretInfo.SecretField != "" {
		extractedValue, err = g.extractSecretValueByField(string(secretData), secretInfo.SecretField)
	} else {
		dummyReq := secrets.Request{
			SecretName:   secretInfo.DockerSecretName,
			SecretLabels: make(map[string]string),
		}
		extractedValue, err = g.extractSecretValue(string(secretData), dummyReq)
	}

	if err != nil {
		return false, fmt.Errorf("failed to extract secret value: %w", err)
	}

	currentHash := computeHash(extractedValue)

	if secretInfo.LastHash != currentHash {
		log.Infof("Secret %s has changed: hash mismatch", secretName)
		return true, nil
	}

	return false, nil
}

func (g *GCPProvider) GetProviderName() string {
	return "gcp"
}

func (g *GCPProvider) Close() error {
	if g.client != nil {
		return g.client.Close()
	}
	return nil
}

func computeHash(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}
