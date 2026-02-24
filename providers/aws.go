package providers

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/docker/go-plugins-helpers/secrets"
	log "github.com/sirupsen/logrus"
)

// AWSProvider implements the SecretsProvider interface for AWS Secrets Manager
type AWSProvider struct {
	client *secretsmanager.Client
	config *AWSConfig
}

// AWSConfig holds the configuration for the AWS Secrets Manager client
type AWSConfig struct {
	Region    string
	accessKey string
	secretKey string
	Profile   string
}

// Initialize sets up the AWS provider with the given configuration
func (a *AWSProvider) Initialize(config map[string]string) error {
	a.config = &AWSConfig{
		Region:    getConfigOrDefault(config, "AWS_REGION", "us-east-1"),
		accessKey: config["AWS_ACCESS_KEY_ID"],
		secretKey: config["AWS_SECRET_ACCESS_KEY"],
		Profile:   config["AWS_PROFILE"],
	}

	// Load AWS configuration
	cfg, err := a.loadAWSConfig()
	if err != nil {
		return fmt.Errorf("failed to load AWS config: %v", err)
	}

	// Create Secrets Manager client
	a.client = secretsmanager.NewFromConfig(cfg)

	log.Printf("Successfully initialized AWS Secrets Manager provider for region: %s", a.config.Region)
	return nil
}

// GetSecret retrieves a secret value from AWS Secrets Manager
func (a *AWSProvider) GetSecret(ctx context.Context, req secrets.Request) ([]byte, error) {
	secretName := a.buildSecretName(req)
	log.Printf("Reading secret from AWS Secrets Manager: %s", secretName)

	// Get secret value from AWS Secrets Manager
	input := &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(secretName),
	}

	result, err := a.client.GetSecretValue(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("failed to get secret from AWS Secrets Manager: %v", err)
	}

	if result.SecretString == nil {
		return nil, fmt.Errorf("secret %s has no string value", secretName)
	}

	// Extract the secret value
	value, err := a.extractSecretValue(*result.SecretString, req)
	if err != nil {
		return nil, fmt.Errorf("failed to extract secret value: %v", err)
	}

	log.Printf("Successfully retrieved secret from AWS Secrets Manager")
	return value, nil
}

// SupportsRotation indicates that AWS Secrets Manager supports secret rotation monitoring
func (a *AWSProvider) SupportsRotation() bool {
	return true
}

// CheckSecretChanged checks if a secret has changed in AWS Secrets Manager
func (a *AWSProvider) CheckSecretChanged(ctx context.Context, secretInfo *SecretInfo) (bool, error) {
	// Get secret value from AWS Secrets Manager
	input := &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(secretInfo.SecretPath),
	}

	result, err := a.client.GetSecretValue(ctx, input)
	if err != nil {
		return false, fmt.Errorf("error reading secret from AWS Secrets Manager: %v", err)
	}

	if result.SecretString == nil {
		return false, fmt.Errorf("secret %s has no string value", secretInfo.SecretPath)
	}

	// Extract current value
	currentValue, err := a.extractSecretValueByField(*result.SecretString, secretInfo.SecretField)
	if err != nil {
		return false, fmt.Errorf("failed to extract secret field %s: %v", secretInfo.SecretField, err)
	}

	// Calculate current hash
	currentHash := fmt.Sprintf("%x", sha256.Sum256(currentValue))

	return currentHash != secretInfo.LastHash, nil
}

// GetProviderName returns the name of this provider
func (a *AWSProvider) GetProviderName() string {
	return "aws"
}

// Close performs cleanup for the AWS provider
func (a *AWSProvider) Close() error {
	// AWS client doesn't require explicit cleanup
	return nil
}

// loadAWSConfig loads AWS configuration from various sources
func (a *AWSProvider) loadAWSConfig() (aws.Config, error) {
	var opts []func(*config.LoadOptions) error

	// Set region if provided
	if a.config.Region != "" {
		opts = append(opts, config.WithRegion(a.config.Region))
	}

	// Set profile if provided
	if a.config.Profile != "" {
		opts = append(opts, config.WithSharedConfigProfile(a.config.Profile))
	}

	// Load configuration
	cfg, err := config.LoadDefaultConfig(context.TODO(), opts...)
	if err != nil {
		return aws.Config{}, err
	}

	// Override with explicit credentials if provided
	if a.config.accessKey != "" && a.config.secretKey != "" {
		cfg.Credentials = aws.CredentialsProviderFunc(func(ctx context.Context) (aws.Credentials, error) {
			return aws.Credentials{
				AccessKeyID:     a.config.accessKey,
				SecretAccessKey: a.config.secretKey,
			}, nil
		})
	}

	return cfg, nil
}

// buildSecretName constructs the AWS secret name based on request labels and service information
func (a *AWSProvider) buildSecretName(req secrets.Request) string {
	// Use custom path from labels if provided
	if customPath, exists := req.SecretLabels["aws_secret_name"]; exists {
		return customPath
	}

	// Default naming convention
	if req.ServiceName != "" {
		return fmt.Sprintf("%s/%s", req.ServiceName, req.SecretName)
	}
	return req.SecretName
}

// extractSecretValue extracts the appropriate value from the AWS secret string
func (a *AWSProvider) extractSecretValue(secretString string, req secrets.Request) ([]byte, error) {
	// Check for specific field in labels
	if field, exists := req.SecretLabels["aws_field"]; exists {
		return a.extractSecretValueByField(secretString, field)
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
func (a *AWSProvider) extractSecretValueByField(secretString, field string) ([]byte, error) {
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
