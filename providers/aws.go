package providers

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/docker/go-plugins-helpers/secrets"
	log "github.com/sirupsen/logrus"
	"github.com/sugar-org/vault-swarm-plugin/providers/types"
)

// AWSProvider implements the SecretsProvider interface for AWS Secrets Manager
type AWSProvider struct {
	client *secretsmanager.Client
	config *AWSConfig
}

// AWSConfig holds the configuration for the AWS Secrets Manager client
type AWSConfig struct {
	Region      string
	AccessKey   string
	SecretKey   string
	Profile     string
	EndpointURL string
}

// Initialize sets up the AWS provider with the given configuration
func (a *AWSProvider) Initialize(config map[string]string) error {
	a.config = &AWSConfig{
		Region:      getConfigOrDefault(config, "AWS_REGION", "us-east-1"),
		AccessKey:   config["AWS_ACCESS_KEY_ID"],
		SecretKey:   config["AWS_SECRET_ACCESS_KEY"],
		Profile:     config["AWS_PROFILE"],
		EndpointURL: config["AWS_ENDPOINT_URL"],
	}

	// Load AWS configuration
	cfg, err := a.loadAWSConfig()
	if err != nil {
		return fmt.Errorf("failed to load AWS config: %v", err)
	}

	// Create Secrets Manager client with optional endpoint override
	a.client = secretsmanager.NewFromConfig(cfg, func(o *secretsmanager.Options) {
		if a.config.EndpointURL != "" {
			o.BaseEndpoint = aws.String(a.config.EndpointURL)
		}
	})

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

// CheckSecretChanged checks if a secret has changed in AWS Secrets Manager.
//
// It uses the same value-extraction logic as GetSecret so that the hash
// comparison is always apples-to-apples:
//   - If a specific field was configured (aws_field label), use that field.
//   - Otherwise fall back to auto-detection (same priority list used by GetSecret).
//
// This fixes a mismatch where GetSecret would successfully find "password" via
// auto-detection but CheckSecretChanged would fail to find "value" (the default
// field name) in a JSON secret like {"password":"..."}, causing it to return
// (false, err) and silently skip rotation.
func (a *AWSProvider) CheckSecretChanged(ctx context.Context, secretInfo *types.SecretInfo) (bool, error) {
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

	var currentValue []byte

	// Use field-specific extraction only when a real field was explicitly
	// configured. The default sentinel "value" means "no label was set",
	// so fall back to auto-detection to mirror GetSecret behaviour.
	if secretInfo.SecretField != "" && secretInfo.SecretField != "value" {
		currentValue, err = a.extractSecretValueByField(*result.SecretString, secretInfo.SecretField)
		if err != nil {
			return false, fmt.Errorf("failed to extract secret field %s: %v", secretInfo.SecretField, err)
		}
	} else {
		currentValue, err = a.extractSecretValueAutoDetect(*result.SecretString)
		if err != nil {
			return false, fmt.Errorf("failed to extract secret value: %v", err)
		}
	}

	currentHash := fmt.Sprintf("%x", sha256.Sum256(currentValue))
	return currentHash != secretInfo.LastHash, nil
}

// GetProviderName returns the name of this provider
func (a *AWSProvider) GetProviderName() string {
	return "aws"
}

// Close performs cleanup for the AWS provider
func (a *AWSProvider) Close() error {
	// AWS client does not require explicit cleanup
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

	// Override with explicit credentials if provided.
	// The session token ("") is intentionally empty — only required for temporary STS credentials.
	if a.config.AccessKey != "" && a.config.SecretKey != "" {
		cfg.Credentials = credentials.NewStaticCredentialsProvider(
			a.config.AccessKey,
			a.config.SecretKey,
			"",
		)
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

// extractSecretValue extracts the appropriate value from the AWS secret string.
// When no specific field label is set, it delegates to auto-detection.
func (a *AWSProvider) extractSecretValue(secretString string, req secrets.Request) ([]byte, error) {
	if field, exists := req.SecretLabels["aws_field"]; exists {
		return a.extractSecretValueByField(secretString, field)
	}
	return a.extractSecretValueAutoDetect(secretString)
}

// extractSecretValueAutoDetect tries a priority list of common field names and
// falls back to the first string value found, then to the raw secret string.
// This is the shared logic used by both GetSecret and CheckSecretChanged when
// no explicit aws_field label is present.
func (a *AWSProvider) extractSecretValueAutoDetect(secretString string) ([]byte, error) {
	var data map[string]interface{}
	if err := json.Unmarshal([]byte(secretString), &data); err == nil {
		// Try common field names in priority order
		for _, field := range []string{"value", "password", "secret", "data"} {
			if v, ok := data[field]; ok {
				return []byte(fmt.Sprintf("%v", v)), nil
			}
		}
		// Fall back to first string value found
		for _, v := range data {
			if strVal, ok := v.(string); ok {
				return []byte(strVal), nil
			}
		}
		return nil, fmt.Errorf("no suitable secret value found in JSON")
	}
	// Not JSON — return raw string
	return []byte(secretString), nil
}

// extractSecretValueByField extracts a specific named field from the secret string
func (a *AWSProvider) extractSecretValueByField(secretString, field string) ([]byte, error) {
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

	// If not JSON and a specific field is requested, that's an error
	if field != "value" {
		return nil, fmt.Errorf("field %s not found in non-JSON secret", field)
	}

	// field == "value" on a non-JSON secret: return raw string
	return []byte(secretString), nil
}
