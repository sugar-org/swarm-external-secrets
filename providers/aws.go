package providers

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
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
	Region      string
	AccessKey   string // #nosec G117
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
func (a *AWSProvider) GetSecret(ctx context.Context, secretInfo *SecretInfo) ([]byte, error) {
	log.Printf("Reading secret from AWS Secrets Manager: %s", secretInfo.SecretPath)

	// Get secret value from AWS Secrets Manager
	input := &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(secretInfo.SecretPath),
	}

	result, err := a.client.GetSecretValue(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("failed to get secret from AWS Secrets Manager: %v", err)
	}

	if result.SecretString == nil {
		return nil, fmt.Errorf("secret %s has no string value", secretInfo.SecretPath)
	}

	// Extract the secret value
	value, err := ExtractSecretValue(*result.SecretString, secretInfo.SecretField)
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

// GetSecretFieldLabel returns the label key used by AWS for the secret field
func (a *AWSProvider) GetSecretFieldLabel() string {
	return "aws_field"
}

// BuildSecretPath constructs the AWS secret name based on request labels and service information
func (a *AWSProvider) BuildSecretPath(req secrets.Request) string {
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

	// Override with explicit credentials if provided
	// The session token ("") is intentionally empty — only required for temporary STS credentials
	if a.config.AccessKey != "" && a.config.SecretKey != "" {
		cfg.Credentials = credentials.NewStaticCredentialsProvider(
			a.config.AccessKey,
			a.config.SecretKey,
			"",
		)
	}

	return cfg, nil
}
