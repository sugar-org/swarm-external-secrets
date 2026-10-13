package providers

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/docker/go-plugins-helpers/secrets"
	log "github.com/sirupsen/logrus"

	"github.com/sugar-org/swarm-external-secrets/internal/spiffesource"
	"github.com/sugar-org/swarm-external-secrets/internal/utils"
)

const (
	awsAuthMethodSPIFFE    = "spiffe"
	awsAuthMethodStatic    = "static"
	defaultAWSJWTAudience  = "swarm-external-secrets"
	defaultSPIFFEEndpoint  = "unix:///run/host/spire/agent-sockets/api.sock"
	awsRoleSessionName     = "swarm-external-secrets"
	awsConfigLoadTimeout   = 30 * time.Second
	spiffeCredentialSource = "SPIFFEWebIdentity" // #nosec G101 -- AWS SDK source label, not a credential.
)

type identityTokenFetcher interface {
	FetchIdentityToken(ctx context.Context) ([]byte, error)
}

type webIdentityRoleAssumer interface {
	AssumeRoleWithWebIdentity(
		ctx context.Context,
		params *sts.AssumeRoleWithWebIdentityInput,
		optFns ...func(*sts.Options),
	) (*sts.AssumeRoleWithWebIdentityOutput, error)
}

type spiffeCredentialsProvider struct {
	client      webIdentityRoleAssumer
	tokenSource identityTokenFetcher
	roleARN     string
}

func (p *spiffeCredentialsProvider) Retrieve(ctx context.Context) (aws.Credentials, error) {
	token, err := p.tokenSource.FetchIdentityToken(ctx)
	if err != nil {
		return aws.Credentials{}, fmt.Errorf("failed to retrieve JWT-SVID: %w", err)
	}

	result, err := p.client.AssumeRoleWithWebIdentity(ctx, &sts.AssumeRoleWithWebIdentityInput{
		RoleArn:          aws.String(p.roleARN),
		RoleSessionName:  aws.String(awsRoleSessionName),
		WebIdentityToken: aws.String(string(token)),
	})
	if err != nil {
		return aws.Credentials{}, fmt.Errorf("failed to assume AWS role with SPIFFE identity: %w", err)
	}
	if result.Credentials == nil {
		return aws.Credentials{}, fmt.Errorf("AWS STS returned no credentials")
	}

	return aws.Credentials{
		AccessKeyID:     aws.ToString(result.Credentials.AccessKeyId),
		SecretAccessKey: aws.ToString(result.Credentials.SecretAccessKey),
		SessionToken:    aws.ToString(result.Credentials.SessionToken),
		Source:          spiffeCredentialSource,
		CanExpire:       true,
		Expires:         aws.ToTime(result.Credentials.Expiration),
	}, nil
}

// AWSProvider implements the SecretsProvider interface for AWS Secrets Manager
type AWSProvider struct {
	client      *secretsmanager.Client
	config      *AWSConfig
	tokenSource *spiffesource.TokenSource
}

// AWSConfig holds the configuration for the AWS Secrets Manager client
type AWSConfig struct {
	Region       string
	AccessKey    string // #nosec G117
	SecretKey    string
	Profile      string
	EndpointURL  string
	AuthMethod   string
	RoleARN      string
	JWTAudience  string
	SPIFFESocket string
	STSEndpoint  string
}

// Initialize sets up the AWS provider with the given configuration
func (a *AWSProvider) Initialize(settings map[string]string) error {
	a.config = &AWSConfig{
		Region:       utils.GetConfigOrDefault(settings, "AWS_REGION", "us-east-1"),
		AccessKey:    utils.GetConfigOrDefault(settings, "AWS_ACCESS_KEY_ID", ""),
		SecretKey:    utils.GetConfigOrDefault(settings, "AWS_SECRET_ACCESS_KEY", ""),
		Profile:      utils.GetConfigOrDefault(settings, "AWS_PROFILE", ""),
		EndpointURL:  utils.GetConfigOrDefault(settings, "AWS_ENDPOINT_URL", ""),
		AuthMethod:   strings.ToLower(utils.GetConfigOrDefault(settings, "AWS_AUTH_METHOD", "")),
		RoleARN:      utils.GetConfigOrDefault(settings, "AWS_ROLE_ARN", ""),
		JWTAudience:  utils.GetConfigOrDefault(settings, "AWS_JWT_AUDIENCE", defaultAWSJWTAudience),
		SPIFFESocket: utils.GetConfigOrDefault(settings, "SPIFFE_ENDPOINT_SOCKET", defaultSPIFFEEndpoint),
		STSEndpoint:  utils.GetConfigOrDefault(settings, "AWS_STS_ENDPOINT_URL", ""),
	}

	if err := a.validateConfig(); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), awsConfigLoadTimeout)
	defer cancel()

	cfg, err := a.loadAWSConfig(ctx)
	if err != nil {
		_ = a.Close()
		return fmt.Errorf("failed to load AWS config: %w", err)
	}

	a.client = secretsmanager.NewFromConfig(cfg, func(o *secretsmanager.Options) {
		if a.config.EndpointURL != "" {
			o.BaseEndpoint = aws.String(a.config.EndpointURL)
		}
	})

	log.Infof("Successfully initialized AWS Secrets Manager provider for region: %s", a.config.Region)
	return nil
}

// GetSecret retrieves a secret value from AWS Secrets Manager
func (a *AWSProvider) GetSecret(ctx context.Context, secretInfo *SecretInfo) ([]byte, error) {
	log.Debugf("Reading secret from AWS Secrets Manager: %s", secretInfo.SecretPath)

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

	log.Debug("Successfully retrieved secret from AWS Secrets Manager")
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
	if a.tokenSource != nil {
		return a.tokenSource.Close()
	}
	return nil
}

// loadAWSConfig loads AWS configuration from various sources
func (a *AWSProvider) loadAWSConfig(ctx context.Context) (aws.Config, error) {
	var opts []func(*config.LoadOptions) error

	if a.config.Region != "" {
		opts = append(opts, config.WithRegion(a.config.Region))
	}

	if a.config.Profile != "" {
		opts = append(opts, config.WithSharedConfigProfile(a.config.Profile))
	}

	cfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return aws.Config{}, err
	}

	if a.config.AuthMethod == awsAuthMethodSPIFFE {
		credentialProvider, err := a.buildSPIFFECredentials(cfg)
		if err != nil {
			return aws.Config{}, err
		}
		cfg.Credentials = credentialProvider
		return cfg, nil
	}

	if a.config.AccessKey != "" && a.config.SecretKey != "" {
		cfg.Credentials = credentials.NewStaticCredentialsProvider(
			a.config.AccessKey,
			a.config.SecretKey,
			"",
		)
	}

	return cfg, nil
}

func (a *AWSProvider) validateConfig() error {
	switch a.config.AuthMethod {
	case "", awsAuthMethodStatic, awsAuthMethodSPIFFE:
	default:
		return fmt.Errorf("unsupported AWS_AUTH_METHOD %q", a.config.AuthMethod)
	}

	hasAccessKey := a.config.AccessKey != ""
	hasSecretKey := a.config.SecretKey != ""
	if hasAccessKey != hasSecretKey {
		return fmt.Errorf("AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY must be set together")
	}

	if a.config.AuthMethod == awsAuthMethodStatic && !hasAccessKey {
		return fmt.Errorf("AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY are required for static authentication")
	}
	if a.config.AuthMethod != awsAuthMethodSPIFFE {
		return nil
	}

	if a.config.RoleARN == "" {
		return fmt.Errorf("AWS_ROLE_ARN is required for spiffe authentication")
	}
	if hasAccessKey {
		return fmt.Errorf("AWS_ACCESS_KEY_ID must not be set when AWS_AUTH_METHOD=spiffe")
	}
	if a.config.Profile != "" {
		return fmt.Errorf("AWS_PROFILE must not be set when AWS_AUTH_METHOD=spiffe")
	}
	return nil
}

func (a *AWSProvider) buildSPIFFECredentials(cfg aws.Config) (aws.CredentialsProvider, error) {
	tokenSource, err := spiffesource.New(a.config.SPIFFESocket, a.config.JWTAudience)
	if err != nil {
		return nil, err
	}
	a.tokenSource = tokenSource

	stsClient := sts.NewFromConfig(cfg, func(o *sts.Options) {
		// AssumeRoleWithWebIdentity does not require AWS SigV4 credentials.
		o.Credentials = aws.AnonymousCredentials{}
		if a.config.STSEndpoint != "" {
			o.BaseEndpoint = aws.String(a.config.STSEndpoint)
		}
	})
	provider := &spiffeCredentialsProvider{
		client:      stsClient,
		tokenSource: tokenSource,
		roleARN:     a.config.RoleARN,
	}
	return aws.NewCredentialsCache(provider), nil
}
