package providers

import (
	"context"
	"fmt"
	"strings"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"github.com/docker/go-plugins-helpers/secrets"
	log "github.com/sirupsen/logrus"
	"google.golang.org/api/option"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/sugar-org/swarm-external-secrets/internal/utils"
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
	// EmulatorHost is host:port for a local emulator (floci-gcp). When set,
	// the client skips Google auth and dials plaintext gRPC.
	EmulatorHost string
}

// Initialize sets up the GCP provider with the given configuration
func (g *GCPProvider) Initialize(config map[string]string) error {
	g.config = &GCPConfig{
		ProjectID:       utils.GetConfigOrDefault(config, "GCP_PROJECT_ID", ""),
		CredentialsPath: utils.GetConfigOrDefault(config, "GOOGLE_APPLICATION_CREDENTIALS", ""),
		CredentialsJSON: config["GCP_CREDENTIALS_JSON"],
		EmulatorHost:    emulatorHostFromConfig(config),
	}

	if g.config.ProjectID == "" {
		return fmt.Errorf("GCP_PROJECT_ID is required in the configuration")
	}

	ctx := context.Background()
	var client *secretmanager.Client
	var err error

	switch {
	case g.config.EmulatorHost != "":
		// floci-gcp (and the official emulator) speak plaintext gRPC and do not
		// validate credentials. SECRET_MANAGER_EMULATOR_HOST is the documented env.
		log.Infof("Connecting to GCP Secret Manager emulator at %s", g.config.EmulatorHost)
		client, err = secretmanager.NewClient(ctx,
			option.WithEndpoint(g.config.EmulatorHost),
			option.WithoutAuthentication(),
			option.WithTelemetryDisabled(),
			option.WithGRPCDialOption(grpc.WithTransportCredentials(insecure.NewCredentials())),
		)
	case g.config.CredentialsJSON != "":
		client, err = secretmanager.NewClient(ctx, option.WithAuthCredentialsJSON(option.ServiceAccount, []byte(g.config.CredentialsJSON)))
	case g.config.CredentialsPath != "":
		client, err = secretmanager.NewClient(ctx, option.WithAuthCredentialsFile(option.ServiceAccount, g.config.CredentialsPath))
	default:
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

func emulatorHostFromConfig(config map[string]string) string {
	host := utils.GetConfigOrDefault(config, "SECRET_MANAGER_EMULATOR_HOST", "")
	if host == "" {
		host = utils.GetConfigOrDefault(config, "GCP_ENDPOINT", "")
	}
	host = strings.TrimPrefix(host, "http://")
	host = strings.TrimPrefix(host, "https://")
	return host
}

// GetSecret retrieves a secret value from GCP Secret Manager
func (g *GCPProvider) GetSecret(ctx context.Context, secretInfo *SecretInfo) ([]byte, error) {
	secretName := secretInfo.SecretPath
	log.Debugf("Reading secret from GCP Secret Manager: %s", secretName)

	// Check if the secret name already contains a version path
	var secretPath string
	if strings.Contains(secretName, "/versions/") {
		// Use the provided version path directly
		secretPath = secretName
	} else {
		// Append /versions/latest to access the latest version
		secretPath = secretName + "/versions/latest"
	}

	// Create the request to access the secret version
	secretRequest := &secretmanagerpb.AccessSecretVersionRequest{
		Name: secretPath,
	}

	// Call the API to get the secret
	result, err := g.client.AccessSecretVersion(ctx, secretRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to access secret version: %w", err)
	}

	// Store version information for rotation tracking
	if g.SupportsRotation() {
		log.Debugf("Secret version for rotation tracking: %s", result.Name)
	}

	// Extract the specific field from the secret data
	secretData := result.Payload.Data
	extractedValue, err := ExtractSecretValue(string(secretData), secretInfo.SecretField)
	if err != nil {
		return nil, fmt.Errorf("failed to extract secret value: %v", err)
	}

	return extractedValue, nil
}

// BuildSecretPath constructs the GCP secret name, handling partial or complete paths securely.
func (g *GCPProvider) BuildSecretPath(req secrets.Request) string {
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
		return secretName
	}

	return fmt.Sprintf("projects/%s/secrets/%s", projectID, secretName)
}

// SupportsRotation indicates that GCP Secret Manager supports secret rotation monitoring
func (g *GCPProvider) SupportsRotation() bool {
	return true
}

// GetSecretFieldLabel returns the label key used by GCP for the secret field
func (g *GCPProvider) GetSecretFieldLabel() string {
	return "gcp_field"
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
