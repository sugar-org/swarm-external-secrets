package providers

import (
	"context"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"

	"github.com/docker/go-plugins-helpers/secrets"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/common/auth"
	ocisecrets "github.com/oracle/oci-go-sdk/v65/secrets"
	log "github.com/sirupsen/logrus"
)

// OCIProvider implements the SecretsProvider interface for Oracle Cloud Infrastructure Vault
type OCIProvider struct {
	client ocisecrets.SecretsClient
	config *OCIConfig
}

// OCIConfig holds the configuration for the OCI Vault client
type OCIConfig struct {
	Region               string
	TenancyOCID          string
	UserOCID             string
	Fingerprint          string
	PrivateKey           string // #nosec G117 -- internal config struct, never serialized
	PrivateKeyPassphrase string
	VaultOCID            string
	AuthMethod           string // "api_key", "instance_principal"
}

// Initialize sets up the OCI provider with the given configuration
func (o *OCIProvider) Initialize(config map[string]string) error {
	o.config = &OCIConfig{
		Region:               getConfigOrDefault(config, "OCI_REGION", ""),
		TenancyOCID:          config["OCI_TENANCY_OCID"],
		UserOCID:             config["OCI_USER_OCID"],
		Fingerprint:          config["OCI_FINGERPRINT"],
		PrivateKey:           config["OCI_PRIVATE_KEY"],
		PrivateKeyPassphrase: config["OCI_PRIVATE_KEY_PASSPHRASE"],
		VaultOCID:            config["OCI_VAULT_OCID"],
		AuthMethod:           getConfigOrDefault(config, "OCI_AUTH_METHOD", "api_key"),
	}

	// Build the configuration provider based on auth method
	configProvider, err := o.buildConfigProvider()
	if err != nil {
		return fmt.Errorf("failed to build OCI config provider: %w", err)
	}

	// Create Secrets client
	client, err := ocisecrets.NewSecretsClientWithConfigurationProvider(configProvider)
	if err != nil {
		return fmt.Errorf("failed to create OCI Secrets client: %w", err)
	}

	// Override region if explicitly set
	if o.config.Region != "" {
		client.SetRegion(o.config.Region)
	}

	o.client = client

	log.Infof("Successfully initialized OCI Vault provider (auth_method=%s, region=%s)", o.config.AuthMethod, o.config.Region)
	return nil
}

// buildConfigProvider creates the appropriate OCI configuration provider based on auth method
func (o *OCIProvider) buildConfigProvider() (common.ConfigurationProvider, error) {
	switch strings.ToLower(o.config.AuthMethod) {
	case "instance_principal":
		return auth.InstancePrincipalConfigurationProvider()

	case "api_key", "":
		if o.config.TenancyOCID == "" || o.config.UserOCID == "" || o.config.Fingerprint == "" || o.config.Region == "" {
			return nil, fmt.Errorf("api_key auth requires OCI_TENANCY_OCID, OCI_USER_OCID, OCI_FINGERPRINT, and OCI_REGION")
		}

		privateKey, err := o.decodePrivateKey()
		if err != nil {
			return nil, fmt.Errorf("api_key auth: %w", err)
		}

		passphrase := common.String(o.config.PrivateKeyPassphrase)
		if o.config.PrivateKeyPassphrase == "" {
			passphrase = nil
		}

		return common.NewRawConfigurationProvider(
			o.config.TenancyOCID,
			o.config.UserOCID,
			o.config.Region,
			o.config.Fingerprint,
			privateKey,
			passphrase,
		), nil

	default:
		return nil, fmt.Errorf("unsupported OCI auth method: %s (supported: api_key, instance_principal)", o.config.AuthMethod)
	}
}

// GetSecret retrieves a secret value from OCI Vault
func (o *OCIProvider) GetSecret(ctx context.Context, secretInfo *SecretInfo) ([]byte, error) {
	if secretID := secretInfo.Labels["oci_secret_ocid"]; secretID != "" {
		log.Infof("Reading secret from OCI Vault by OCID: %s (stage: %s)", secretID, secretInfo.Labels["oci_stage"])
	} else {
		log.Infof("Reading secret from OCI Vault: %s (stage: %s)", secretInfo.SecretPath, secretInfo.Labels["oci_stage"])
	}

	rawValue, err := o.fetchRawContent(ctx, secretInfo)
	if err != nil {
		return nil, err
	}

	return ExtractSecretValue(string(rawValue), secretInfo.SecretField)
}

// SupportsRotation indicates that OCI Vault supports secret rotation monitoring
func (o *OCIProvider) SupportsRotation() bool {
	return true
}

// fetchRawContent retrieves the raw decoded secret bytes using either OCID or name-based lookup.
func (o *OCIProvider) fetchRawContent(ctx context.Context, secretInfo *SecretInfo) ([]byte, error) {
	stage, err := resolveStage(secretInfo.Labels["oci_stage"])
	if err != nil {
		return nil, err
	}

	var content ocisecrets.SecretBundleContentDetails
	if secretID, exists := secretInfo.Labels["oci_secret_ocid"]; exists && secretID != "" {
		content, err = o.fetchBundleByID(ctx, secretID, stage)
	} else {
		content, err = o.fetchBundleByName(ctx, secretInfo.SecretPath, secretInfo.Labels, stage)
	}
	if err != nil {
		return nil, err
	}

	return extractBundleContent(content)
}

func (o *OCIProvider) fetchBundleByID(ctx context.Context, secretID string, stage SecretStager) (ocisecrets.SecretBundleContentDetails, error) {
	bundleReq := ocisecrets.GetSecretBundleRequest{
		SecretId: common.String(secretID),
	}
	switch s := stage.(type) {
	case NamedStage:
		bundleReq.Stage = ocisecrets.GetSecretBundleStageEnum(s.Name)
	case VersionStage:
		bundleReq.VersionNumber = &s.Version
	}

	result, err := o.client.GetSecretBundle(ctx, bundleReq)
	if err != nil {
		return nil, fmt.Errorf("failed to get secret bundle from OCI Vault: %w", err)
	}
	return result.SecretBundleContent, nil
}

func (o *OCIProvider) fetchBundleByName(ctx context.Context, secretName string, labels map[string]string, stage SecretStager) (ocisecrets.SecretBundleContentDetails, error) {
	vaultOCID := labels["oci_vault_ocid"]
	if vaultOCID == "" {
		vaultOCID = o.config.VaultOCID
	}
	if vaultOCID == "" {
		return nil, fmt.Errorf("OCI_VAULT_OCID or oci_vault_ocid label is required when checking secrets by name")
	}

	bundleReq := ocisecrets.GetSecretBundleByNameRequest{
		SecretName: common.String(secretName),
		VaultId:    common.String(vaultOCID),
	}
	switch s := stage.(type) {
	case NamedStage:
		bundleReq.Stage = ocisecrets.GetSecretBundleByNameStageEnum(s.Name)
	case VersionStage:
		bundleReq.VersionNumber = &s.Version
	}

	result, err := o.client.GetSecretBundleByName(ctx, bundleReq)
	if err != nil {
		return nil, fmt.Errorf("failed to get secret by name from OCI Vault: %w", err)
	}
	return result.SecretBundleContent, nil
}

// GetSecretFieldLabel returns the label key used by OCI for the secret field
func (o *OCIProvider) GetSecretFieldLabel() string {
	return "oci_field"
}

// BuildSecretPath constructs the OCI secret name based on request labels and service information
func (o *OCIProvider) BuildSecretPath(req secrets.Request) string {
	// Use custom name from labels if provided
	if customPath, exists := req.SecretLabels["oci_secret_name"]; exists {
		return customPath
	}
	// Default naming convention
	if req.ServiceName != "" {
		return fmt.Sprintf("%s-%s", req.ServiceName, req.SecretName)
	}
	return req.SecretName
}

// GetProviderName returns the name of this provider
func (o *OCIProvider) GetProviderName() string {
	return "oci"
}

// Close performs cleanup for the OCI provider
func (o *OCIProvider) Close() error {
	// OCI client does not require explicit cleanup
	return nil
}

// decodePrivateKey decodes the base64-encoded PEM private key from OCI_PRIVATE_KEY
func (o *OCIProvider) decodePrivateKey() (string, error) {
	if o.config.PrivateKey == "" {
		return "", fmt.Errorf("OCI_PRIVATE_KEY is required for api_key auth (base64-encoded PEM)")
	}

	decoded, err := base64.StdEncoding.DecodeString(o.config.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("OCI_PRIVATE_KEY must be base64-encoded: %w", err)
	}

	pem := string(decoded)
	if !strings.HasPrefix(strings.TrimSpace(pem), "-----BEGIN") {
		return "", fmt.Errorf("OCI_PRIVATE_KEY does not contain a valid PEM after base64 decoding")
	}

	return pem, nil
}

// SecretStager represents either a named stage or a specific version number.
type SecretStager interface {
	secretStage() // unexported method seals the interface
}

// NamedStage selects a secret by lifecycle stage (e.g. "CURRENT", "PENDING").
type NamedStage struct{ Name string }

// VersionStage selects a secret by explicit version number.
type VersionStage struct{ Version int64 }

func (NamedStage) secretStage() {
	// sealed interface marker — prevents external implementations of SecretStager
}
func (VersionStage) secretStage() {
	// sealed interface marker — prevents external implementations of SecretStager
}

// resolveStage parses the oci_stage label into a SecretStager.
// Accepts named stages (current, previous, latest, pending, deprecated) or a numeric version (e.g. "3").
// Returns NamedStage{"CURRENT"} when the label is empty or unset.
func resolveStage(label string) (SecretStager, error) {
	if label == "" {
		return NamedStage{Name: "CURRENT"}, nil
	}

	// Try numeric version first
	if v, err := strconv.ParseInt(label, 10, 64); err == nil {
		return VersionStage{Version: v}, nil
	}

	switch strings.ToLower(label) {
	case "current":
		return NamedStage{Name: "CURRENT"}, nil
	case "pending":
		return NamedStage{Name: "PENDING"}, nil
	case "latest":
		return NamedStage{Name: "LATEST"}, nil
	case "previous":
		return NamedStage{Name: "PREVIOUS"}, nil
	case "deprecated":
		return NamedStage{Name: "DEPRECATED"}, nil
	default:
		return nil, fmt.Errorf("unsupported oci_stage value: %q (valid: current, pending, latest, previous, deprecated, or a version number)", label)
	}
}

// extractBundleContent extracts the raw decoded bytes from an OCI SecretBundleContent.
func extractBundleContent(content ocisecrets.SecretBundleContentDetails) ([]byte, error) {
	base64Content, ok := content.(ocisecrets.Base64SecretBundleContentDetails)
	if !ok {
		return nil, fmt.Errorf("unsupported secret bundle content type: %T", content)
	}

	if base64Content.Content == nil {
		return nil, fmt.Errorf("secret bundle content is nil")
	}

	decoded, err := base64.StdEncoding.DecodeString(*base64Content.Content)
	if err != nil {
		return nil, fmt.Errorf("failed to base64-decode secret content: %w", err)
	}

	return decoded, nil
}
