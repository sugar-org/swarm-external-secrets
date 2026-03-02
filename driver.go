package main

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/docker/docker/api/types/swarm"
	dockerclient "github.com/docker/docker/client"
	"github.com/docker/go-plugins-helpers/secrets"
	log "github.com/sirupsen/logrus"

	"github.com/sugar-org/vault-swarm-plugin/monitoring"
	"github.com/sugar-org/vault-swarm-plugin/providers"
)

// SecretsDriver implements the secrets.Driver interface with multi-provider support
type SecretsDriver struct {
	provider      providers.SecretsProvider
	config        *SecretsConfig
	dockerClient  *dockerclient.Client
	secretTracker map[string]*providers.SecretInfo // key: docker secret name
	trackerMutex  sync.RWMutex
	monitorCtx    context.Context
	monitorCancel context.CancelFunc
	monitor       *monitoring.Monitor
	webInterface  *monitoring.WebInterface
}

// SecretsConfig holds the configuration for the multi-provider driver
type SecretsConfig struct {
	ProviderType     string
	EnableRotation   bool
	RotationInterval time.Duration
	EnableMonitoring bool
	MonitoringPort   int
	Settings         map[string]string
}
func parseBoolEnv(key string, defaultVal bool) bool {
    raw := getEnvOrDefault(key, strconv.FormatBool(defaultVal))

    v, err := strconv.ParseBool(raw)
    if err != nil {
        log.Warnf("Invalid boolean value for %s: %q, defaulting to %t", key, raw, defaultVal)
        return defaultVal
    }

    return v
}

// NewDriver creates a new Driver instance with multi-provider support
func NewDriver() (*SecretsDriver, error) {
	// Collect all configuration from environment variables
	settings := make(map[string]string)

	// Get provider type (default to vault for backward compatibility)
	providerType := getEnvOrDefault("SECRETS_PROVIDER", "vault")

	// Collect all environment variables for provider configuration
	for _, env := range os.Environ() {
		pair := strings.SplitN(env, "=", 2)
		if len(pair) == 2 {
			settings[pair[0]] = pair[1]
		}
	}

	enableRotation := true
    rotationEnv := getEnvOrDefault("ENABLE_ROTATION", "true")
    if v, err := strconv.ParseBool(rotationEnv); err == nil {
	    enableRotation = v
    } else {
	    log.Warnf("Invalid boolean value for ENABLE_ROTATION: %q, defaulting to true", rotationEnv)
    }

    enableMonitoring := parseBoolEnv("ENABLE_MONITORING", true)
    config := &SecretsConfig{
        ProviderType:      providerType,
        EnableRotation:    enableRotation,
        RotationInterval:  parseDurationOrDefault(
            getEnvOrDefault("ROTATION_INTERVAL", "10s"),
        ),
        EnableMonitoring:  enableMonitoring,
        MonitoringPort:    parseIntOrDefault(
            getEnvOrDefault("MONITORING_PORT", "8080"),
        ),
        Settings: settings,
    }

	// Create the appropriate provider
	provider, err := providers.CreateProvider(config.ProviderType)
	if err != nil {
		return nil, fmt.Errorf("failed to create provider: %w", err)
	}

	// Initialize the provider
	if err := provider.Initialize(settings); err != nil {
		return nil, fmt.Errorf("failed to initialize %s provider: %w", config.ProviderType, err)
	}

	// Create Docker client
	dockerClient, err := dockerclient.NewClientWithOpts(dockerclient.FromEnv, dockerclient.WithAPIVersionNegotiation())
	if err != nil {
		return nil, fmt.Errorf("failed to create docker client: %w", err)
	}

	// Create context for monitoring
	monitorCtx, monitorCancel := context.WithCancel(context.Background())

	driver := &SecretsDriver{
		provider:      provider,
		config:        config,
		dockerClient:  dockerClient,
		secretTracker: make(map[string]*providers.SecretInfo),
		monitorCtx:    monitorCtx,
		monitorCancel: monitorCancel,
	}

	// Initialize monitoring if enabled
	if config.EnableMonitoring {
		driver.monitor = monitoring.NewMonitor(30 * time.Second) // Monitor every 30 seconds
		driver.monitor.SetRotationInterval(config.RotationInterval)
		driver.monitor.Start()

		// Start web interface
		driver.webInterface = monitoring.NewWebInterface(driver.monitor, config.MonitoringPort)
		if err := driver.webInterface.Start(); err != nil {
			log.Warnf("Failed to start web monitoring interface: %v", err)
		}
	}

	// Start monitoring if rotation is enabled and provider supports it
	if config.EnableRotation && provider.SupportsRotation() {
		log.Printf("Starting secret rotation monitoring with interval: %v", config.RotationInterval)
		go driver.startMonitoring()
	} else if config.EnableRotation {
		log.Printf("Secret rotation is enabled but provider %s does not support rotation", config.ProviderType)
	} else {
		log.Printf("Secret rotation monitoring is disabled")
	}

	log.Printf("Successfully initialized driver with %s provider", provider.GetProviderName())
	return driver, nil
}

// Get method implements the secrets.Driver interface
func (d *SecretsDriver) Get(req secrets.Request) secrets.Response {
	log.Printf("Received secret request for: %s using provider: %s", req.SecretName, d.provider.GetProviderName())

	if req.SecretName == "" {
		return secrets.Response{
			Err: "secret name is required",
		}
	}

	// Add context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Get secret from the provider
	value, err := d.provider.GetSecret(ctx, req)
	if err != nil {
		log.Printf("Error getting secret from provider: %v", err)
		return secrets.Response{
			Err: fmt.Sprintf("failed to get secret: %v", err),
		}
	}

	log.Printf("Successfully retrieved secret from %s provider", d.provider.GetProviderName())

	// Track this secret for monitoring if rotation is enabled
	if d.config.EnableRotation && d.provider.SupportsRotation() {
		d.trackSecret(req, value)
	}

	// Determine if secret should be reusable
	doNotReuse := d.shouldNotReuse(req)

	log.Printf("Successfully returning secret value")
	return secrets.Response{
		Value:      value,
		DoNotReuse: doNotReuse,
	}
}

// shouldNotReuse determines if the secret should not be reused
func (d *SecretsDriver) shouldNotReuse(req secrets.Request) bool {
	// Check for explicit label
	if reuse, exists := req.SecretLabels["vault_reuse"]; exists {
		return strings.EqualFold(reuse, "false")
	}

	name := strings.ToLower(req.SecretName)

	// Don't reuse dynamic secrets or certificates
	if strings.Contains(name, "cert") ||
		strings.Contains(name, "token") ||
		strings.Contains(name, "dynamic") {
		return true
	}

	return false
}

// trackSecret adds or updates a secret in the tracking system
func (d *SecretsDriver) trackSecret(req secrets.Request, value []byte) {
	d.trackerMutex.Lock()
	defer d.trackerMutex.Unlock()

	// Calculate hash for change detection
	hash := fmt.Sprintf("%x", sha256.Sum256(value))

	// Extract secret field from labels based on provider
	var secretField string
	switch d.provider.GetProviderName() {
	case "vault":
		secretField = req.SecretLabels["vault_field"]
	case "aws":
		secretField = req.SecretLabels["aws_field"]
	case "gcp":
		secretField = req.SecretLabels["gcp_field"]
	case "azure":
		secretField = req.SecretLabels["azure_field"]
	case "openbao":
		secretField = req.SecretLabels["openbao_field"]
	}

	if secretField == "" {
		secretField = "value" // default field
	}

	// Build secret path using provider-specific logic
	var secretPath string
	switch d.provider.GetProviderName() {
	case "vault":
		secretPath = d.buildVaultSecretPath(req)
	case "aws":
		secretPath = d.buildAWSSecretName(req)
	case "gcp":
		secretPath = d.buildGCPSecretName(req)
	case "azure":
        var err error
        secretPath, err = d.buildAzureSecretName(req)
        if err != nil {
            log.Errorf("failed to build azure secret name: %v", err)
            return
        
        }
	case "openbao":
		secretPath = d.buildOpenBaoSecretPath(req)
	default:
		secretPath = req.SecretName
	}

	log.Printf("Current provider %s tracking secret: %s at path: %s with field: %s",
		d.provider.GetProviderName(), req.SecretName, secretPath, secretField)

	secretInfo := &providers.SecretInfo{
		DockerSecretName: req.SecretName,
		SecretPath:       secretPath,
		SecretField:      secretField,
		ServiceNames:     []string{req.ServiceName}, // Start with current service
		LastHash:         hash,
		LastUpdated:      time.Now(),
		Provider:         d.provider.GetProviderName(),
	}

	// If already tracking, update service names
	if existing, exists := d.secretTracker[req.SecretName]; exists {
		// Add service name if not already present
		serviceFound := false
		for _, svc := range existing.ServiceNames {
			if svc == req.ServiceName {
				serviceFound = true
				break
			}
		}
		if !serviceFound && req.ServiceName != "" {
			existing.ServiceNames = append(existing.ServiceNames, req.ServiceName)
		}
		existing.LastHash = hash
		existing.LastUpdated = time.Now()
	} else {
		d.secretTracker[req.SecretName] = secretInfo
	}

	log.Printf("Tracking secret: %s -> %s (provider: %s, services: %v)",
		req.SecretName, secretPath, d.provider.GetProviderName(), secretInfo.ServiceNames)
}

// startMonitoring starts the background monitoring goroutine
func (d *SecretsDriver) startMonitoring() {
	ticker := time.NewTicker(d.config.RotationInterval)
	defer ticker.Stop()

	log.Printf("Secret monitoring started with interval: %v", d.config.RotationInterval)

	for {
		select {
		case <-d.monitorCtx.Done():
			log.Printf("Secret monitoring stopped")
			return
		case <-ticker.C:
			// Update ticker heartbeat for monitoring
			if d.monitor != nil {
				d.monitor.UpdateTickerHeartbeat()
			}
			d.checkForSecretChanges()
		}
	}
}

// checkForSecretChanges monitors tracked secrets for changes
func (d *SecretsDriver) checkForSecretChanges() {
	d.trackerMutex.RLock()
	secrets := make(map[string]*providers.SecretInfo)
	for k, v := range d.secretTracker {
		secrets[k] = v
	}
	d.trackerMutex.RUnlock()

	if len(secrets) == 0 {
		log.Debug("No secrets to monitor")
		return
	}

	log.Printf("Checking %d tracked secrets for changes", len(secrets))

	for secretName, secretInfo := range secrets {
		if d.hasSecretChanged(secretInfo) {
			log.Printf("Detected change in secret: %s", secretName)
			if err := d.rotateSecret(secretInfo); err != nil {
				log.Errorf("Failed to rotate secret %s: %v", secretName, err)
				if d.monitor != nil {
					d.monitor.IncrementRotationErrors()
				}
			} else {
				if d.monitor != nil {
					d.monitor.IncrementSecretRotations()
				}
			}
		}
	}
}

// hasSecretChanged checks if a secret has changed using the provider
func (d *SecretsDriver) hasSecretChanged(secretInfo *providers.SecretInfo) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	changed, err := d.provider.CheckSecretChanged(ctx, secretInfo)
	if err != nil {
		log.Errorf("Error checking secret change for %s: %v", secretInfo.DockerSecretName, err)
		return false
	}

	return changed
}

// rotateSecret handles the secret rotation process
func (d *SecretsDriver) rotateSecret(secretInfo *providers.SecretInfo) error {
	log.Printf("Starting rotation for secret: %s", secretInfo.DockerSecretName)

	// Create a dummy request to get the new secret value
	req := secrets.Request{
		SecretName:   secretInfo.DockerSecretName,
		SecretLabels: make(map[string]string),
	}

	// Set appropriate field and path labels based on provider
	switch secretInfo.Provider {
	case "vault":
		req.SecretLabels["vault_field"] = secretInfo.SecretField
		// Extract the specific path part from the full path
		req.SecretLabels["vault_path"] = strings.TrimPrefix(secretInfo.SecretPath, "secret/data/")
	case "aws":
		req.SecretLabels["aws_field"] = secretInfo.SecretField
		req.SecretLabels["aws_secret_name"] = secretInfo.SecretPath
	case "gcp":
		req.SecretLabels["gcp_field"] = secretInfo.SecretField
		req.SecretLabels["gcp_secret_name"] = secretInfo.SecretPath
	case "azure":
		req.SecretLabels["azure_field"] = secretInfo.SecretField
		req.SecretLabels["azure_secret_name"] = secretInfo.SecretPath
	case "openbao":
		req.SecretLabels["openbao_field"] = secretInfo.SecretField
		req.SecretLabels["openbao_path"] = strings.TrimPrefix(secretInfo.SecretPath, "secret/data/")
	}

	// Get the new secret value from the provider
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	newValue, err := d.provider.GetSecret(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to get updated secret from provider: %w", err)
	}

	// Update Docker secret (this now handles service updates internally)
	if err := d.updateDockerSecret(secretInfo.DockerSecretName, newValue); err != nil {
		return fmt.Errorf("failed to update docker secret: %w", err)
	}

	// Update tracking information
	d.trackerMutex.Lock()
	secretInfo.LastHash = fmt.Sprintf("%x", sha256.Sum256(newValue))
	secretInfo.LastUpdated = time.Now()
	d.trackerMutex.Unlock()

	log.Printf("Successfully rotated secret: %s", secretInfo.DockerSecretName)
	return nil
}

// updateDockerSecret creates a new version of the Docker secret
func (d *SecretsDriver) updateDockerSecret(secretName string, newValue []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// List existing secrets to find the one to update
	secrets, err := d.dockerClient.SecretList(ctx, swarm.SecretListOptions{})
	if err != nil {
		return fmt.Errorf("failed to list secrets: %w", err)
	}

	var existingSecret *swarm.Secret
	for _, secret := range secrets {
		if secret.Spec.Name == secretName {
			existingSecret = &secret
			break
		}
	}

	if existingSecret == nil {
		return fmt.Errorf("secret %s not found", secretName)
	}

	// Generate a unique name for the new secret version
	newSecretName := fmt.Sprintf("%s-%d", secretName, time.Now().UnixNano())

	// Create new secret with versioned name and same labels but updated value
	newSecretSpec := swarm.SecretSpec{
		Annotations: swarm.Annotations{
			Name:   newSecretName,
			Labels: existingSecret.Spec.Labels,
		},
		Data: newValue,
	}

	// Create the new secret
	createResponse, err := d.dockerClient.SecretCreate(ctx, newSecretSpec)
	if err != nil {
		return fmt.Errorf("failed to create new secret version: %w", err)
	}

	log.Printf("Created new version of secret %s with name %s and ID: %s", secretName, newSecretName, createResponse.ID)

	// Update all services that use this secret to point to the new version
	if err := d.updateServicesSecretReference(secretName, newSecretName, createResponse.ID); err != nil {
		// try to remove the new secret since service update failed
		if cleanupErr := d.dockerClient.SecretRemove(ctx, createResponse.ID); cleanupErr != nil {
			log.Warnf("failed to remove new secret %s after service update error: %v", createResponse.ID, cleanupErr)
		}
		return fmt.Errorf("failed to update services to use new secret: %w", err)
	}

	// Remove the old secret only after services are updated
	if err := d.dockerClient.SecretRemove(ctx, existingSecret.ID); err != nil {
		log.Warnf("Failed to remove old secret version %s: %v", existingSecret.ID, err)
		// Don't return error as the new secret was created and services updated successfully
	}

	return nil
}

// updateServicesSecretReference updates all services to use the new secret version
func (d *SecretsDriver) updateServicesSecretReference(oldSecretName, newSecretName, newSecretID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// List all services
	services, err := d.dockerClient.ServiceList(ctx, swarm.ServiceListOptions{})
	if err != nil {
		return fmt.Errorf("failed to list services: %w", err)
	}

	var updatedServices []string

	for _, service := range services {
		// Check if service uses this secret and update the reference
		needsUpdate := false

		taskTemplate := service.Spec.TaskTemplate
		containerSpec := taskTemplate.ContainerSpec
		if containerSpec == nil {
			log.Debugf("Skipping service %s: no container spec defined", service.Spec.Name)
			continue
		}

		updatedSecrets := make([]*swarm.SecretReference, len(containerSpec.Secrets))

		for i, secretRef := range containerSpec.Secrets {
			// Match exact name or versioned variants (e.g., secret-1, secret-2)
            if secretRef.SecretName == oldSecretName ||
	            strings.HasPrefix(secretRef.SecretName, oldSecretName+"-") {
				// Update to use the new secret name and ID
				updatedSecrets[i] = &swarm.SecretReference{
					File:       secretRef.File,
					SecretID:   newSecretID,
					SecretName: newSecretName,
				}
				needsUpdate = true
			} else {
				updatedSecrets[i] = secretRef
			}
		}

		if needsUpdate {
			// Update service with new secret references
			serviceSpec := service.Spec
			serviceSpec.TaskTemplate.ContainerSpec.Secrets = updatedSecrets

			// Add/update a label to force the update
			if serviceSpec.Labels == nil {
				serviceSpec.Labels = make(map[string]string)
			}
			serviceSpec.Labels["vault.secret.rotated"] = fmt.Sprintf("%d", time.Now().Unix())

			updateOptions := swarm.ServiceUpdateOptions{}
			updateResponse, err := d.dockerClient.ServiceUpdate(ctx, service.ID, service.Version, serviceSpec, updateOptions)
			if err != nil {
				return fmt.Errorf("failed to update service %s: %w", service.Spec.Name, err)
			}

			if len(updateResponse.Warnings) > 0 {
				log.Warnf("Service update warnings for %s: %v", service.Spec.Name, updateResponse.Warnings)
			}

			updatedServices = append(updatedServices, service.Spec.Name)
		}
	}

	if len(updatedServices) > 0 {
		log.Printf("Updated services to use new secret %s: %v", newSecretName, updatedServices)
	}

	return nil
}

// forceServiceUpdate forces a service to update (recreate tasks)
// TODO - This method is currently not used, check later if needed
// func (d *SecretsDriver) forceServiceUpdate(service swarm.Service) error {
// 	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
// 	defer cancel()

// 	// Get current service spec
// 	serviceSpec := service.Spec

// 	// Add/update a label to force the update
// 	if serviceSpec.Labels == nil {
// 		serviceSpec.Labels = make(map[string]string)
// 	}
// 	serviceSpec.Labels["vault.secret.rotated"] = fmt.Sprintf("%d", time.Now().Unix())

// 	// Update the service
// 	updateOptions := types.ServiceUpdateOptions{}
// 	updateResponse, err := d.dockerClient.ServiceUpdate(ctx, service.ID, service.Version, serviceSpec, updateOptions)
// 	if err != nil {
// 		return fmt.Errorf("failed to update service: %v", err)
// 	}

// 	if len(updateResponse.Warnings) > 0 {
// 		log.Warnf("Service update warnings for %s: %v", service.Spec.Name, updateResponse.Warnings)
// 	}

// 	log.Printf("Forced update for service: %s", service.Spec.Name)
// 	return nil
// }

// Stop gracefully stops monitoring components and releases resources.
// It attempts to shut down all components and collects any errors
// instead of failing fast, so we don't miss cleanup steps.
func (d *SecretsDriver) Stop() error {
	var errs []error

	// Cancel monitoring context if running
	if d.monitorCancel != nil {
		d.monitorCancel()
	}

	// Stop monitoring loop if initialized
	if d.monitor != nil {
		d.monitor.Stop()
	}

	// Stop web interface and capture any shutdown error
	if d.webInterface != nil {
		if err := d.webInterface.Stop(); err != nil {
			log.Warnf("Error stopping web interface: %v", err)
			errs = append(errs, err)
		}
	}

	// Close provider and record error if it occurs
	if d.provider != nil {
		if err := d.provider.Close(); err != nil {
			log.Warnf("Error closing provider: %v", err)
			errs = append(errs, err)
		}
	}

	// Close Docker client if initialized
	if d.dockerClient != nil {
		if err := d.dockerClient.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	// If any shutdown errors occurred, return a combined error
	if len(errs) > 0 {
		return fmt.Errorf("shutdown errors: %v", errs)
	}

	return nil
}

// Helper methods for building provider-specific secret paths/names

func (d *SecretsDriver) buildVaultSecretPath(req secrets.Request) string {
	// Use custom path from labels if provided
	if customPath, exists := req.SecretLabels["vault_path"]; exists {
		return fmt.Sprintf("secret/data/%s", customPath)
	}

	// Default path structure for KV v2
	if req.ServiceName != "" {
		return fmt.Sprintf("secret/data/%s/%s", req.ServiceName, req.SecretName)
	}
	return fmt.Sprintf("secret/data/%s", req.SecretName)
}

func (d *SecretsDriver) buildOpenBaoSecretPath(req secrets.Request) string {
	// Use custom path from labels if provided
	if customPath, exists := req.SecretLabels["openbao_path"]; exists {
		return fmt.Sprintf("secret/data/%s", customPath)
	}

	// Default path structure for KV v2
	if req.ServiceName != "" {
		return fmt.Sprintf("secret/data/%s/%s", req.ServiceName, req.SecretName)
	}
	return fmt.Sprintf("secret/data/%s", req.SecretName)
}

func (d *SecretsDriver) buildAWSSecretName(req secrets.Request) string {
	if customName, exists := req.SecretLabels["aws_secret_name"]; exists {
		return customName
	}

	if req.ServiceName != "" {
		return fmt.Sprintf("%s/%s", req.ServiceName, req.SecretName)
	}
	return req.SecretName
}

func (d *SecretsDriver) buildGCPSecretName(req secrets.Request) string {
	if customName, exists := req.SecretLabels["gcp_secret_name"]; exists {
		name, err := normalizeGCPSecretName(customName)
		if err != nil {
			log.Warnf("invalid GCP secret name %q: %v", customName, err)
			return customName
		}
		return name
	}

	secretName := req.SecretName
	if req.ServiceName != "" {
		secretName = fmt.Sprintf("%s-%s", req.ServiceName, req.SecretName)
	}

	name, err := normalizeGCPSecretName(secretName)
	if err != nil {
		log.Warnf("invalid GCP secret name %q: %v", secretName, err)
		return secretName
	}

	return name
}
// normalizeGCPSecretName ensures the name matches GCP Secret Manager requirements.
// Reference (GCP Secret Manager API):
// https://cloud.google.com/secret-manager/docs/reference/rest/v1/projects.secrets/create
// Secret ID must be <= 255 characters and match allowed pattern.
// normalizeGCPSecretName ensures the name matches GCP's requirements: [a-zA-Z][a-zA-Z0-9_-]*
func normalizeGCPSecretName(secretName string) (string, error) {
    if len(secretName) == 0 {
        return "s", nil
    }

    result := ""
    for i, char := range secretName {
        if i == 0 {
            if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') {
                result += string(char)
            } else {
                result += "s"
            }
        } else {
            if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') ||
                (char >= '0' && char <= '9') || char == '_' || char == '-' {
                result += string(char)
            } else {
                result += "_"
            }
        }
    }

    if len(result) > 255 {
        return "", fmt.Errorf("secret name exceeds 255 characters (GCP limit as per Secret Manager spec)")
    }

    return result, nil
}
// buildAzureSecretName ensures the name matches Azure Key Vault requirements.
// Reference (Azure Key Vault naming rules):
// https://learn.microsoft.com/en-us/azure/key-vault/general/about-keys-secrets-certificates#object-identifiers
// Secret name must be <= 127 characters and match ^[0-9a-zA-Z-]+$
func (d *SecretsDriver) buildAzureSecretName(req secrets.Request) (string, error) {
	if customName, exists := req.SecretLabels["azure_secret_name"]; exists {
		if len(customName) > 127 {
			return "", fmt.Errorf("secret name exceeds 127 characters (Azure Key Vault limit)")
		}
		return customName, nil
	}

	secretName := req.SecretName
	if req.ServiceName != "" {
		secretName = fmt.Sprintf("%s-%s", req.ServiceName, req.SecretName)
	}

	// Azure Key Vault secret names must match regex: ^[0-9a-zA-Z-]+$
	result := ""

	for _, char := range secretName {
		if (char >= 'a' && char <= 'z') ||
			(char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') ||
			char == '-' {
			result += string(char)
		} else {
			result += "-"
		}
	}

	// Remove consecutive hyphens
	for strings.Contains(result, "--") {
		result = strings.ReplaceAll(result, "--", "-")
	}

	// Trim leading/trailing hyphens
	result = strings.Trim(result, "-")

	if result == "" || (result[0] >= '0' && result[0] <= '9') {
		result = "secret-" + result
	}

	// Explicit length validation (Azure limit: 127 chars)
	if len(result) > 127 {
		return "", fmt.Errorf("secret name exceeds 127 characters (Azure Key Vault limit)")
	}

	return result, nil
}

// func (d *SecretsDriver) buildVaultSecretPath(req secrets.Request) string {
// 	// Use custom path from labels if provided
// 	if customPath, exists := req.SecretLabels["vault_path"]; exists {
// 		return fmt.Sprintf("secret/data/%s", customPath)
// 	}

// 	// Default path structure for KV v2
// 	if req.ServiceName != "" {
// 		return fmt.Sprintf("secret/data/%s/%s", req.ServiceName, req.SecretName)
// 	}
// 	return fmt.Sprintf("secret/data/%s", req.SecretName)
// }
