package main

import (
	"context"
	"crypto/sha256"
	"fmt"
	"maps"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/docker/docker/api/types/swarm"
	dockerclient "github.com/docker/docker/client"
	"github.com/docker/go-plugins-helpers/secrets"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"

	"github.com/sugar-org/swarm-external-secrets/internal/secrettransform"
	"github.com/sugar-org/swarm-external-secrets/internal/utils"
	"github.com/sugar-org/swarm-external-secrets/monitoring"
	"github.com/sugar-org/swarm-external-secrets/providers"
)

// SecretsDriver implements the secrets.Driver interface with multi-provider support
type SecretsDriver struct {
	provider      providers.SecretsProvider
	config        *SecretsConfig
	dockerClient  *dockerclient.Client
	transformer   secrettransform.Transformer      // aws kms service which decrypts ciphertexts
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

// NewDriver creates a new Driver instance with multi-provider support
func NewDriver() (*SecretsDriver, error) {
	// Collect all configuration from environment variables
	settings := make(map[string]string)

	// Get provider type (default to vault for backward compatibility)
	providerType := utils.GetEnvOrDefault("SECRETS_PROVIDER", "vault")

	// Collect all environment variables for provider configuration
	for _, env := range os.Environ() {
		pair := strings.SplitN(env, "=", 2)
		if len(pair) == 2 {
			settings[pair[0]] = pair[1]
		}
	}

	config := &SecretsConfig{
		ProviderType:     providerType,
		EnableRotation:   utils.GetEnvOrDefault("ENABLE_ROTATION", "true") == "true",
		RotationInterval: utils.ParseDurationOrDefault(utils.GetEnvOrDefault("ROTATION_INTERVAL", "10s")),
		EnableMonitoring: utils.GetEnvOrDefault("ENABLE_MONITORING", "true") == "true",
		MonitoringPort:   utils.ParseIntOrDefault(utils.GetEnvOrDefault("MONITORING_PORT", "8080")),
		Settings:         settings,
	}

	// Create the appropriate provider
	provider, err := providers.CreateProvider(config.ProviderType)
	if err != nil {
		return nil, fmt.Errorf("failed to create provider: %v", err)
	}

	// Initialize the provider
	if err := provider.Initialize(settings); err != nil {
		log.Errorf("failed to initialize %s provider: %v", config.ProviderType, err)
		return nil, fmt.Errorf("failed to initialize %s provider: %v", config.ProviderType, err)
	}

	// Create Docker client
	dockerClient, err := dockerclient.NewClientWithOpts(dockerclient.FromEnv, dockerclient.WithAPIVersionNegotiation())
	if err != nil {
		log.Errorf("failed to create docker client: %v", err)
		return nil, fmt.Errorf("failed to create docker client: %v", err)
	}

	// Create context for monitoring
	monitorCtx, monitorCancel := context.WithCancel(context.Background())

	driver := &SecretsDriver{
		provider:      provider,
		config:        config,
		dockerClient:  dockerClient,
		transformer:   secrettransform.NewAWSKMSTransformer(settings),
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
		log.Infof("Starting secret rotation monitoring with interval: %v", config.RotationInterval)
		go driver.startMonitoring()
	} else if config.EnableRotation {
		log.Warnf("Secret rotation is enabled but provider %s does not support rotation", config.ProviderType)
	} else {
		log.Debug("Secret rotation monitoring is disabled")
	}

	log.Infof("Successfully initialized driver with %s provider", provider.GetProviderName())
	return driver, nil
}

// buildSecretInfo constructs a SecretInfo from the incoming request, using the
// provider to resolve the secret path. This is the single point where we
// translate a Docker secrets.Request into our internal representation.
func (d *SecretsDriver) buildSecretInfo(req secrets.Request) *providers.SecretInfo {
	secretField := req.SecretLabels[d.provider.GetSecretFieldLabel()]
	if secretField == "" {
		secretField = "value"
	}

	return &providers.SecretInfo{
		DockerSecretName: req.SecretName,
		SecretPath:       d.provider.BuildSecretPath(req), // Start with current service
		SecretField:      secretField,
		ServiceNames:     []string{req.ServiceName},
		Provider:         d.provider.GetProviderName(),
		Labels:           maps.Clone(req.SecretLabels),
	}
}

// shortID returns a short unique identifier used to correlate all log lines
// belonging to a single secret resolution request, even when many requests
// are being handled concurrently.
func shortID() string {
	return uuid.NewString()[:8]
}

// Get method implements the secrets.Driver interface
func (d *SecretsDriver) Get(req secrets.Request) secrets.Response {
	reqID := shortID()
	start := time.Now()
	log.Debugf("[%s] received secret request for: %s using provider: %s", reqID, req.SecretName, d.provider.GetProviderName())

	if req.SecretName == "" {
		log.Warnf("[%s] get request rejected: secret name is required", reqID)
		log.WithField("duration", time.Since(start)).Debugf("[%s] secret resolution completed", reqID)
		return secrets.Response{
			Err: "secret name is required",
		}
	}

	// Build SecretInfo once from the request — used for all downstream calls
	secretInfo := d.buildSecretInfo(req)

	// Add context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Get secret from the provider
	value, err := d.provider.GetSecret(ctx, secretInfo)
	if err != nil {
		log.WithField("duration", time.Since(start)).Errorf("[%s] error getting secret from provider %s for secret %s: %v", reqID, d.provider.GetProviderName(), req.SecretName, err)
		return secrets.Response{
			Err: fmt.Sprintf("failed to get secret: %v", err),
		}
	}

	// Track this secret for monitoring if rotation is enabled
	if d.config.EnableRotation && d.provider.SupportsRotation() {
		d.trackSecret(secretInfo, value, reqID)
	}

	value, err = d.transformSecret(ctx, secretInfo, value)
	if err != nil {
		log.Errorf("Error transforming secret %s: %v", req.SecretName, err)
		return secrets.Response{
			Err: fmt.Sprintf("failed to transform secret: %v", err),
		}
	}

	log.Debugf("Successfully retrieved secret from %s provider", d.provider.GetProviderName())

	// Determine if secret should be reusable (Docker DoNotReuse=true means do not cache/reuse)
	doNotReuse := d.shouldNotReuse(req)
	log.Debugf("[%s] get secret %q: DoNotReuse=%v (Swarm may reuse cached value when false)", reqID, req.SecretName, doNotReuse)

	log.WithField("duration", time.Since(start)).Debugf("[%s] successfully returning secret value", reqID)
	return secrets.Response{
		Value:      value,
		DoNotReuse: doNotReuse,
	}
}

func (d *SecretsDriver) transformSecret(ctx context.Context, secretInfo *providers.SecretInfo, value []byte) ([]byte, error) {
	if d.transformer == nil {
		return value, nil
	}

	transformed, err := d.transformer.Transform(ctx, secretInfo, value)
	if err != nil {
		return nil, fmt.Errorf("transform secret value: %w", err)
	}

	return transformed, nil
}

// shouldNotReuse returns the value for secrets.Response.DoNotReuse.
// When true, Docker should not reuse a cached value (fetch from provider again).
// Label secret_reuse: "true" means allow reuse → DoNotReuse must be false (see docs/multi-provider.md).
func (d *SecretsDriver) shouldNotReuse(req secrets.Request) bool {
	if reuse, exists := req.SecretLabels["secret_reuse"]; exists {
		v := strings.ToLower(strings.TrimSpace(reuse))
		allowReuse := v == "true"
		if allowReuse {
			log.Debugf("secret_reuse=%q for %q: allowing Swarm reuse (DoNotReuse=false)", reuse, req.SecretName)
			return false
		}
		log.Debugf("secret_reuse=%q for %q: disallowing Swarm reuse (DoNotReuse=true)", reuse, req.SecretName)
		return true
	}

	// Don't reuse dynamic secrets or certificates
	if strings.Contains(req.SecretName, "cert") ||
		strings.Contains(req.SecretName, "token") ||
		strings.Contains(req.SecretName, "dynamic") {
		return true
	}

	return false
}

// trackSecret adds or updates a secret in the tracking system
func (d *SecretsDriver) trackSecret(secretInfo *providers.SecretInfo, value []byte, reqID string) {
	d.trackerMutex.Lock()
	defer d.trackerMutex.Unlock()

	// Calculate hash for change detection
	hash := fmt.Sprintf("%x", sha256.Sum256(value))

	log.Tracef("[%s] current provider %s tracking secret: %s at path: %s",
		reqID, secretInfo.Provider, secretInfo.DockerSecretName, secretInfo.SecretPath)

	// If already tracking, update service names and hash
	if existing, exists := d.secretTracker[secretInfo.DockerSecretName]; exists {
		// Add service name if not already present
		serviceName := secretInfo.ServiceNames[0]
		serviceFound := slices.Contains(existing.ServiceNames, serviceName)
		if !serviceFound && serviceName != "" {
			existing.ServiceNames = append(existing.ServiceNames, serviceName)
		}
		existing.LastHash = hash
		existing.LastUpdated = time.Now()
		existing.Labels = secretInfo.Labels
	} else {
		secretInfo.LastHash = hash
		secretInfo.LastUpdated = time.Now()
		d.secretTracker[secretInfo.DockerSecretName] = secretInfo
	}

	log.Tracef("[%s] tracking secret: %s -> %s (provider: %s, services: %v)",
		reqID, secretInfo.DockerSecretName, secretInfo.SecretPath, secretInfo.Provider, secretInfo.ServiceNames)
}

// startMonitoring starts the background monitoring goroutine
func (d *SecretsDriver) startMonitoring() {
	ticker := time.NewTicker(d.config.RotationInterval)
	defer ticker.Stop()

	log.Infof("Secret monitoring started with interval: %v", d.config.RotationInterval)

	for {
		select {
		case <-d.monitorCtx.Done():
			log.Info("Secret monitoring stopped")
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
	secrets := make(map[string]*providers.SecretInfo, len(d.secretTracker))
	maps.Copy(secrets, d.secretTracker)
	d.trackerMutex.RUnlock()

	if len(secrets) == 0 {
		log.Debug("No secrets to monitor")
		return
	}

	log.Debugf("Checking %d tracked secrets for changes", len(secrets))
	// TODO: Revisit this limit if secret-label fanout or provider latency changes.
	concurrentSecretChecks := len(secrets) + 1

	sem := make(chan struct{}, concurrentSecretChecks)
	var wg sync.WaitGroup

	for secretName, secretInfo := range secrets {
		sem <- struct{}{}
		wg.Add(1)
		go func(secretName string, secretInfo *providers.SecretInfo) {
			defer wg.Done()
			defer func() { <-sem }()

			if !d.hasSecretChanged(secretInfo) {
				return
			}

			log.Tracef("Detected change in secret: %s", secretName)
			d.handleSecretRotationResult(secretName, secretInfo)
		}(secretName, secretInfo)
	}

	wg.Wait()
}

func (d *SecretsDriver) handleSecretRotationResult(secretName string, secretInfo *providers.SecretInfo) {
	if err := d.rotateSecret(secretInfo); err != nil {
		log.Errorf("Failed to rotate secret %s: %v", secretName, err)
		if d.monitor != nil {
			d.monitor.IncrementRotationErrors()
		}
		return
	}

	if d.monitor != nil {
		d.monitor.IncrementSecretRotations()
	}
}

// hasSecretChanged fetches the current secret value and compares its hash
// against the stored hash to detect changes.
func (d *SecretsDriver) hasSecretChanged(secretInfo *providers.SecretInfo) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	currentValue, err := d.provider.GetSecret(ctx, secretInfo)
	if err != nil {
		log.Errorf("Error checking secret change for %s: %v", secretInfo.DockerSecretName, err)
		return false
	}

	d.trackerMutex.RLock()
	lastHash := secretInfo.LastHash
	d.trackerMutex.RUnlock()

	currentHash := fmt.Sprintf("%x", sha256.Sum256(currentValue))
	return currentHash != lastHash
}

// rotateSecret handles the secret rotation process
func (d *SecretsDriver) rotateSecret(secretInfo *providers.SecretInfo) error {
	log.Infof("Starting rotation for secret: %s", secretInfo.DockerSecretName)

	// Get the new secret value from the provider using the existing SecretInfo
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	providerValue, err := d.provider.GetSecret(ctx, secretInfo)
	if err != nil {
		return fmt.Errorf("failed to get updated secret from provider: %v", err)
	}

	newValue, err := d.transformSecret(ctx, secretInfo, providerValue)
	if err != nil {
		return fmt.Errorf("failed to transform updated secret: %w", err)
	}

	// Update Docker secret (this now handles service updates internally)
	if err := d.updateDockerSecret(secretInfo.DockerSecretName, newValue); err != nil {
		return fmt.Errorf("failed to update docker secret: %v", err)
	}

	// Update tracking information
	d.trackerMutex.Lock()
	secretInfo.LastHash = fmt.Sprintf("%x", sha256.Sum256(providerValue))
	secretInfo.LastUpdated = time.Now()
	d.trackerMutex.Unlock()

	log.Infof("Successfully rotated secret: %s", secretInfo.DockerSecretName)
	return nil
}

// updateDockerSecret creates a new version of the Docker secret
func (d *SecretsDriver) updateDockerSecret(secretName string, newValue []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// List existing secrets to find the one to update
	secrets, err := d.dockerClient.SecretList(ctx, swarm.SecretListOptions{})
	if err != nil {
		return fmt.Errorf("failed to list secrets: %v", err)
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
		return fmt.Errorf("failed to create new secret version: %v", err)
	}

	log.Infof("Created new version of secret %s with name %s and ID: %s", secretName, newSecretName, createResponse.ID)

	// Update all services that use this secret to point to the new version
	if err := d.updateServicesSecretReference(secretName, existingSecret.ID, newSecretName, createResponse.ID); err != nil {
		// try to remove the new secret since service update failed
		if cleanupErr := d.dockerClient.SecretRemove(ctx, createResponse.ID); cleanupErr != nil {
			log.Warnf("failed to remove new secret %s after service update error: %v", createResponse.ID, cleanupErr)
		}
		return fmt.Errorf("failed to update services to use new secret: %v", err)
	}

	// Remove the old secret only after services are updated
	if err := d.dockerClient.SecretRemove(ctx, existingSecret.ID); err != nil {
		log.Warnf("Failed to remove old secret version %s: %v", existingSecret.ID, err)
		// Don't return error as the new secret was created and services updated successfully
	}

	return nil
}

// updateServicesSecretReference updates all services to use the new secret version
func (d *SecretsDriver) updateServicesSecretReference(oldSecretName, oldSecretID, newSecretName, newSecretID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// List all services
	services, err := d.dockerClient.ServiceList(ctx, swarm.ServiceListOptions{})
	if err != nil {
		return fmt.Errorf("failed to list services: %v", err)
	}

	var updatedServices []string

	for _, service := range services {
		// Check if service uses this secret and update the reference.
		containerSpec := service.Spec.TaskTemplate.ContainerSpec
		if containerSpec == nil {
			log.Warnf("Skipping secret update for service %s: TaskTemplate.ContainerSpec is nil", service.Spec.Name)
			continue
		}

		updatedSecrets := make([]*swarm.SecretReference, len(containerSpec.Secrets))
		needsUpdate := buildUpdatedSecretReferences(
			containerSpec.Secrets,
			oldSecretName,
			oldSecretID,
			newSecretName,
			newSecretID,
			updatedSecrets,
		)
		if needsUpdate {
			if err := d.applyServiceSecretUpdate(ctx, service, updatedSecrets); err != nil {
				return err
			}
			updatedServices = append(updatedServices, service.Spec.Name)
		}
	}

	if len(updatedServices) > 0 {
		log.Infof("Updated services to use new secret %s: %v", newSecretName, updatedServices)
	}

	return nil
}

func buildUpdatedSecretReferences(
	secretRefs []*swarm.SecretReference,
	oldSecretName string,
	oldSecretID string,
	newSecretName string,
	newSecretID string,
	updatedSecrets []*swarm.SecretReference,
) bool {
	needsUpdate := false
	for i, secretRef := range secretRefs {
		if secretRef == nil {
			continue
		}

		if (oldSecretID != "" && secretRef.SecretID == oldSecretID) || secretRef.SecretName == oldSecretName {
			// Update to use the new secret name and ID.
			updatedSecrets[i] = &swarm.SecretReference{
				File:       secretRef.File,
				SecretID:   newSecretID, // Use actual Docker secret ID
				SecretName: newSecretName,
			}
			needsUpdate = true
			continue
		}

		updatedSecrets[i] = secretRef
	}

	return needsUpdate
}

func (d *SecretsDriver) applyServiceSecretUpdate(
	ctx context.Context,
	service swarm.Service,
	updatedSecrets []*swarm.SecretReference,
) error {
	serviceSpec := service.Spec
	if serviceSpec.TaskTemplate.ContainerSpec == nil {
		log.Warnf("Skipping secret update for service %s: TaskTemplate.ContainerSpec is nil", service.Spec.Name)
		return nil
	}

	// Update service with new secret references.
	serviceSpec.TaskTemplate.ContainerSpec.Secrets = updatedSecrets

	if serviceSpec.Labels == nil {
		serviceSpec.Labels = make(map[string]string)
	}

	// Add/update a label to force the update.
	serviceSpec.Labels["vault.secret.rotated"] = fmt.Sprintf("%d", time.Now().Unix())

	updateResponse, err := d.dockerClient.ServiceUpdate(ctx, service.ID, service.Version, serviceSpec, swarm.ServiceUpdateOptions{})
	if err != nil {
		return fmt.Errorf("failed to update service %s: %v", service.Spec.Name, err)
	}

	if len(updateResponse.Warnings) > 0 {
		log.Warnf("Service update warnings for %s: %v", service.Spec.Name, updateResponse.Warnings)
	}

	return nil
}

// Stop gracefully stops the monitoring and cleans up resources
func (d *SecretsDriver) Stop() error {
	if d.monitorCancel != nil {
		d.monitorCancel()
	}

	if d.monitor != nil {
		d.monitor.Stop()
	}

	if d.webInterface != nil {
		if err := d.webInterface.Stop(); err != nil {
			log.Warnf("Error stopping web interface: %v", err)
		}
	}

	if d.provider != nil {
		if err := d.provider.Close(); err != nil {
			log.Warnf("Error closing provider: %v", err)
		}
	}

	if d.dockerClient != nil {
		return d.dockerClient.Close()
	}
	return nil
}
