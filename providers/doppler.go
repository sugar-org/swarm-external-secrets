package providers

import (
	"context"
	cryptorand "crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/docker/go-plugins-helpers/secrets"
	log "github.com/sirupsen/logrus"

	"github.com/sugar-org/swarm-external-secrets/internal/utils"
)

const (
	defaultDopplerAPIURL   = "https://api.doppler.com"
	defaultDopplerCacheTTL = 30 * time.Second

	// dopplerAPIVersion is owned by this client. DOPPLER_API_URL is only the
	// origin; a future API would need its own request and response models.
	dopplerAPIVersion = "v3"

	dopplerMaxAttempts = 3
	dopplerRetryBase   = 100 * time.Millisecond

	// maxDopplerResponseBytes caps how much of an API response we read into
	// memory, guarding against a misbehaving or compromised server.
	maxDopplerResponseBytes = 10 << 20 // 10 MiB
)

// DopplerProvider implements the SecretsProvider interface for Doppler.
type DopplerProvider struct {
	config     *DopplerConfig
	httpClient *http.Client
	cache      map[dopplerCacheKey]dopplerCacheEntry
	cacheMu    sync.RWMutex
	fetchMu    sync.Mutex
	// generation invalidates in-flight downloads. It is bumped only while
	// fetchMu is held, and a response is stored only when it still matches.
	generation uint64
}

// DopplerConfig holds configuration for the Doppler API client.
type DopplerConfig struct {
	Token      string
	Project    string
	Config     string
	APIBaseURL string
	CacheTTL   time.Duration
}

// DopplerAPIError is a non-success response from the Doppler API.
type DopplerAPIError struct {
	Status    int
	RequestID string
	Messages  []string
}

func (e *DopplerAPIError) Error() string {
	detail := "request failed"
	if len(e.Messages) > 0 {
		detail = strings.Join(e.Messages, "; ")
	}
	if e.RequestID != "" {
		return fmt.Sprintf("doppler api status %d (request %s): %s", e.Status, e.RequestID, detail)
	}
	return fmt.Sprintf("doppler api status %d: %s", e.Status, detail)
}

type dopplerCacheKey struct {
	project string
	config  string
	secret  string
}

type dopplerCacheEntry struct {
	value      string
	fetchedAt  time.Time
	generation uint64
}

type dopplerConfigKey struct {
	project string
	config  string
}

// Initialize sets up the Doppler provider with the given configuration.
func (d *DopplerProvider) Initialize(config map[string]string) error {
	token := utils.GetConfigOrDefault(config, "DOPPLER_TOKEN", "")
	if token == "" {
		return fmt.Errorf("DOPPLER_TOKEN is required")
	}

	cacheTTL := defaultDopplerCacheTTL
	if rawTTL := utils.GetConfigOrDefault(config, "DOPPLER_CACHE_TTL", ""); rawTTL != "" {
		parsed, err := time.ParseDuration(rawTTL)
		if err != nil {
			return fmt.Errorf("invalid DOPPLER_CACHE_TTL %q: %w", rawTTL, err)
		}
		cacheTTL = parsed
	}

	apiBaseURL, err := validateDopplerAPIURL(utils.GetConfigOrDefault(config, "DOPPLER_API_URL", defaultDopplerAPIURL))
	if err != nil {
		return err
	}

	d.config = &DopplerConfig{
		Token:      token,
		Project:    utils.GetConfigOrDefault(config, "DOPPLER_PROJECT", ""),
		Config:     utils.GetConfigOrDefault(config, "DOPPLER_CONFIG", ""),
		APIBaseURL: apiBaseURL,
		CacheTTL:   cacheTTL,
	}
	d.httpClient = &http.Client{Timeout: 30 * time.Second}
	d.cache = make(map[dopplerCacheKey]dopplerCacheEntry)

	if !isDopplerServiceToken(d.config.Token) {
		if d.config.Project == "" || d.config.Config == "" {
			return fmt.Errorf("DOPPLER_PROJECT and DOPPLER_CONFIG are required when not using a service token")
		}
	}

	log.Infof("Successfully initialized Doppler provider (cache TTL: %v)", d.config.CacheTTL)
	return nil
}

// GetSecret retrieves a secret value from Doppler.
func (d *DopplerProvider) GetSecret(ctx context.Context, secretInfo *SecretInfo) ([]byte, error) {
	secretName := d.resolveSecretName(secretInfo)
	project, configName := d.parseSecretPath(secretInfo.SecretPath)

	log.Debugf("Reading secret from Doppler: %s (project=%s, config=%s)", secretName, project, configName)

	value, err := d.getSecretValue(ctx, project, configName, secretName)
	if err != nil {
		return nil, err
	}

	log.Debug("Successfully retrieved secret from Doppler")
	return []byte(value), nil
}

// SupportsRotation indicates that Doppler supports secret rotation monitoring.
func (d *DopplerProvider) SupportsRotation() bool {
	return true
}

// GetSecretFieldLabel returns the label key used by Doppler for the secret name.
func (d *DopplerProvider) GetSecretFieldLabel() string {
	return "doppler_secret_name"
}

// BuildSecretPath constructs the Doppler secret path from the request.
func (d *DopplerProvider) BuildSecretPath(req secrets.Request) string {
	secretName := d.resolveSecretNameFromRequest(req)
	project, configName := d.resolveProjectConfigFromRequest(req)
	return fmt.Sprintf("%s/%s/%s", project, configName, secretName)
}

// GetProviderName returns the name of this provider.
func (d *DopplerProvider) GetProviderName() string {
	return "doppler"
}

// Close performs cleanup for the Doppler provider.
func (d *DopplerProvider) Close() error {
	return nil
}

// CacheInvalidator is an optional interface for providers that cache secret
// lookups. The driver drops that cache when a webhook says values changed.
//
// DopplerProvider is the only implementer, so the interface lives here rather
// than in interface.go. Providers that do not cache are skipped.
type CacheInvalidator interface {
	InvalidateCache()
}

// ReconciliationPreparer is an optional interface for providers that should
// refresh cached secrets once per rotation cycle. One call can fill the cache
// for every secret in a config, so the checks that follow share that download.
type ReconciliationPreparer interface {
	PrepareReconciliation(ctx context.Context, infos []*SecretInfo) error
}

// InvalidateCache drops cached Doppler downloads. It takes fetchMu before
// cacheMu, same as the fetch path, and bumps generation so a response that
// started earlier cannot be stored afterward.
func (d *DopplerProvider) InvalidateCache() {
	d.fetchMu.Lock()
	defer d.fetchMu.Unlock()
	d.invalidateLocked()
}

// PrepareReconciliation drops the cache and downloads the named secrets once
// per project and config. Later GetSecret calls in the same cycle reuse it.
func (d *DopplerProvider) PrepareReconciliation(ctx context.Context, infos []*SecretInfo) error {
	groups := d.groupSecretInfos(infos)

	d.fetchMu.Lock()
	defer d.fetchMu.Unlock()
	generation := d.invalidateLocked()

	var joined error
	for key, names := range groups {
		secretsMap, err := d.downloadSecrets(ctx, key.project, key.config, names)
		if err != nil {
			joined = errors.Join(joined, err)
			continue
		}
		for _, name := range names {
			value, ok := secretsMap[name]
			if !ok {
				continue
			}
			d.store(dopplerCacheKey{project: key.project, config: key.config, secret: name}, value, generation)
		}
	}
	return joined
}

func (d *DopplerProvider) resolveSecretNameFromRequest(req secrets.Request) string {
	if customName, exists := req.SecretLabels["doppler_secret_name"]; exists && customName != "" {
		return customName
	}
	return strings.ToUpper(req.SecretName)
}

func (d *DopplerProvider) resolveSecretName(secretInfo *SecretInfo) string {
	if secretInfo.SecretField != "" && secretInfo.SecretField != "value" {
		return secretInfo.SecretField
	}
	if name, exists := secretInfo.Labels["doppler_secret_name"]; exists && name != "" {
		return name
	}
	return strings.ToUpper(secretInfo.DockerSecretName)
}

func (d *DopplerProvider) resolveProjectConfigFromRequest(req secrets.Request) (string, string) {
	project := d.config.Project
	configName := d.config.Config

	if override, exists := req.SecretLabels["doppler_project"]; exists && override != "" {
		project = override
	}
	if override, exists := req.SecretLabels["doppler_config"]; exists && override != "" {
		configName = override
	}

	return project, configName
}

func (d *DopplerProvider) parseSecretPath(secretPath string) (string, string) {
	parts := strings.SplitN(secretPath, "/", 3)
	if len(parts) < 3 {
		return d.config.Project, d.config.Config
	}
	return parts[0], parts[1]
}

func (d *DopplerProvider) groupSecretInfos(infos []*SecretInfo) map[dopplerConfigKey][]string {
	groups := make(map[dopplerConfigKey][]string)
	seen := make(map[dopplerConfigKey]map[string]struct{})
	for _, info := range infos {
		if info == nil {
			continue
		}
		name := d.resolveSecretName(info)
		if name == "" {
			continue
		}
		project, configName := d.parseSecretPath(info.SecretPath)
		key := dopplerConfigKey{project: project, config: configName}
		if seen[key] == nil {
			seen[key] = make(map[string]struct{})
		}
		if _, ok := seen[key][name]; ok {
			continue
		}
		seen[key][name] = struct{}{}
		groups[key] = append(groups[key], name)
	}
	return groups
}

func isDopplerServiceToken(token string) bool {
	return strings.HasPrefix(token, "dp.st.")
}

func validateDopplerAPIURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("DOPPLER_API_URL is required")
	}

	parsed, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("invalid DOPPLER_API_URL: %w", err)
	}
	if parsed.Host == "" {
		return "", fmt.Errorf("DOPPLER_API_URL must include a host")
	}
	if parsed.User != nil {
		return "", fmt.Errorf("DOPPLER_API_URL must not include userinfo")
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", fmt.Errorf("DOPPLER_API_URL must not include a query or fragment")
	}
	if path := strings.Trim(parsed.EscapedPath(), "/"); path != "" {
		return "", fmt.Errorf("DOPPLER_API_URL must be an origin; the API version is fixed by the client")
	}

	switch parsed.Scheme {
	case "https":
	case "http":
		if !isLoopbackHost(parsed.Hostname()) {
			return "", fmt.Errorf("DOPPLER_API_URL must use https except for loopback hosts")
		}
	default:
		return "", fmt.Errorf("DOPPLER_API_URL must use https")
	}

	return parsed.Scheme + "://" + parsed.Host, nil
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func dopplerSecretsDownloadPath() string {
	path, err := url.JoinPath("/", dopplerAPIVersion, "configs", "config", "secrets", "download")
	if err != nil {
		return "/" + dopplerAPIVersion + "/configs/config/secrets/download"
	}
	return path
}

func (d *DopplerProvider) getSecretValue(ctx context.Context, project, configName, secretName string) (string, error) {
	if secretName == "" {
		return "", fmt.Errorf("doppler secret name is required")
	}
	key := dopplerCacheKey{project: project, config: configName, secret: secretName}
	if value, ok := d.cachedValue(key); ok {
		return value, nil
	}

	d.fetchMu.Lock()
	defer d.fetchMu.Unlock()

	if value, ok := d.cachedValue(key); ok {
		return value, nil
	}
	generation := d.generationSnapshot()

	secretsMap, err := d.downloadSecrets(ctx, project, configName, []string{secretName})
	if err != nil {
		return "", err
	}
	value, ok := secretsMap[secretName]
	if !ok {
		return "", fmt.Errorf("secret %q not found in Doppler config", secretName)
	}
	d.store(key, value, generation)
	return value, nil
}

func (d *DopplerProvider) invalidateLocked() uint64 {
	d.cacheMu.Lock()
	defer d.cacheMu.Unlock()
	d.generation++
	d.cache = make(map[dopplerCacheKey]dopplerCacheEntry)
	return d.generation
}

func (d *DopplerProvider) generationSnapshot() uint64 {
	d.cacheMu.RLock()
	defer d.cacheMu.RUnlock()
	return d.generation
}

func (d *DopplerProvider) cachedValue(key dopplerCacheKey) (string, bool) {
	d.cacheMu.RLock()
	defer d.cacheMu.RUnlock()

	entry, ok := d.cache[key]
	if !ok || entry.generation != d.generation || time.Since(entry.fetchedAt) >= d.config.CacheTTL {
		return "", false
	}
	return entry.value, true
}

func (d *DopplerProvider) store(key dopplerCacheKey, value string, generation uint64) {
	d.cacheMu.Lock()
	defer d.cacheMu.Unlock()
	if d.generation != generation {
		return
	}
	d.cache[key] = dopplerCacheEntry{
		value:      value,
		fetchedAt:  time.Now(),
		generation: generation,
	}
}

func (d *DopplerProvider) secretsDownloadURL(project, configName string, names []string) (string, error) {
	endpoint, err := url.JoinPath(d.config.APIBaseURL, dopplerAPIVersion, "configs", "config", "secrets", "download")
	if err != nil {
		return "", fmt.Errorf("invalid Doppler API URL: %w", err)
	}
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return "", fmt.Errorf("invalid Doppler API URL: %w", err)
	}

	query := parsed.Query()
	query.Set("format", "json")
	if project != "" {
		query.Set("project", project)
	}
	if configName != "" {
		query.Set("config", configName)
	}
	if len(names) > 0 {
		sorted := append([]string(nil), names...)
		slices.Sort(sorted)
		query.Set("secrets", strings.Join(sorted, ","))
	}
	parsed.RawQuery = query.Encode()
	return parsed.String(), nil
}

func (d *DopplerProvider) downloadSecrets(ctx context.Context, project, configName string, names []string) (map[string]string, error) {
	endpoint, err := d.secretsDownloadURL(project, configName, names)
	if err != nil {
		return nil, err
	}

	var lastErr error
	for attempt := 0; attempt < dopplerMaxAttempts; attempt++ {
		secretsMap, retryAfter, retry, err := d.downloadSecretsOnce(ctx, endpoint)
		if err == nil {
			return secretsMap, nil
		}
		lastErr = err
		if !retry || attempt == dopplerMaxAttempts-1 {
			return nil, err
		}
		delay := dopplerJitter(attempt)
		if retryAfter != nil {
			delay = *retryAfter
		}
		if err := sleepContext(ctx, delay); err != nil {
			return nil, err
		}
	}
	return nil, lastErr
}

func dopplerJitter(attempt int) time.Duration {
	shift := attempt
	if shift > 4 {
		shift = 4
	}
	ceiling := dopplerRetryBase << shift
	if ceiling < dopplerRetryBase {
		ceiling = dopplerRetryBase
	}
	n, err := cryptorand.Int(cryptorand.Reader, big.NewInt(int64(ceiling)+1))
	if err != nil {
		return ceiling / 2
	}
	return time.Duration(n.Int64())
}

func sleepContext(ctx context.Context, delay time.Duration) error {
	if delay <= 0 {
		return nil
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (d *DopplerProvider) downloadSecretsOnce(ctx context.Context, endpoint string) (map[string]string, *time.Duration, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, nil, false, fmt.Errorf("failed to create Doppler request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+d.config.Token)
	req.Header.Set("Accept", "application/json")

	// URL is validated at Initialize: https, or http only for a loopback host.
	resp, err := d.httpClient.Do(req) // #nosec G704
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, nil, false, fmt.Errorf("failed to call Doppler API: %w", err)
		}
		return nil, nil, true, fmt.Errorf("failed to call Doppler API: %w", err)
	}

	body, readErr := io.ReadAll(io.LimitReader(resp.Body, maxDopplerResponseBytes))
	_ = resp.Body.Close()
	if readErr != nil {
		return nil, nil, true, fmt.Errorf("failed to read Doppler response: %w", readErr)
	}

	if resp.StatusCode == http.StatusOK {
		var secretsMap map[string]string
		if err := json.Unmarshal(body, &secretsMap); err != nil {
			return nil, nil, false, fmt.Errorf("failed to parse Doppler response: %w", err)
		}
		return secretsMap, nil, false, nil
	}

	apiErr := &DopplerAPIError{
		Status:    resp.StatusCode,
		RequestID: dopplerRequestID(resp.Header),
		Messages:  parseDopplerMessages(body),
	}
	retry := dopplerRetryableStatus(resp.StatusCode)
	if !retry {
		return nil, nil, false, apiErr
	}
	retryAfter, hasRetryAfter := parseRetryAfter(resp.Header.Get("Retry-After"), time.Now())
	if !hasRetryAfter {
		return nil, nil, true, apiErr
	}
	return nil, &retryAfter, true, apiErr
}

func dopplerRetryableStatus(code int) bool {
	switch code {
	case http.StatusTooManyRequests,
		http.StatusInternalServerError,
		http.StatusBadGateway,
		http.StatusServiceUnavailable,
		http.StatusGatewayTimeout:
		return true
	default:
		return false
	}
}

func dopplerRequestID(header http.Header) string {
	if id := strings.TrimSpace(header.Get("X-Request-Id")); id != "" {
		return id
	}
	return strings.TrimSpace(header.Get("X-Doppler-Request-Id"))
}

func parseDopplerMessages(body []byte) []string {
	var payload struct {
		Messages []string `json:"messages"`
		Message  string   `json:"message"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil
	}
	if payload.Message != "" {
		payload.Messages = append(payload.Messages, payload.Message)
	}
	return payload.Messages
}

func parseRetryAfter(raw string, now time.Time) (time.Duration, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, false
	}
	if seconds, err := strconv.Atoi(raw); err == nil {
		if seconds < 0 {
			seconds = 0
		}
		return time.Duration(seconds) * time.Second, true
	}
	when, err := http.ParseTime(raw)
	if err != nil {
		return 0, false
	}
	delay := when.Sub(now)
	if delay < 0 {
		delay = 0
	}
	return delay, true
}
