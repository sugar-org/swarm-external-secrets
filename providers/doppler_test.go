package providers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/docker/go-plugins-helpers/secrets"
)

func TestDopplerProviderInitialize(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		config  map[string]string
		wantErr string
	}{
		{
			name:    "missing token",
			config:  map[string]string{},
			wantErr: "DOPPLER_TOKEN is required",
		},
		{
			name: "cli token requires project and config",
			config: map[string]string{
				"DOPPLER_TOKEN": "dp.pt.example",
			},
			wantErr: "DOPPLER_PROJECT and DOPPLER_CONFIG are required",
		},
		{
			name: "service token only",
			config: map[string]string{
				"DOPPLER_TOKEN": "dp.st.example",
			},
		},
		{
			name: "cli token with project and config",
			config: map[string]string{
				"DOPPLER_TOKEN":   "dp.pt.example",
				"DOPPLER_PROJECT": "my-api",
				"DOPPLER_CONFIG":  "dev",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			provider := &DopplerProvider{}
			err := provider.Initialize(tt.config)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("expected error containing %q, got %v", tt.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestDopplerProviderGetSecret(t *testing.T) {
	provider, _ := setupDopplerProvider(t, map[string]string{
		"MYSQL_PASSWORD": "secret-value",
		"API_KEY":        "key-value",
	}, "1m")

	t.Run("explicit label", func(t *testing.T) {
		req := secrets.Request{
			SecretName: "mysql_password",
			SecretLabels: map[string]string{
				"doppler_secret_name": "MYSQL_PASSWORD",
			},
		}
		got := mustGetSecret(t, provider, &SecretInfo{
			DockerSecretName: req.SecretName,
			SecretPath:       provider.BuildSecretPath(req),
			SecretField:      "MYSQL_PASSWORD",
			Labels:           req.SecretLabels,
		})
		if got != "secret-value" {
			t.Fatalf("expected secret-value, got %q", got)
		}
	})

	t.Run("uppercase fallback", func(t *testing.T) {
		got := mustGetSecret(t, provider, &SecretInfo{
			DockerSecretName: "api_key",
			SecretPath:       provider.BuildSecretPath(secrets.Request{SecretName: "api_key"}),
			SecretField:      "value",
		})
		if got != "key-value" {
			t.Fatalf("expected key-value, got %q", got)
		}
	})
}

func TestDopplerProviderCaching(t *testing.T) {
	t.Parallel()

	provider, state := setupDopplerProvider(t, map[string]string{"CACHE_TEST": "v1"}, "1m")
	info := &SecretInfo{
		DockerSecretName: "cache_test",
		SecretPath:       "my-api/dev/CACHE_TEST",
		SecretField:      "CACHE_TEST",
	}

	if got := mustGetSecret(t, provider, info); got != "v1" {
		t.Fatalf("expected v1, got %q", got)
	}
	assertRequestCount(t, state, 1)

	state.secrets["CACHE_TEST"] = "v2"
	if got := mustGetSecret(t, provider, info); got != "v1" {
		t.Fatalf("expected cached value v1, got %q", got)
	}
	assertRequestCount(t, state, 1)
}

func TestDopplerProviderRefreshAfterCacheTTL(t *testing.T) {
	t.Parallel()

	provider, state := setupDopplerProvider(t, map[string]string{"ROTATE_ME": "v1"}, "50ms")
	info := &SecretInfo{
		SecretPath:  "my-api/dev/ROTATE_ME",
		SecretField: "ROTATE_ME",
	}

	if got := mustGetSecret(t, provider, info); got != "v1" {
		t.Fatalf("expected v1, got %q", got)
	}
	assertRequestCount(t, state, 1)

	state.secrets["ROTATE_ME"] = "v2"
	if got := mustGetSecret(t, provider, info); got != "v1" {
		t.Fatalf("expected cached value v1, got %q", got)
	}
	assertRequestCount(t, state, 1)

	time.Sleep(75 * time.Millisecond)

	if got := mustGetSecret(t, provider, info); got != "v2" {
		t.Fatalf("expected refreshed value v2, got %q", got)
	}
	assertRequestCount(t, state, 2)
}

func TestDopplerProviderBuildSecretPath(t *testing.T) {
	t.Parallel()

	provider := &DopplerProvider{}
	if err := provider.Initialize(map[string]string{
		"DOPPLER_TOKEN":   "dp.st.example",
		"DOPPLER_PROJECT": "my-api",
		"DOPPLER_CONFIG":  "dev",
	}); err != nil {
		t.Fatalf("initialize failed: %v", err)
	}

	got := provider.BuildSecretPath(secrets.Request{
		SecretName: "mysql_password",
		SecretLabels: map[string]string{
			"doppler_secret_name": "MYSQL_PASSWORD",
		},
	})
	want := "my-api/dev/MYSQL_PASSWORD"
	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}

type dopplerTestState struct {
	secrets      map[string]string
	requestCount atomic.Int32
}

func (s *dopplerTestState) handler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != dopplerSecretsDownloadPath() {
		http.NotFound(w, r)
		return
	}
	if r.Header.Get("Authorization") != "Bearer dp.pt.test" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	s.requestCount.Add(1)
	payload := map[string]string{}
	raw := r.URL.Query().Get("secrets")
	if raw == "" {
		for name, value := range s.secrets {
			payload[name] = value
		}
	} else {
		for _, name := range strings.Split(raw, ",") {
			if value, ok := s.secrets[name]; ok {
				payload[name] = value
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(payload)
}

func setupDopplerProvider(t *testing.T, secretsMap map[string]string, cacheTTL string) (*DopplerProvider, *dopplerTestState) {
	t.Helper()
	state := &dopplerTestState{secrets: secretsMap}
	server := httptest.NewServer(http.HandlerFunc(state.handler))
	t.Cleanup(server.Close)

	provider := &DopplerProvider{}
	if err := provider.Initialize(map[string]string{
		"DOPPLER_TOKEN":     "dp.pt.test",
		"DOPPLER_PROJECT":   "my-api",
		"DOPPLER_CONFIG":    "dev",
		"DOPPLER_API_URL":   server.URL,
		"DOPPLER_CACHE_TTL": cacheTTL,
	}); err != nil {
		t.Fatalf("initialize failed: %v", err)
	}
	return provider, state
}

func mustGetSecret(t *testing.T, provider *DopplerProvider, info *SecretInfo) string {
	t.Helper()
	value, err := provider.GetSecret(context.Background(), info)
	if err != nil {
		t.Fatalf("GetSecret failed: %v", err)
	}
	return string(value)
}

func assertRequestCount(t *testing.T, state *dopplerTestState, want int32) {
	t.Helper()
	if got := state.requestCount.Load(); got != want {
		t.Fatalf("expected %d API calls, got %d", want, got)
	}
}

func TestValidateDopplerAPIURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		raw     string
		want    string
		wantErr string
	}{
		{name: "https origin", raw: "https://api.doppler.com", want: "https://api.doppler.com"},
		{name: "https with trailing slash", raw: "https://api.doppler.com/", want: "https://api.doppler.com"},
		{name: "loopback ipv4", raw: "http://127.0.0.1:18080", want: "http://127.0.0.1:18080"},
		{name: "localhost", raw: "http://localhost:8080", want: "http://localhost:8080"},
		{name: "ipv6 loopback", raw: "http://[::1]:9", want: "http://[::1]:9"},
		{name: "plaintext public host", raw: "http://api.doppler.com", wantErr: "must use https"},
		{name: "plaintext private ip", raw: "http://10.1.2.3", wantErr: "must use https"},
		{name: "version in path", raw: "https://api.doppler.com/v3", wantErr: "must be an origin"},
		{name: "userinfo", raw: "https://user:pass@api.doppler.com", wantErr: "userinfo"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := validateDopplerAPIURL(tt.raw)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("validateDopplerAPIURL(%q) error = %v, want %q", tt.raw, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("validateDopplerAPIURL(%q) error = %v", tt.raw, err)
			}
			if got != tt.want {
				t.Fatalf("validateDopplerAPIURL(%q) = %q, want %q", tt.raw, got, tt.want)
			}
		})
	}
}

func TestDopplerProviderGetSecretFiltersByName(t *testing.T) {
	t.Parallel()

	var gotFilter atomic.Value
	state := &dopplerTestState{secrets: map[string]string{
		"WANTED": "yes",
		"OTHER":  "no",
	}}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotFilter.Store(r.URL.Query().Get("secrets"))
		state.handler(w, r)
	}))
	t.Cleanup(server.Close)

	provider := &DopplerProvider{}
	if err := provider.Initialize(map[string]string{
		"DOPPLER_TOKEN":     "dp.pt.test",
		"DOPPLER_PROJECT":   "my-api",
		"DOPPLER_CONFIG":    "dev",
		"DOPPLER_API_URL":   server.URL,
		"DOPPLER_CACHE_TTL": "1m",
	}); err != nil {
		t.Fatalf("initialize failed: %v", err)
	}

	got := mustGetSecret(t, provider, &SecretInfo{
		SecretPath:  "my-api/dev/WANTED",
		SecretField: "WANTED",
	})
	if got != "yes" {
		t.Fatalf("GetSecret() = %q, want yes", got)
	}
	if filter := gotFilter.Load().(string); filter != "WANTED" {
		t.Fatalf("secrets filter = %q, want WANTED", filter)
	}
}

func TestDopplerProviderPrepareReconciliationBypassesCache(t *testing.T) {
	t.Parallel()

	provider, state := setupDopplerProvider(t, map[string]string{
		"ONE": "v1",
		"TWO": "v1",
	}, "1h")
	one := &SecretInfo{SecretPath: "my-api/dev/ONE", SecretField: "ONE"}
	two := &SecretInfo{SecretPath: "my-api/dev/TWO", SecretField: "TWO"}

	if got := mustGetSecret(t, provider, one); got != "v1" {
		t.Fatalf("GetSecret(ONE) = %q, want v1", got)
	}
	assertRequestCount(t, state, 1)

	state.secrets["ONE"] = "v2"
	state.secrets["TWO"] = "v2"
	if err := provider.PrepareReconciliation(context.Background(), []*SecretInfo{one, two}); err != nil {
		t.Fatalf("PrepareReconciliation() error = %v", err)
	}
	assertRequestCount(t, state, 2)

	if got := mustGetSecret(t, provider, one); got != "v2" {
		t.Fatalf("GetSecret(ONE) after prepare = %q, want v2", got)
	}
	if got := mustGetSecret(t, provider, two); got != "v2" {
		t.Fatalf("GetSecret(TWO) after prepare = %q, want v2", got)
	}
	assertRequestCount(t, state, 2)
}

func TestDopplerProviderInvalidateCacheDropsInFlightResponse(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	var current atomic.Value
	current.Store("old")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		value, _ := current.Load().(string)
		if n == 1 {
			close(started)
			<-release
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"ROTATE_ME": value})
	}))
	t.Cleanup(server.Close)

	provider := &DopplerProvider{}
	if err := provider.Initialize(map[string]string{
		"DOPPLER_TOKEN":     "dp.pt.test",
		"DOPPLER_PROJECT":   "my-api",
		"DOPPLER_CONFIG":    "dev",
		"DOPPLER_API_URL":   server.URL,
		"DOPPLER_CACHE_TTL": "1h",
	}); err != nil {
		t.Fatalf("initialize failed: %v", err)
	}

	info := &SecretInfo{SecretPath: "my-api/dev/ROTATE_ME", SecretField: "ROTATE_ME"}
	errCh := make(chan error, 1)
	go func() {
		got, err := provider.GetSecret(context.Background(), info)
		if err != nil {
			errCh <- err
			return
		}
		if string(got) != "old" {
			errCh <- fmt.Errorf("in-flight GetSecret() = %q, want old", got)
			return
		}
		errCh <- nil
	}()

	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("download did not start")
	}

	current.Store("new")
	invalidateDone := make(chan struct{})
	go func() {
		provider.InvalidateCache()
		close(invalidateDone)
	}()

	select {
	case <-invalidateDone:
		t.Fatal("InvalidateCache returned while the download was still in flight")
	case <-time.After(50 * time.Millisecond):
	}

	close(release)

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("GetSecret did not return")
	}
	select {
	case <-invalidateDone:
	case <-time.After(2 * time.Second):
		t.Fatal("InvalidateCache did not return")
	}

	if got := mustGetSecret(t, provider, info); got != "new" {
		t.Fatalf("GetSecret() after invalidation = %q, want new", got)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("API calls = %d, want 2", got)
	}
}

func TestDopplerProviderRetriesRetryAfter(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		if n == 1 {
			w.Header().Set("Retry-After", "1")
			w.Header().Set("X-Request-Id", "req-429")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"messages":["slow down"]}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"RETRY_ME": "ok"})
	}))
	t.Cleanup(server.Close)

	provider := &DopplerProvider{}
	if err := provider.Initialize(map[string]string{
		"DOPPLER_TOKEN":     "dp.pt.test",
		"DOPPLER_PROJECT":   "my-api",
		"DOPPLER_CONFIG":    "dev",
		"DOPPLER_API_URL":   server.URL,
		"DOPPLER_CACHE_TTL": "1s",
	}); err != nil {
		t.Fatalf("initialize failed: %v", err)
	}

	start := time.Now()
	got := mustGetSecret(t, provider, &SecretInfo{SecretPath: "my-api/dev/RETRY_ME", SecretField: "RETRY_ME"})
	if got != "ok" {
		t.Fatalf("GetSecret() = %q, want ok", got)
	}
	if calls.Load() != 2 {
		t.Fatalf("API calls = %d, want 2", calls.Load())
	}
	if time.Since(start) < 900*time.Millisecond {
		t.Fatalf("retry returned in %s, want at least the Retry-After delay", time.Since(start))
	}
}

func TestDopplerProviderRetriesServerError(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			http.Error(w, `{"messages":["unavailable"]}`, http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"RETRY_ME": "ok"})
	}))
	t.Cleanup(server.Close)

	provider := &DopplerProvider{}
	if err := provider.Initialize(map[string]string{
		"DOPPLER_TOKEN":     "dp.pt.test",
		"DOPPLER_PROJECT":   "my-api",
		"DOPPLER_CONFIG":    "dev",
		"DOPPLER_API_URL":   server.URL,
		"DOPPLER_CACHE_TTL": "1s",
	}); err != nil {
		t.Fatalf("initialize failed: %v", err)
	}

	if got := mustGetSecret(t, provider, &SecretInfo{SecretPath: "my-api/dev/RETRY_ME", SecretField: "RETRY_ME"}); got != "ok" {
		t.Fatalf("GetSecret() = %q, want ok", got)
	}
	if calls.Load() != 2 {
		t.Fatalf("API calls = %d, want 2", calls.Load())
	}
}

func TestDopplerProviderAPIErrorDoesNotRetry(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("X-Request-Id", "req-400")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"messages":["bad project"],"message":"extra"}`))
	}))
	t.Cleanup(server.Close)

	provider := &DopplerProvider{}
	if err := provider.Initialize(map[string]string{
		"DOPPLER_TOKEN":     "dp.pt.test",
		"DOPPLER_PROJECT":   "my-api",
		"DOPPLER_CONFIG":    "dev",
		"DOPPLER_API_URL":   server.URL,
		"DOPPLER_CACHE_TTL": "1s",
	}); err != nil {
		t.Fatalf("initialize failed: %v", err)
	}

	_, err := provider.GetSecret(context.Background(), &SecretInfo{
		SecretPath:  "my-api/dev/NOPE",
		SecretField: "NOPE",
	})
	var apiErr *DopplerAPIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("GetSecret() error = %v, want DopplerAPIError", err)
	}
	if apiErr.Status != http.StatusBadRequest || apiErr.RequestID != "req-400" {
		t.Fatalf("api error = %+v", apiErr)
	}
	if strings.Contains(err.Error(), "bad project") && strings.Contains(err.Error(), "{") {
		t.Fatalf("error included raw body: %v", err)
	}
	if len(apiErr.Messages) != 2 || apiErr.Messages[0] != "bad project" || apiErr.Messages[1] != "extra" {
		t.Fatalf("messages = %#v", apiErr.Messages)
	}
	if calls.Load() != 1 {
		t.Fatalf("API calls = %d, want 1", calls.Load())
	}
}

func TestParseRetryAfter(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)
	delay, ok := parseRetryAfter("2", now)
	if !ok || delay != 2*time.Second {
		t.Fatalf("seconds parse = %s, %v", delay, ok)
	}
	delay, ok = parseRetryAfter(now.Add(3*time.Second).Format(http.TimeFormat), now)
	if !ok || delay < 2*time.Second || delay > 4*time.Second {
		t.Fatalf("http-date parse = %s, %v", delay, ok)
	}
	if _, ok = parseRetryAfter("", now); ok {
		t.Fatal("empty Retry-After was accepted")
	}
}
