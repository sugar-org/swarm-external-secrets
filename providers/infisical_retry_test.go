package providers

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestInfisicalRetryStatus(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		status   int
		attempts int32
	}{
		{400, 1},
		{401, 1},
		{403, 1},
		{404, 1},
		{429, 3},
		{500, 3},
		{502, 3},
		{503, 3},
		{504, 3},
	} {
		t.Run(http.StatusText(test.status), func(t *testing.T) {
			t.Parallel()
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.Header().Set("Retry-After", "0")
				w.WriteHeader(test.status)
			}))
			defer server.Close()
			provider := infisicalProviderForServer(t, server.URL, "st.test")
			defer func() { _ = provider.Close() }()
			_, err := provider.GetSecret(context.Background(), &SecretInfo{DockerSecretName: "x", SecretPath: "proj-1/dev/X"})
			if err == nil {
				t.Fatal("expected status error")
			}
			if calls.Load() != test.attempts {
				t.Fatalf("calls = %d, want %d", calls.Load(), test.attempts)
			}
		})
	}
}

func TestInfisicalRetryAfterBound(t *testing.T) {
	t.Parallel()
	for _, raw := range []string{"999999999999", "9223372036854775807", "5"} {
		delay, ok := parseInfisicalRetryAfter(raw)
		if !ok || delay != infisicalMaxBackoff {
			t.Fatalf("Retry-After %q = %v, %v", raw, delay, ok)
		}
	}
	for attempt := 0; attempt < 10; attempt++ {
		delay := infisicalJitter(attempt)
		if delay < 0 || delay > infisicalMaxBackoff {
			t.Fatalf("jitter = %v", delay)
		}
	}
}

func TestInfisicalRetryBackoffCancellation(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Retry-After", "999999")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer server.Close()
	provider := infisicalProviderForServer(t, server.URL, "st.test")
	defer func() { _ = provider.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, err := provider.GetSecret(ctx, &SecretInfo{DockerSecretName: "x", SecretPath: "proj-1/dev/X"})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %v", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("calls = %d", calls.Load())
	}
}

func TestInfisicalClientTimeoutRetry(t *testing.T) {
	original := infisicalHTTPClient
	infisicalHTTPClient = &http.Client{Timeout: 30 * time.Millisecond}
	t.Cleanup(func() { infisicalHTTPClient = original })
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			<-r.Context().Done()
			return
		}
		_, _ = w.Write([]byte(`{"secret":{"secretValue":"ok"}}`))
	}))
	defer server.Close()
	provider := infisicalProviderForServer(t, server.URL, "st.test")
	defer func() { _ = provider.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	value, err := provider.GetSecret(ctx, &SecretInfo{DockerSecretName: "x", SecretPath: "proj-1/dev/X"})
	if err != nil || string(value) != "ok" || calls.Load() != 2 {
		t.Fatalf("value=%q error=%v calls=%d", value, err, calls.Load())
	}
}

func TestInfisicalAuthRefresh(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name         string
		renewalFails bool
	}{
		{name: "renew"},
		{name: "reauthenticate", renewalFails: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			var logins, renewals atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch r.URL.Path {
				case "/api/v1/auth/universal-auth/login":
					logins.Add(1)
					_, _ = w.Write([]byte(`{"accessToken":"login-token","expiresIn":7200,"accessTokenMaxTTL":86400}`))
				case "/api/v1/auth/token/renew":
					renewals.Add(1)
					if test.renewalFails {
						w.WriteHeader(http.StatusUnauthorized)
						return
					}
					_, _ = w.Write([]byte(`{"accessToken":"renewed-token","expiresIn":7200,"accessTokenMaxTTL":86400}`))
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			provider := infisicalProviderForServer(t, server.URL, "")
			provider.config.ClientID, provider.config.ClientSecret = "cid", "secret"
			defer func() { _ = provider.Close() }()
			if _, err := provider.authenticationToken(context.Background()); err != nil {
				t.Fatal(err)
			}
			provider.expiresAt = time.Now().Add(-time.Second)
			var workers sync.WaitGroup
			for worker := 0; worker < 10; worker++ {
				workers.Go(func() {
					if _, err := provider.authenticationToken(context.Background()); err != nil {
						t.Error(err)
					}
				})
			}
			workers.Wait()
			wantLogins := int32(1)
			if test.renewalFails {
				wantLogins = 2
			}
			if logins.Load() != wantLogins || renewals.Load() != 1 {
				t.Fatalf("logins=%d renewals=%d", logins.Load(), renewals.Load())
			}
			provider.expiresAt = time.Now().Add(-time.Second)
			provider.maxTTLAt = time.Now().Add(-time.Second)
			if _, err := provider.authenticationToken(context.Background()); err != nil {
				t.Fatal(err)
			}
			if logins.Load() != wantLogins+1 || renewals.Load() != 1 {
				t.Fatalf("max TTL: logins=%d renewals=%d", logins.Load(), renewals.Load())
			}
		})
	}
}

func TestInfisicalAuthCancellation(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"deadline", "close"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			started, canceled := make(chan struct{}), make(chan struct{})
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				close(started)
				_, _ = io.Copy(io.Discard, r.Body)
				<-r.Context().Done()
				close(canceled)
			}))
			defer server.Close()
			provider := infisicalProviderForServer(t, server.URL, "")
			defer func() { _ = provider.Close() }()
			ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
			defer cancel()
			done := make(chan error, 1)
			go func() { _, err := provider.authenticationToken(ctx); done <- err }()
			<-started
			if name == "close" {
				_ = provider.Close()
			}
			if err := <-done; err == nil {
				t.Fatal("expected cancellation")
			}
			select {
			case <-canceled:
			case <-time.After(time.Second):
				t.Fatal("auth request was not canceled")
			}
		})
	}
}
