package vaultcompat

import (
	"context"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/sugar-org/swarm-external-secrets/internal/utils"
	"github.com/sugar-org/swarm-external-secrets/internal/vaultcompat/vclient"
)

type fakeClientResult struct {
	secret *vclient.Secret
	err    error
}

type fakeAuthResult struct {
	auth *vclient.Auth
	err  error
}

type fakeVaultClient struct {
	mu sync.Mutex

	readResults  []fakeClientResult
	writeResults []fakeClientResult
	renewResults []fakeAuthResult

	readPaths   []string
	writePaths  []string
	renewCalls  int
	setTokens   []string
	closeCalled bool

	renewCalled chan struct{}
}

func (f *fakeVaultClient) Read(_ context.Context, path string) (*vclient.Secret, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if len(f.readResults) > 0 {
		result := f.readResults[0]
		f.readResults = f.readResults[1:]
		f.readPaths = append(f.readPaths, path)
		return result.secret, result.err
	}
	f.readPaths = append(f.readPaths, path)
	return nil, nil
}

func (f *fakeVaultClient) Write(_ context.Context, path string, _ map[string]any) (*vclient.Secret, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.writePaths = append(f.writePaths, path)
	if len(f.writeResults) == 0 {
		return nil, nil
	}

	result := f.writeResults[0]
	f.writeResults = f.writeResults[1:]
	return result.secret, result.err
}

func (f *fakeVaultClient) RenewSelf(context.Context, int) (*vclient.Auth, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.renewCalls++
	if f.renewCalled != nil {
		select {
		case f.renewCalled <- struct{}{}:
		default:
		}
	}
	if len(f.renewResults) == 0 {
		return nil, nil
	}

	result := f.renewResults[0]
	f.renewResults = f.renewResults[1:]
	return result.auth, result.err
}

func (f *fakeVaultClient) SetToken(token string) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.setTokens = append(f.setTokens, token)
}

func (f *fakeVaultClient) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.closeCalled = true
	return nil
}

func (f *fakeVaultClient) tokens() []string {
	f.mu.Lock()
	defer f.mu.Unlock()

	return slices.Clone(f.setTokens)
}

func (f *fakeVaultClient) writePathCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()

	return len(f.writePaths)
}

func (f *fakeVaultClient) wasClosed() bool {
	f.mu.Lock()
	defer f.mu.Unlock()

	return f.closeCalled
}

type fakeRenewalTimer struct {
	ch      chan time.Time
	delays  chan time.Duration
	onReset func()
}

func (f *fakeRenewalTimer) C() <-chan time.Time {
	return f.ch
}

func (f *fakeRenewalTimer) Reset(delay time.Duration) bool {
	if f.delays != nil {
		f.delays <- delay
	}
	if f.onReset != nil {
		f.onReset()
	}
	return true
}

func (f *fakeRenewalTimer) Stop() bool {
	return true
}

func TestBackend_GetSecretReauthenticatesOnAuthError(t *testing.T) {
	client := &fakeVaultClient{
		readResults: []fakeClientResult{
			{err: vclient.ErrAuthFailed},
			{secret: &vclient.Secret{Data: map[string]any{"data": map[string]any{"password": "rotated"}}}},
		},
		writeResults: []fakeClientResult{
			{secret: &vclient.Secret{Auth: &vclient.Auth{ClientToken: "token-2"}}},
		},
	}
	backend := newTestBackend(t, client, &vclient.Auth{ClientToken: "token-1"})
	defer func() { _ = backend.Close() }()

	got, err := backend.GetSecret(context.Background(), &utils.SecretInfo{
		SecretPath:  "secret/data/database",
		SecretField: "password",
	})
	if err != nil {
		t.Fatalf("GetSecret() error = %v", err)
	}
	if string(got) != "rotated" {
		t.Fatalf("GetSecret() = %q, want rotated", string(got))
	}

	if client.writePathCount() != 1 {
		t.Fatalf("write calls = %d, want 1", client.writePathCount())
	}
	if !slices.Contains(client.tokens(), "token-2") {
		t.Fatalf("SetToken calls = %v, want token-2", client.tokens())
	}
}

func TestBackend_GetSecret_KVVersionExtraction(t *testing.T) {
	// A KV v1 secret may legitimately contain both a top-level field and a
	// nested "data" map. KV v1 must read the top-level field directly, while
	// KV v2 (including empty version for backward compatibility) unwraps it.
	v1Data := map[string]any{
		"password": "current",
		"data":     map[string]any{"password": "other"},
	}
	v2Data := map[string]any{
		"data": map[string]any{"password": "other"},
	}

	tests := []struct {
		name      string
		kvVersion string
		data      map[string]any
		want      string
	}{
		{name: "v1 reads top-level field beside nested data", kvVersion: "1", data: v1Data, want: "current"},
		{name: "v2 unwraps nested data", kvVersion: "2", data: v1Data, want: "other"},
		{name: "empty version keeps v2 unwrapping", kvVersion: "", data: v1Data, want: "other"},
		{name: "v2 nested-only response", kvVersion: "2", data: v2Data, want: "other"},
		{name: "v1 flat response", kvVersion: "1", data: map[string]any{"password": "current"}, want: "current"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &fakeVaultClient{
				readResults: []fakeClientResult{
					{secret: &vclient.Secret{Data: tt.data}},
				},
			}
			backend := newTestBackend(t, client, &vclient.Auth{ClientToken: "token-1"})
			backend.config.KVVersion = tt.kvVersion
			defer func() { _ = backend.Close() }()

			got, err := backend.GetSecret(context.Background(), &utils.SecretInfo{
				SecretPath:  "secret/database",
				SecretField: "password",
			})
			if err != nil {
				t.Fatalf("GetSecret() error = %v", err)
			}
			if string(got) != tt.want {
				t.Fatalf("GetSecret() = %q, want %q (KVVersion=%q)", got, tt.want, tt.kvVersion)
			}
		})
	}
}

func TestBackend_TokenRenewalUpdatesToken(t *testing.T) {
	client := &fakeVaultClient{
		renewCalled: make(chan struct{}, 1),
		renewResults: []fakeAuthResult{
			{auth: &vclient.Auth{ClientToken: "token-2", Renewable: true, LeaseTTL: 120}},
		},
	}
	backend := newTestBackend(t, client, &vclient.Auth{
		ClientToken: "token-1",
		Renewable:   true,
		LeaseTTL:    60,
	})
	trigger := make(chan time.Time, 1)
	delays := make(chan time.Duration, 2)
	backend.newTimer = func() renewalTimer {
		return &fakeRenewalTimer{
			ch:     trigger,
			delays: delays,
		}
	}
	backend.startTokenRenewal()
	defer func() { _ = backend.Close() }()

	if delay := <-delays; delay != 40*time.Second {
		t.Fatalf("renew delay = %v, want 40s", delay)
	}
	trigger <- time.Now()

	waitFor(t, func() bool {
		return slices.Contains(client.tokens(), "token-2")
	})
}

func TestBackend_TokenRenewalReauthenticatesOnFailure(t *testing.T) {
	client := &fakeVaultClient{
		renewCalled: make(chan struct{}, 1),
		renewResults: []fakeAuthResult{
			{err: vclient.ErrAuthFailed},
		},
		writeResults: []fakeClientResult{
			{secret: &vclient.Secret{Auth: &vclient.Auth{
				ClientToken: "token-reauth",
				Renewable:   true,
				LeaseTTL:    120,
			}}},
		},
	}
	backend := newTestBackend(t, client, &vclient.Auth{
		ClientToken: "token-1",
		Renewable:   true,
		LeaseTTL:    60,
	})
	trigger := make(chan time.Time, 1)
	backend.newTimer = func() renewalTimer {
		return &fakeRenewalTimer{ch: trigger}
	}
	backend.startTokenRenewal()
	defer func() { _ = backend.Close() }()

	trigger <- time.Now()

	waitFor(t, func() bool {
		return client.writePathCount() == 1 && slices.Contains(client.tokens(), "token-reauth")
	})
}

func TestBackend_CloseStopsRenewalWorker(t *testing.T) {
	client := &fakeVaultClient{}
	backend := newTestBackend(t, client, &vclient.Auth{
		ClientToken: "token-1",
		Renewable:   true,
		LeaseTTL:    60,
	})
	waiting := make(chan struct{}, 1)
	never := make(chan time.Time)
	backend.newTimer = func() renewalTimer {
		return &fakeRenewalTimer{
			ch: never,
			onReset: func() {
				waiting <- struct{}{}
			},
		}
	}
	backend.startTokenRenewal()

	select {
	case <-waiting:
	case <-time.After(time.Second):
		t.Fatal("renewal worker did not start")
	}

	closed := make(chan struct{})
	go func() {
		defer close(closed)
		if err := backend.Close(); err != nil {
			t.Errorf("Close() error = %v", err)
		}
	}()

	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("Close() did not stop renewal worker")
	}
	if !client.wasClosed() {
		t.Fatal("client was not closed")
	}
}

func TestNextRetryWaitCapsAtMax(t *testing.T) {
	tests := []struct {
		name string
		in   time.Duration
		want time.Duration
	}{
		{
			name: "doubles below cap",
			in:   5 * time.Second,
			want: 10 * time.Second,
		},
		{
			name: "caps at max",
			in:   renewalRetryMaxWait,
			want: renewalRetryMaxWait,
		},
		{
			name: "does not exceed max",
			in:   45 * time.Second,
			want: renewalRetryMaxWait,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := nextRetryWait(tt.in); got != tt.want {
				t.Fatalf("nextRetryWait(%v) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func TestRetryDelayWithJitterStaysWithinExpectedRange(t *testing.T) {
	base := 10 * time.Second

	for range 100 {
		got := retryDelayWithJitter(base)
		if got < base {
			t.Fatalf("retryDelayWithJitter(%v) = %v, want >= %v", base, got, base)
		}
		if got >= base+(base/2) {
			t.Fatalf("retryDelayWithJitter(%v) = %v, want < %v", base, got, base+(base/2))
		}
	}
}

func newTestBackend(t *testing.T, client vclient.Client, auth *vclient.Auth) *Backend {
	t.Helper()

	cfg := Config{
		ProviderName: "vault",
		AuthMethod:   "jwt",
		JWTRole:      "swarm-external-secrets",
		JWT:          "test.jwt.token",
	}
	method, err := newLoginMethod(cfg)
	if err != nil {
		t.Fatalf("newLoginMethod() error = %v", err)
	}

	renewCtx, renewCancel := context.WithCancel(context.Background())
	return &Backend{
		client:      client,
		config:      cfg,
		loginMethod: method,
		auth:        auth,
		renewCtx:    renewCtx,
		renewCancel: renewCancel,
		newTimer:    newStoppedRenewalTimer,
	}
}

func waitFor(t *testing.T, condition func() bool) {
	t.Helper()

	deadline := time.After(time.Second)
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()

	for {
		if condition() {
			return
		}

		select {
		case <-deadline:
			t.Fatal("condition was not met before timeout")
		case <-ticker.C:
		}
	}
}
