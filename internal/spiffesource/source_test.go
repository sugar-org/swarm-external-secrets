package spiffesource

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

type fakeFetcher struct {
	token          string
	err            error
	audience       string
	closed         bool
	waitForContext bool
	started        chan struct{}
}

func (f *fakeFetcher) FetchJWTSVID(ctx context.Context, audience string) (string, error) {
	f.audience = audience
	if f.started != nil {
		close(f.started)
	}
	if f.waitForContext {
		<-ctx.Done()
		return "", ctx.Err()
	}
	return f.token, f.err
}

func (f *fakeFetcher) Close() error {
	f.closed = true
	return f.err
}

func TestNew_Validation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		socketAddr string
		audience   string
		wantErr    string
	}{
		{
			name:       "missing socket path",
			socketAddr: "unix://",
			audience:   "swarm-external-secrets",
			wantErr:    "SPIFFE_ENDPOINT_SOCKET must be a unix socket URL",
		},
		{
			name:       "unsupported socket scheme",
			socketAddr: "tcp://127.0.0.1:8080",
			audience:   "swarm-external-secrets",
			wantErr:    "SPIFFE_ENDPOINT_SOCKET must be a unix socket URL",
		},
		{
			name:       "socket URL with host component",
			socketAddr: "unix://run/spire/agent-sockets/api.sock",
			audience:   "swarm-external-secrets",
			wantErr:    "must use unix:///absolute/path form with no host",
		},
		{
			name:       "missing audience",
			socketAddr: "unix:///run/spire/agent-sockets/api.sock",
			wantErr:    "JWT-SVID audience is required",
		},
		{
			name:       "valid configuration",
			socketAddr: "unix:///run/spire/agent-sockets/api.sock",
			audience:   "swarm-external-secrets",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := New(tt.socketAddr, tt.audience)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("New() error = %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("New() error = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

func TestTokenSource_FetchIdentityToken(t *testing.T) {
	t.Parallel()

	fetcher := &fakeFetcher{token: "signed-jwt-svid"}
	source := newTestSource(fetcher)

	token, err := source.FetchIdentityToken(t.Context())
	if err != nil {
		t.Fatalf("FetchIdentityToken() error = %v", err)
	}
	if got, want := string(token), "signed-jwt-svid"; got != want {
		t.Fatalf("FetchIdentityToken() = %q, want %q", got, want)
	}
	if got, want := fetcher.audience, "swarm-external-secrets"; got != want {
		t.Fatalf("FetchJWTSVID() audience = %q, want %q", got, want)
	}
}

func TestTokenSource_FetchIdentityToken_RetriesClientCreation(t *testing.T) {
	t.Parallel()

	fetcher := &fakeFetcher{token: "signed-jwt-svid"}
	source := newTestSource(fetcher)
	attempts := 0
	source.newFetcher = func(context.Context, string) (tokenFetcher, error) {
		attempts++
		if attempts == 1 {
			return nil, errors.New("agent unavailable")
		}
		return fetcher, nil
	}

	if _, err := source.FetchIdentityToken(t.Context()); err == nil || !strings.Contains(err.Error(), "agent unavailable") {
		t.Fatalf("first FetchIdentityToken() error = %v, want agent unavailable", err)
	}
	if _, err := source.FetchIdentityToken(t.Context()); err != nil {
		t.Fatalf("second FetchIdentityToken() error = %v", err)
	}
	if attempts != 2 {
		t.Fatalf("client creation attempts = %d, want 2", attempts)
	}
}

func TestTokenSource_FetchIdentityToken_Timeout(t *testing.T) {
	t.Parallel()

	source := newTestSource(&fakeFetcher{waitForContext: true})
	source.timeout = time.Millisecond

	if _, err := source.FetchIdentityToken(t.Context()); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("FetchIdentityToken() error = %v, want context deadline exceeded", err)
	}
}

func TestTokenSource_FetchIdentityToken_PropagatesCancellation(t *testing.T) {
	t.Parallel()

	source := newTestSource(&fakeFetcher{waitForContext: true})
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	if _, err := source.FetchIdentityToken(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("FetchIdentityToken() error = %v, want context canceled", err)
	}
}

func TestTokenSource_Close(t *testing.T) {
	t.Parallel()

	fetcher := &fakeFetcher{token: "signed-jwt-svid"}
	source := newTestSource(fetcher)

	if _, err := source.FetchIdentityToken(t.Context()); err != nil {
		t.Fatalf("FetchIdentityToken() error = %v", err)
	}
	if err := source.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if !fetcher.closed {
		t.Fatal("Close() did not close the Workload API client")
	}
	if _, err := source.FetchIdentityToken(t.Context()); err == nil || !strings.Contains(err.Error(), "closed") {
		t.Fatalf("FetchIdentityToken() after Close() error = %v, want closed", err)
	}
}

func TestTokenSource_CloseDoesNotWaitForInFlightFetch(t *testing.T) {
	t.Parallel()

	fetcher := &fakeFetcher{waitForContext: true, started: make(chan struct{})}
	source := newTestSource(fetcher)
	source.timeout = time.Minute

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = source.FetchIdentityToken(ctx)
	}()
	<-fetcher.started

	closed := make(chan error, 1)
	go func() { closed <- source.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close() blocked on an in-flight FetchIdentityToken call")
	}

	cancel()
	<-done
}

func newTestSource(fetcher tokenFetcher) *TokenSource {
	return &TokenSource{
		socketAddr: "unix:///run/spire/agent-sockets/api.sock",
		audience:   "swarm-external-secrets",
		timeout:    time.Second,
		newFetcher: func(context.Context, string) (tokenFetcher, error) {
			return fetcher, nil
		},
	}
}
