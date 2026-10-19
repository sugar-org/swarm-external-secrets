package spiffesource

import (
	"context"
	"fmt"
	"net/url"
	"sync"
	"time"

	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

const defaultFetchTimeout = 30 * time.Second

type tokenFetcher interface {
	FetchJWTSVID(ctx context.Context, audience string) (string, error)
	Close() error
}

type workloadAPIFetcher struct {
	client *workloadapi.Client
}

func (f *workloadAPIFetcher) FetchJWTSVID(ctx context.Context, audience string) (string, error) {
	svid, err := f.client.FetchJWTSVID(ctx, jwtsvid.Params{Audience: audience})
	if err != nil {
		return "", err
	}
	return svid.Marshal(), nil
}

func (f *workloadAPIFetcher) Close() error {
	return f.client.Close()
}

type fetcherFactory func(ctx context.Context, socketAddr string) (tokenFetcher, error)

// TokenSource lazily fetches JWT-SVIDs from the SPIFFE Workload API.
type TokenSource struct {
	mu         sync.RWMutex
	socketAddr string
	audience   string
	timeout    time.Duration
	newFetcher fetcherFactory
	fetcher    tokenFetcher
	closed     bool
}

// New creates a lazy JWT-SVID token source.
func New(socketAddr, audience string) (*TokenSource, error) {
	if err := validateSocketAddr(socketAddr); err != nil {
		return nil, err
	}
	if audience == "" {
		return nil, fmt.Errorf("JWT-SVID audience is required")
	}

	return &TokenSource{
		socketAddr: socketAddr,
		audience:   audience,
		timeout:    defaultFetchTimeout,
		newFetcher: newWorkloadAPIFetcher,
	}, nil
}

// FetchIdentityToken fetches a fresh JWT-SVID for an AWS STS exchange.
func (s *TokenSource) FetchIdentityToken(ctx context.Context) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	if err := s.ensureFetcher(ctx); err != nil {
		return nil, fmt.Errorf("failed to connect to SPIFFE Workload API: %w", err)
	}

	// Do not hold the lock across the Workload API call, or Close blocks until
	// the fetch times out.
	s.mu.RLock()
	fetcher, closed := s.fetcher, s.closed
	s.mu.RUnlock()

	if closed {
		return nil, fmt.Errorf("SPIFFE token source is closed")
	}

	token, err := fetcher.FetchJWTSVID(ctx, s.audience)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWT-SVID: %w", err)
	}
	return []byte(token), nil
}

// Close releases the Workload API connection, if one was opened.
func (s *TokenSource) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil
	}
	s.closed = true

	if s.fetcher == nil {
		return nil
	}
	if err := s.fetcher.Close(); err != nil {
		return fmt.Errorf("failed to close SPIFFE Workload API client: %w", err)
	}
	return nil
}

func (s *TokenSource) ensureFetcher(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return fmt.Errorf("SPIFFE token source is closed")
	}
	if s.fetcher != nil {
		return nil
	}

	fetcher, err := s.newFetcher(ctx, s.socketAddr)
	if err != nil {
		return err
	}
	s.fetcher = fetcher
	return nil
}

func newWorkloadAPIFetcher(ctx context.Context, socketAddr string) (tokenFetcher, error) {
	client, err := workloadapi.New(ctx, workloadapi.WithAddr(socketAddr))
	if err != nil {
		return nil, err
	}
	return &workloadAPIFetcher{client: client}, nil
}

func validateSocketAddr(socketAddr string) error {
	endpoint, err := url.Parse(socketAddr)
	if err != nil {
		return fmt.Errorf("invalid SPIFFE_ENDPOINT_SOCKET %q: %w", socketAddr, err)
	}
	if endpoint.Scheme != "unix" || endpoint.Path == "" {
		return fmt.Errorf("SPIFFE_ENDPOINT_SOCKET must be a unix socket URL")
	}
	if endpoint.Host != "" {
		return fmt.Errorf("SPIFFE_ENDPOINT_SOCKET %q must use unix:///absolute/path form with no host", socketAddr)
	}
	return nil
}
