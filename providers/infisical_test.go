package providers

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/docker/go-plugins-helpers/secrets"
)

func TestInfisicalProviderInitialize(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		config  map[string]string
		wantErr string
	}{
		{
			name:    "missing auth",
			config:  map[string]string{},
			wantErr: "INFISICAL_TOKEN or both INFISICAL_CLIENT_ID and INFISICAL_CLIENT_SECRET are required",
		},
		{
			name: "token without project",
			config: map[string]string{
				"INFISICAL_TOKEN": "st.example",
			},
			wantErr: "INFISICAL_PROJECT_ID is required",
		},
		{
			name: "invalid site url",
			config: map[string]string{
				"INFISICAL_TOKEN":      "st.example",
				"INFISICAL_PROJECT_ID": "proj",
				"INFISICAL_SITE_URL":   "not-a-url",
			},
			wantErr: "INFISICAL_SITE_URL must use https scheme",
		},
		{
			name: "http site url",
			config: map[string]string{
				"INFISICAL_TOKEN":      "st.example",
				"INFISICAL_PROJECT_ID": "proj",
				"INFISICAL_SITE_URL":   "http://infisical.example.com",
			},
			wantErr: "INFISICAL_SITE_URL must use https scheme",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			p := &InfisicalProvider{}
			err := p.Initialize(tt.config)
			if err == nil {
				t.Fatal("Initialize() error = nil, want error")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Initialize() error = %q, want %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestInfisicalProviderInitializeHTTPS(t *testing.T) {
	t.Parallel()
	p := &InfisicalProvider{}
	if err := p.Initialize(map[string]string{
		"INFISICAL_TOKEN":      "st.example",
		"INFISICAL_PROJECT_ID": "proj",
		"INFISICAL_SITE_URL":   "https://app.infisical.com",
	}); err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}
	defer func() { _ = p.Close() }()
}

func TestInfisicalProviderGetSecretToken(t *testing.T) {
	t.Parallel()

	server := newInfisicalTestServer(t, "", "")
	defer server.Close()

	p := infisicalProviderForServer(t, server.URL, "st.test")
	defer func() { _ = p.Close() }()

	got, err := p.GetSecret(context.Background(), &SecretInfo{
		DockerSecretName: "db_password",
		SecretPath:       "proj-1/dev/DB_PASSWORD",
		Labels:           map[string]string{"infisical_secret_name": "DB_PASSWORD"},
	})
	if err != nil {
		t.Fatalf("GetSecret() error = %v", err)
	}
	if string(got) != "secret-value" {
		t.Fatalf("GetSecret() = %q, want secret-value", got)
	}
}

func TestInfisicalProviderGetSecretUniversalAuth(t *testing.T) {
	t.Parallel()

	server := newInfisicalTestServer(t, "cid", "csecret")
	defer server.Close()

	p := infisicalProviderForServer(t, server.URL, "")
	p.config.ClientID, p.config.ClientSecret = "cid", "csecret"
	defer func() { _ = p.Close() }()

	got, err := p.GetSecret(context.Background(), &SecretInfo{
		DockerSecretName: "mysql_password",
		SecretPath:       "proj-1/dev/MYSQL_PASSWORD",
	})
	if err != nil {
		t.Fatalf("GetSecret() error = %v", err)
	}
	if string(got) != "secret-value" {
		t.Fatalf("GetSecret() = %q, want secret-value", got)
	}
}

func TestInfisicalProviderGetSecretCanceled(t *testing.T) {
	t.Parallel()

	server := newInfisicalTestServer(t, "", "")
	defer server.Close()

	p := infisicalProviderForServer(t, server.URL, "st.test")
	defer func() { _ = p.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := p.GetSecret(ctx, &SecretInfo{DockerSecretName: "x", SecretPath: "proj-1/dev/X"})
	if err == nil {
		t.Fatal("GetSecret() error = nil, want canceled")
	}
}

func TestInfisicalProviderGetSecretHonorsContextDeadline(t *testing.T) {
	t.Parallel()

	sawCancel := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || !strings.HasPrefix(r.URL.Path, "/api/v3/secrets/raw/") {
			http.NotFound(w, r)
			return
		}
		<-r.Context().Done()
		close(sawCancel)
	}))
	t.Cleanup(server.Close)

	p := infisicalProviderForServer(t, server.URL, "st.test")
	defer func() { _ = p.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := p.GetSecret(ctx, &SecretInfo{DockerSecretName: "x", SecretPath: "proj-1/dev/X"})
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("GetSecret() error = nil, want deadline exceeded")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("GetSecret() error = %v, want context.DeadlineExceeded", err)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("GetSecret() returned after %v, want return on context deadline", elapsed)
	}

	select {
	case <-sawCancel:
	case <-time.After(2 * time.Second):
		t.Fatal("server did not observe request cancellation")
	}
}

func TestInfisicalProviderRetriesTooManyRequests(t *testing.T) {
	t.Parallel()

	var calls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"message":"slow down"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"secret":{"secretValue":"secret-value"}}`))
	}))
	t.Cleanup(server.Close)

	p := infisicalProviderForServer(t, server.URL, "st.test")
	defer func() { _ = p.Close() }()

	got, err := p.GetSecret(context.Background(), &SecretInfo{
		DockerSecretName: "db_password",
		SecretPath:       "proj-1/dev/DB_PASSWORD",
	})
	if err != nil {
		t.Fatalf("GetSecret() error = %v", err)
	}
	if string(got) != "secret-value" {
		t.Fatalf("GetSecret() = %q, want secret-value", got)
	}
	if calls != 2 {
		t.Fatalf("requests = %d, want 2", calls)
	}
}

func TestInfisicalProviderBuildSecretPath(t *testing.T) {
	t.Parallel()

	p := &InfisicalProvider{config: &InfisicalConfig{
		ProjectID:   "proj-1",
		Environment: "dev",
		SecretPath:  "/",
	}}

	got := p.BuildSecretPath(secrets.Request{
		SecretName: "mysql_password",
		SecretLabels: map[string]string{
			"infisical_secret_name": "MYSQL_PASSWORD",
		},
	})
	if got != "proj-1/dev/MYSQL_PASSWORD" {
		t.Fatalf("BuildSecretPath() = %q", got)
	}
}

func infisicalProviderForServer(t *testing.T, serverURL, token string) *InfisicalProvider {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	return &InfisicalProvider{
		config: &InfisicalConfig{
			ProjectID:   "proj-1",
			Environment: "dev",
			SecretPath:  "/",
			SiteURL:     serverURL,
			Token:       token,
		},
		lifecycle: ctx,
		authGate:  make(chan struct{}, 1),
		cancel:    cancel,
	}
}

func newInfisicalTestServer(t *testing.T, clientID, clientSecret string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/auth/universal-auth/login":
			handleInfisicalTestLogin(t, w, r, clientID, clientSecret)
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/v3/secrets/raw/"):
			handleInfisicalTestSecret(w, r, clientID)
		default:
			http.NotFound(w, r)
		}
	}))
}

func handleInfisicalTestLogin(t *testing.T, w http.ResponseWriter, r *http.Request, clientID, clientSecret string) {
	t.Helper()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		t.Errorf("read login body: %v", err)
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}
	var payload struct {
		ClientID     string `json:"clientId"`
		ClientSecret string `json:"clientSecret"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	if payload.ClientID != clientID || payload.ClientSecret != clientSecret {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"accessToken":"sdk-token","expiresIn":7200,"accessTokenMaxTTL":7200,"tokenType":"Bearer"}`))
}

func handleInfisicalTestSecret(w http.ResponseWriter, r *http.Request, clientID string) {
	wantToken := "st.test"
	if clientID != "" {
		wantToken = "sdk-token"
	}
	if r.Header.Get("Authorization") != "Bearer "+wantToken {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"secret":{"secretValue":"secret-value"}}`))
}
