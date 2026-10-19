package providers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/docker/go-plugins-helpers/secrets"

	"github.com/sugar-org/swarm-external-secrets/internal/vaultcompat"
)

const vaultPathLabel = "vault_path"

func TestVaultProvider_AuthenticateWithJWT(t *testing.T) {
	var loginRequest struct {
		Role string `json:"role"`
		JWT  string `json:"jwt"`
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/jwt/login":
			if r.Method != http.MethodPut {
				t.Fatalf("jwt login method = %s, want PUT", r.Method)
			}

			if err := json.NewDecoder(r.Body).Decode(&loginRequest); err != nil {
				t.Fatalf("decode jwt login request: %v", err)
			}

			_, _ = w.Write([]byte(`{"auth":{"client_token":"vault-client-token"}}`))
		case "/v1/secret/data/database/mysql":
			if got := r.Header.Get("X-Vault-Token"); got != "vault-client-token" {
				t.Fatalf("X-Vault-Token = %q, want vault-client-token", got)
			}

			_, _ = w.Write([]byte(`{"data":{"data":{"password":"jwt-secret"}}}`))
		default:
			t.Fatalf("unexpected request path: %s", r.URL.Path)
		}
	}))
	defer server.Close()

	provider := &VaultProvider{}
	if err := provider.Initialize(map[string]string{
		"VAULT_ADDR":        server.URL,
		"VAULT_AUTH_METHOD": "jwt",
		"VAULT_JWT_ROLE":    "swarm-external-secrets",
		"VAULT_JWT":         "test.jwt.token",
		"VAULT_MOUNT_PATH":  "secret",
	}); err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}
	defer func() { _ = provider.Close() }()

	req := secrets.Request{
		SecretName: "fallback",
		SecretLabels: map[string]string{
			vaultPathLabel: "database/mysql",
			"vault_field":  "password",
		},
	}

	got, err := provider.GetSecret(t.Context(), &SecretInfo{
		DockerSecretName: req.SecretName,
		SecretPath:       provider.BuildSecretPath(req),
		SecretField:      req.SecretLabels[provider.GetSecretFieldLabel()],
		Provider:         provider.GetProviderName(),
		Labels:           req.SecretLabels,
	})
	if err != nil {
		t.Fatalf("GetSecret() error = %v", err)
	}

	if string(got) != "jwt-secret" {
		t.Fatalf("GetSecret() = %q, want jwt-secret", string(got))
	}

	if loginRequest.Role != "swarm-external-secrets" {
		t.Fatalf("login role = %q, want swarm-external-secrets", loginRequest.Role)
	}

	if loginRequest.JWT != "test.jwt.token" {
		t.Fatalf("login jwt = %q, want test.jwt.token", loginRequest.JWT)
	}
}

func TestVaultProvider_RenewsJWTToken(t *testing.T) {
	renewCalled := make(chan struct{})
	var closeRenewCalled sync.Once

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/jwt/login":
			_, _ = w.Write([]byte(`{"auth":{"client_token":"token-1","renewable":true,"lease_duration":1}}`))
		case "/v1/auth/token/renew-self":
			if r.Method != http.MethodPut {
				t.Fatalf("renew method = %s, want PUT", r.Method)
			}
			if got := r.Header.Get("X-Vault-Token"); got != "token-1" {
				t.Fatalf("renew X-Vault-Token = %q, want token-1", got)
			}

			closeRenewCalled.Do(func() {
				close(renewCalled)
			})
			_, _ = w.Write([]byte(`{"auth":{"client_token":"token-2","renewable":true,"lease_duration":60}}`))
		case "/v1/secret/data/database/mysql":
			if got := r.Header.Get("X-Vault-Token"); got != "token-2" {
				t.Fatalf("read X-Vault-Token = %q, want token-2", got)
			}

			_, _ = w.Write([]byte(`{"data":{"data":{"password":"renewed-secret"}}}`))
		default:
			t.Fatalf("unexpected request path: %s", r.URL.Path)
		}
	}))
	defer server.Close()

	provider := &VaultProvider{}
	if err := provider.Initialize(map[string]string{
		"VAULT_ADDR":        server.URL,
		"VAULT_AUTH_METHOD": "jwt",
		"VAULT_JWT_ROLE":    "swarm-external-secrets",
		"VAULT_JWT":         "test.jwt.token",
		"VAULT_MOUNT_PATH":  "secret",
	}); err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}
	defer func() { _ = provider.Close() }()

	select {
	case <-renewCalled:
	case <-time.After(3 * time.Second):
		t.Fatal("token was not renewed")
	}
	time.Sleep(100 * time.Millisecond)

	req := secrets.Request{
		SecretName: "fallback",
		SecretLabels: map[string]string{
			vaultPathLabel: "database/mysql",
			"vault_field":  "password",
		},
	}
	got, err := provider.GetSecret(t.Context(), &SecretInfo{
		DockerSecretName: req.SecretName,
		SecretPath:       provider.BuildSecretPath(req),
		SecretField:      req.SecretLabels[provider.GetSecretFieldLabel()],
		Provider:         provider.GetProviderName(),
		Labels:           req.SecretLabels,
	})
	if err != nil {
		t.Fatalf("GetSecret() error = %v", err)
	}
	if string(got) != "renewed-secret" {
		t.Fatalf("GetSecret() = %q, want renewed-secret", string(got))
	}
}

func TestVaultProvider_AuthenticateWithJWT_CustomAuthPathAndFilePrecedence(t *testing.T) {
	var loginRequest struct {
		Role string `json:"role"`
		JWT  string `json:"jwt"`
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/auth/oidc/login" {
			t.Fatalf("jwt login path = %s, want /v1/auth/oidc/login", r.URL.Path)
		}

		if err := json.NewDecoder(r.Body).Decode(&loginRequest); err != nil {
			t.Fatalf("decode jwt login request: %v", err)
		}

		_, _ = w.Write([]byte(`{"auth":{"client_token":"vault-client-token"}}`))
	}))
	defer server.Close()

	jwtFile := filepath.Join(t.TempDir(), "jwt")
	if err := os.WriteFile(jwtFile, []byte("file.jwt.token\n"), 0o600); err != nil {
		t.Fatalf("write jwt file: %v", err)
	}

	provider := &VaultProvider{}
	if err := provider.Initialize(map[string]string{
		"VAULT_ADDR":          server.URL,
		"VAULT_AUTH_METHOD":   "jwt",
		"VAULT_JWT_ROLE":      "swarm-external-secrets",
		"VAULT_JWT":           "env.jwt.token",
		"VAULT_JWT_FILE":      jwtFile,
		"VAULT_JWT_AUTH_PATH": "/oidc/",
	}); err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}
	defer func() { _ = provider.Close() }()

	if loginRequest.JWT != "file.jwt.token" {
		t.Fatalf("login jwt = %q, want file.jwt.token", loginRequest.JWT)
	}
}

func TestVaultProvider_AuthenticateWithJWT_Validation(t *testing.T) {
	tests := []struct {
		name    string
		config  map[string]string
		wantErr string
	}{
		{
			name: "missing role",
			config: map[string]string{
				"VAULT_AUTH_METHOD": "jwt",
				"VAULT_JWT":         "test.jwt.token",
			},
			wantErr: "VAULT_JWT_ROLE is required for jwt authentication",
		},
		{
			name: "missing jwt",
			config: map[string]string{
				"VAULT_AUTH_METHOD": "jwt",
				"VAULT_JWT_ROLE":    "swarm-external-secrets",
			},
			wantErr: "VAULT_JWT or VAULT_JWT_FILE is required for jwt authentication",
		},
		{
			name: "empty jwt file",
			config: map[string]string{
				"VAULT_AUTH_METHOD": "jwt",
				"VAULT_JWT_ROLE":    "swarm-external-secrets",
				"VAULT_JWT_FILE":    emptyFile(t),
			},
			wantErr: "VAULT_JWT_FILE is empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := &VaultProvider{}
			err := provider.Initialize(tt.config)
			if err == nil {
				t.Fatal("Initialize() error = nil, want error")
			}

			if got := err.Error(); got != "failed to authenticate with vault: "+tt.wantErr {
				t.Fatalf("Initialize() error = %q, want %q", got, "failed to authenticate with vault: "+tt.wantErr)
			}
		})
	}
}

func TestVaultProvider_AuthenticateWithJWT_LoginFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/auth/jwt/login" {
			t.Fatalf("unexpected request path: %s", r.URL.Path)
		}

		http.Error(w, "permission denied", http.StatusForbidden)
	}))
	defer server.Close()

	provider := &VaultProvider{}
	err := provider.Initialize(map[string]string{
		"VAULT_ADDR":        server.URL,
		"VAULT_AUTH_METHOD": "jwt",
		"VAULT_JWT_ROLE":    "swarm-external-secrets",
		"VAULT_JWT":         "test.jwt.token",
	})
	if err == nil {
		t.Fatal("Initialize() error = nil, want error")
	}

	if got := err.Error(); got != "failed to authenticate with vault: jwt authentication failed: Error making API request.\n\nURL: PUT "+server.URL+"/v1/auth/jwt/login\nCode: 403. Errors:\n\n* permission denied" {
		if !containsAll(got, "failed to authenticate with vault", "jwt authentication failed", "403", "permission denied") {
			t.Fatalf("Initialize() error = %q", got)
		}
	}
}

func containsAll(s string, parts ...string) bool {
	for _, part := range parts {
		if !strings.Contains(s, part) {
			return false
		}
	}
	return true
}

func emptyFile(t *testing.T) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "empty-jwt")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("write empty jwt file: %v", err)
	}

	return path
}

// vaultProviderFromConfig adapts a config into the provider under test, so the
// shared path helpers can drive Vault without a provider-specific signature.
func vaultProviderFromConfig(cfg vaultcompat.Config) secretPathBuilder {
	return &VaultProvider{config: cfg}
}

// TestVaultProvider_BuildSecretPath runs the shared KV v1/v2 path matrix with
// the Vault path label.
func TestVaultProvider_BuildSecretPath(t *testing.T) {
	runSharedKVPathCases(t, vaultPathLabel, vaultProviderFromConfig)
}

// TestVaultProvider_Initialize_RejectsUnsupportedKVVersion keeps the
// Vault-specific contract: Initialize names VAULT_KV_VERSION when it fails.
func TestVaultProvider_Initialize_RejectsUnsupportedKVVersion(t *testing.T) {
	runUnsupportedKVVersionRejection(t, "VAULT_KV_VERSION", func(config map[string]string) error {
		return (&VaultProvider{}).Initialize(config)
	})
}

func TestParseVaultConfig_KVVersionDefault(t *testing.T) {
	runKVVersionConfigDefaults(t, "VAULT_KV_VERSION", vaultcompat.ParseVaultConfig)
}

func TestNormalizeVaultKVVersion(t *testing.T) {
	runKVVersionNormalizationCases(t, vaultcompat.NormalizeVaultKVVersion)
}

// TestVaultProvider_BuildSecretPathThroughConfig mirrors the OpenBao
// config-driven check: ParseVaultConfig + NormalizeVaultKVVersion drive path
// construction end to end (unset -> v2, "1" -> v1, "2" -> v2).
func TestVaultProvider_BuildSecretPathThroughConfig(t *testing.T) {
	runSharedKVVersionConfigDrivenPath(t, "VAULT_KV_VERSION",
		vaultcompat.ParseVaultConfig,
		vaultcompat.NormalizeVaultKVVersion,
		vaultProviderFromConfig)
}
