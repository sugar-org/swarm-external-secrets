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
			"vault_path":  "database/mysql",
			"vault_field": "password",
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
			"vault_path":  "database/mysql",
			"vault_field": "password",
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

func newVaultProviderForPathTest(mountPath, kvVersion string) *VaultProvider {
	return &VaultProvider{
		config: vaultcompat.Config{
			ProviderName: "vault",
			EnvPrefix:    "VAULT",
			MountPath:    mountPath,
			PathLabel:    "vault_path",
			FieldLabel:   "vault_field",
			KVVersion:    kvVersion,
		},
	}
}

func TestVaultProvider_BuildSecretPath(t *testing.T) {
	tests := []struct {
		name      string
		mountPath string
		kvVersion string
		req       secrets.Request
		want      string
	}{
		{
			name:      "v2 default mount service fallback",
			mountPath: "secret",
			kvVersion: "2",
			req:       secrets.Request{SecretName: "db-password", ServiceName: "my-service"},
			want:      "secret/data/my-service/db-password",
		},
		{
			name:      "v1 default mount service fallback",
			mountPath: "secret",
			kvVersion: "1",
			req:       secrets.Request{SecretName: "db-password", ServiceName: "my-service"},
			want:      "secret/my-service/db-password",
		},
		{
			name:      "v2 explicit vault_path",
			mountPath: "secret",
			kvVersion: "2",
			req: secrets.Request{
				SecretName:   "ignored",
				SecretLabels: map[string]string{"vault_path": "database/mysql"},
			},
			want: "secret/data/database/mysql",
		},
		{
			name:      "v1 explicit vault_path",
			mountPath: "secret",
			kvVersion: "1",
			req: secrets.Request{
				SecretName:   "ignored",
				SecretLabels: map[string]string{"vault_path": "database/mysql"},
			},
			want: "secret/database/mysql",
		},
		{
			name:      "v1 relative data path keeps data folder",
			mountPath: "secret",
			kvVersion: "1",
			req: secrets.Request{
				SecretName:   "ignored",
				SecretLabels: map[string]string{"vault_path": "data/mysql"},
			},
			want: "secret/data/mysql",
		},
		{
			name:      "v1 mount-qualified path preserves literal data folder",
			mountPath: "secret",
			kvVersion: "1",
			req: secrets.Request{
				SecretName:   "ignored",
				SecretLabels: map[string]string{"vault_path": "secret/data/mysql"},
			},
			want: "secret/data/mysql",
		},
		{
			name:      "v1 mount-qualified path preserves literal data folder on custom mount",
			mountPath: "kv",
			kvVersion: "1",
			req: secrets.Request{
				SecretName:   "ignored",
				SecretLabels: map[string]string{"vault_path": "kv/data/mysql"},
			},
			want: "kv/data/mysql",
		},
		{
			name:      "empty version keeps historical v2 behaviour",
			mountPath: "secret",
			kvVersion: "",
			req:       secrets.Request{SecretName: "db-password", ServiceName: "my-service"},
			want:      "secret/data/my-service/db-password",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := newVaultProviderForPathTest(tt.mountPath, tt.kvVersion)
			if got := p.BuildSecretPath(tt.req); got != tt.want {
				t.Fatalf("BuildSecretPath() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestVaultProvider_Initialize_RejectsUnsupportedKVVersion(t *testing.T) {
	for _, bad := range []string{"3", "v1", "v2", "V1", "0", "foo", "v", "12"} {
		t.Run("kv="+bad, func(t *testing.T) {
			p := &VaultProvider{}
			err := p.Initialize(map[string]string{"VAULT_KV_VERSION": bad})
			if err == nil {
				t.Fatal("Initialize() error = nil, want error for unsupported KV version")
			}
			if !strings.Contains(err.Error(), "VAULT_KV_VERSION") {
				t.Fatalf("Initialize() error = %q, want it to name VAULT_KV_VERSION", err.Error())
			}
		})
	}
}

func TestParseVaultConfig_KVVersionDefault(t *testing.T) {
	cfg := vaultcompat.ParseVaultConfig(map[string]string{})
	if cfg.KVVersion != "2" {
		t.Fatalf("KVVersion = %q, want %q (backward-compatible default)", cfg.KVVersion, "2")
	}

	cfg = vaultcompat.ParseVaultConfig(map[string]string{"VAULT_KV_VERSION": "1"})
	if cfg.KVVersion != "1" {
		t.Fatalf("KVVersion = %q, want %q", cfg.KVVersion, "1")
	}

	if cfg.MountPath != "secret" {
		t.Fatalf("MountPath = %q, want %q", cfg.MountPath, "secret")
	}
}

func TestNormalizeVaultKVVersion(t *testing.T) {
	valid := map[string]string{
		"1":   "1",
		"2":   "2",
		" 1 ": "1",
		" 2 ": "2",
		"":    "2",
	}
	for raw, want := range valid {
		if got, err := vaultcompat.NormalizeVaultKVVersion(raw); err != nil || got != want {
			t.Fatalf("NormalizeVaultKVVersion(%q) = %q, %v; want %q, nil", raw, got, err, want)
		}
	}

	for _, bad := range []string{"3", "v1", "v2", "V1", "foo", "12", "v"} {
		if got, err := vaultcompat.NormalizeVaultKVVersion(bad); err == nil {
			t.Fatalf("NormalizeVaultKVVersion(%q) = %q, nil; want error", bad, got)
		}
	}
}
