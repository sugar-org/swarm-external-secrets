package providers

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/docker/go-plugins-helpers/secrets"
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

func TestVaultProvider_Base64Decode(t *testing.T) {
	binaryData := []byte{0x00, 0xFF, 0xFE, 0x80, 0x7F, 0x12, 0x34, 0x56}
	validBase64Binary := base64.StdEncoding.EncodeToString(binaryData)
	validBase64Text := base64.StdEncoding.EncodeToString([]byte("hello world"))

	tests := []struct {
		name        string
		secretInfo  *SecretInfo
		input       []byte
		want        []byte
		wantErr     bool
		errContains string
	}{
		{
			name: "label absent preserves raw value",
			secretInfo: &SecretInfo{
				DockerSecretName: "test-secret",
				Labels:           map[string]string{},
			},
			input: []byte("not-decoded-value"),
			want:  []byte("not-decoded-value"),
		},
		{
			name: "label false preserves raw value",
			secretInfo: &SecretInfo{
				DockerSecretName: "test-secret",
				Labels:           map[string]string{"base64_decode": "false"},
			},
			input: []byte("not-decoded-value"),
			want:  []byte("not-decoded-value"),
		},
		{
			name: "label with 1 does not decode (strict boolean)",
			secretInfo: &SecretInfo{
				DockerSecretName: "test-secret",
				Labels:           map[string]string{"base64_decode": "1"},
			},
			input: []byte(validBase64Text),
			want:  []byte(validBase64Text),
		},
		{
			name: "label true decodes valid base64 text",
			secretInfo: &SecretInfo{
				DockerSecretName: "test-secret",
				Labels:           map[string]string{"base64_decode": "true"},
			},
			input: []byte(validBase64Text),
			want:  []byte("hello world"),
		},
		{
			name: "label TRUE (uppercase) decodes valid base64",
			secretInfo: &SecretInfo{
				DockerSecretName: "test-secret",
				Labels:           map[string]string{"base64_decode": "TRUE"},
			},
			input: []byte(validBase64Text),
			want:  []byte("hello world"),
		},
		{
			name: "label true trims surrounding whitespace and newlines",
			secretInfo: &SecretInfo{
				DockerSecretName: "test-secret",
				Labels:           map[string]string{"base64_decode": " true "},
			},
			input: []byte("  " + validBase64Text + " \r\n"),
			want:  []byte("hello world"),
		},
		{
			name: "label true decodes binary non-UTF-8 bytes correctly without corruption",
			secretInfo: &SecretInfo{
				DockerSecretName: "kafka-keystore",
				Labels:           map[string]string{"base64_decode": "true"},
			},
			input: []byte(validBase64Binary),
			want:  binaryData,
		},
		{
			name: "label true with empty value decodes to empty bytes without error",
			secretInfo: &SecretInfo{
				DockerSecretName: "empty-secret",
				Labels:           map[string]string{"base64_decode": "true"},
			},
			input: []byte(""),
			want:  []byte{},
		},
		{
			name: "label true with whitespace-only value decodes to empty bytes without error",
			secretInfo: &SecretInfo{
				DockerSecretName: "whitespace-secret",
				Labels:           map[string]string{"base64_decode": "true"},
			},
			input: []byte("   \r\n\t  "),
			want:  []byte{},
		},
		{
			name: "label true with invalid base64 returns error with secret name but no secret bytes",
			secretInfo: &SecretInfo{
				DockerSecretName: "my-secret",
				Labels:           map[string]string{"base64_decode": "true"},
			},
			input:       []byte("super-secret-not-base64!@#$"),
			wantErr:     true,
			errContains: `"my-secret"`,
		},
		{
			name:       "nil secretInfo preserves raw value",
			secretInfo: nil,
			input:      []byte("raw-bytes"),
			want:       []byte("raw-bytes"),
		},
		{
			name: "nil labels in secretInfo preserves raw value",
			secretInfo: &SecretInfo{
				DockerSecretName: "secret-without-labels",
			},
			input: []byte("raw-bytes"),
			want:  []byte("raw-bytes"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !shouldBase64Decode(tt.secretInfo) {
				if tt.wantErr {
					t.Fatalf("expected shouldBase64Decode to be true")
				}
				if !bytes.Equal(tt.input, tt.want) {
					t.Errorf("got %v, want %v", tt.input, tt.want)
				}
				return
			}

			got, err := decodeBase64Secret(tt.input, tt.secretInfo)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				errMsg := err.Error()
				if !strings.Contains(errMsg, tt.errContains) {
					t.Errorf("error %q should contain %q", errMsg, tt.errContains)
				}
				if len(tt.input) > 0 && strings.Contains(errMsg, string(tt.input)) {
					t.Errorf("error %q leaked input secret value %q", errMsg, string(tt.input))
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !bytes.Equal(got, tt.want) {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestVaultProvider_GetSecret_Base64Decode(t *testing.T) {
	binaryPayload := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01, 0x02}
	encodedPayload := base64.StdEncoding.EncodeToString(binaryPayload)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/secret/data/app/binary":
			_, _ = w.Write([]byte(fmt.Sprintf(`{"data":{"data":{"keystore":"%s"}}}`, encodedPayload)))
		default:
			t.Fatalf("unexpected request path: %s", r.URL.Path)
		}
	}))
	defer server.Close()

	provider := &VaultProvider{}
	if err := provider.Initialize(map[string]string{
		"VAULT_ADDR":  server.URL,
		"VAULT_TOKEN": "test-token",
	}); err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}
	defer func() { _ = provider.Close() }()

	info := &SecretInfo{
		DockerSecretName: "test-keystore",
		SecretPath:       "secret/data/app/binary",
		SecretField:      "keystore",
		Labels: map[string]string{
			"base64_decode": "true",
		},
	}

	got, err := provider.GetSecret(t.Context(), info)
	if err != nil {
		t.Fatalf("GetSecret() error = %v", err)
	}
	if !bytes.Equal(got, binaryPayload) {
		t.Fatalf("GetSecret() = %v, want %v", got, binaryPayload)
	}

	infoRaw := &SecretInfo{
		DockerSecretName: "test-keystore",
		SecretPath:       "secret/data/app/binary",
		SecretField:      "keystore",
	}
	gotRaw, err := provider.GetSecret(t.Context(), infoRaw)
	if err != nil {
		t.Fatalf("GetSecret() error = %v", err)
	}
	if string(gotRaw) != encodedPayload {
		t.Fatalf("GetSecret() = %q, want %q", string(gotRaw), encodedPayload)
	}
}
