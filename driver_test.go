package main

import (
	"testing"

	"github.com/docker/go-plugins-helpers/secrets"
)

const (
	testSecretPath    = "svc/db"
	testDefaultResult = "secret/data/" + testSecretPath
	testCustomResult  = "kv/" + testSecretPath
)

var customVaultMount = map[string]string{"VAULT_MOUNT_PATH": "kv"}
var customOpenBaoMount = map[string]string{"OPENBAO_MOUNT_PATH": "kv"}

func newRequest(name, service string, labels map[string]string) secrets.Request {
	if labels == nil {
		labels = map[string]string{}
	}
	return secrets.Request{
		SecretName:   name,
		ServiceName:  service,
		SecretLabels: labels,
	}
}

func TestBuildSecretPath(t *testing.T) {
	tests := []struct {
		name     string
		provider string
		settings map[string]string
		req      secrets.Request
		expected string
	}{
		// Vault — default mount
		{"vault: label path, default mount", "vault", nil, newRequest("test", "", map[string]string{"vault_path": testSecretPath}), testDefaultResult},
		{"vault: service fallback, default mount", "vault", nil, newRequest("db", "svc", nil), testDefaultResult},
		{"vault: name only, default mount", "vault", nil, newRequest("db", "", nil), "secret/data/db"},
		// Vault — custom mount
		{"vault: label path, custom mount", "vault", customVaultMount, newRequest("test", "", map[string]string{"vault_path": testSecretPath}), testCustomResult},
		{"vault: service fallback, custom mount", "vault", customVaultMount, newRequest("db", "svc", nil), testCustomResult},
		{"vault: name only, custom mount", "vault", customVaultMount, newRequest("db", "", nil), "kv/db"},
		// OpenBao
		{"openbao: label path, default mount", "openbao", nil, newRequest("test", "", map[string]string{"openbao_path": testSecretPath}), testDefaultResult},
		{"openbao: label path, custom mount", "openbao", customOpenBaoMount, newRequest("test", "", map[string]string{"openbao_path": testSecretPath}), testCustomResult},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			settings := tt.settings
			if settings == nil {
				settings = map[string]string{}
			}
			driver := &SecretsDriver{config: &SecretsConfig{Settings: settings}}

			var got string
			if tt.provider == "vault" {
				got = driver.buildVaultSecretPath(tt.req)
			} else {
				got = driver.buildOpenBaoSecretPath(tt.req)
			}
			if got != tt.expected {
				t.Errorf("got %q, want %q", got, tt.expected)
			}
		})
	}
}
