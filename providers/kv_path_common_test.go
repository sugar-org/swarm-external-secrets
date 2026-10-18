package providers

import (
	"strings"
	"testing"

	"github.com/docker/go-plugins-helpers/secrets"

	"github.com/sugar-org/swarm-external-secrets/internal/vaultcompat"
)

// secretPathBuilder is the slice of the provider behaviour these shared tests
// exercise. Both OpenBaoProvider and VaultProvider implement it.
type secretPathBuilder interface {
	BuildSecretPath(secrets.Request) string
}

// kvPathCase is one BuildSecretPath expectation. customPath holds the value of
// the provider's path label (vault_path / openbao_path); an empty value leaves
// the label unset. The runner injects the provider-specific label key, so a
// single table keeps the two providers' KV v1/v2 path behaviour in sync without
// duplicating the expectations.
type kvPathCase struct {
	name        string
	mountPath   string
	kvVersion   string
	secretName  string
	serviceName string
	customPath  string
	want        string
}

// sharedKVPathCases covers KV v1 and v2, default and custom mounts, the
// service-name fallback, explicit custom paths, normalization, literal "data/"
// folders preserved for KV v1, and the empty version that keeps the historical
// v2 behaviour.
var sharedKVPathCases = []kvPathCase{
	{name: "v2 default mount service fallback", mountPath: "secret", kvVersion: "2", secretName: "db-password", serviceName: "my-service", want: "secret/data/my-service/db-password"},
	{name: "v1 default mount service fallback", mountPath: "secret", kvVersion: "1", secretName: "db-password", serviceName: "my-service", want: "secret/my-service/db-password"},
	{name: "v2 custom mount service fallback", mountPath: "kv", kvVersion: "2", secretName: "db-password", serviceName: "my-service", want: "kv/data/my-service/db-password"},
	{name: "v1 custom mount service fallback", mountPath: "kv", kvVersion: "1", secretName: "db-password", serviceName: "my-service", want: "kv/my-service/db-password"},
	{name: "v2 secret name only without service", mountPath: "secret", kvVersion: "2", secretName: "db-password", want: "secret/data/db-password"},
	{name: "v1 secret name only without service", mountPath: "secret", kvVersion: "1", secretName: "db-password", want: "secret/db-password"},
	{name: "v2 explicit custom path", mountPath: "secret", kvVersion: "2", customPath: "database/mysql", want: "secret/data/database/mysql"},
	{name: "v1 explicit custom path", mountPath: "secret", kvVersion: "1", customPath: "database/mysql", want: "secret/database/mysql"},
	{name: "v2 explicit custom path custom mount", mountPath: "kv", kvVersion: "2", customPath: "database/mysql", want: "kv/data/database/mysql"},
	{name: "v1 explicit custom path custom mount", mountPath: "kv", kvVersion: "1", customPath: "database/mysql", want: "kv/database/mysql"},
	{name: "v2 explicit path normalization preserved", mountPath: "secret", kvVersion: "2", customPath: "/secret/data/database/mysql/", want: "secret/data/database/mysql"},
	{name: "v1 explicit path normalization preserves literal data", mountPath: "secret", kvVersion: "1", customPath: "/secret/data/database/mysql/", want: "secret/data/database/mysql"},
	{name: "v1 relative data path keeps data folder", mountPath: "secret", kvVersion: "1", customPath: "data/mysql", want: "secret/data/mysql"},
	{name: "v1 mount-qualified path preserves literal data folder", mountPath: "secret", kvVersion: "1", customPath: "secret/data/mysql", want: "secret/data/mysql"},
	{name: "v1 relative data path keeps data folder on custom mount", mountPath: "kv", kvVersion: "1", customPath: "data/mysql", want: "kv/data/mysql"},
	{name: "v1 mount-qualified path preserves literal data folder on custom mount", mountPath: "kv", kvVersion: "1", customPath: "kv/data/mysql", want: "kv/data/mysql"},
	{name: "v2 relative data path normalization unchanged", mountPath: "secret", kvVersion: "2", customPath: "data/mysql", want: "secret/data/mysql"},
	{name: "empty version keeps historical v2 behaviour", mountPath: "secret", kvVersion: "", secretName: "db-password", serviceName: "my-service", want: "secret/data/my-service/db-password"},
}

// runSharedKVPathCases exercises the shared path matrix against one provider.
// labelKey is the provider's path label ("vault_path" / "openbao_path").
func runSharedKVPathCases(t *testing.T, labelKey string, newProvider func(mountPath, kvVersion string) secretPathBuilder) {
	t.Helper()

	for _, tt := range sharedKVPathCases {
		t.Run(tt.name, func(t *testing.T) {
			p := newProvider(tt.mountPath, tt.kvVersion)
			req := secrets.Request{SecretName: tt.secretName, ServiceName: tt.serviceName}
			if tt.customPath != "" {
				req.SecretLabels = map[string]string{labelKey: tt.customPath}
			}
			if got := p.BuildSecretPath(req); got != tt.want {
				t.Fatalf("BuildSecretPath() = %q, want %q", got, tt.want)
			}
		})
	}
}

// runUnsupportedKVVersionRejection asserts that Initialize rejects every value
// other than "1"/"2" and names the provider's configuration variable.
func runUnsupportedKVVersionRejection(t *testing.T, envKey string, initialize func(map[string]string) error) {
	t.Helper()

	for _, bad := range []string{"3", "v1", "v2", "V1", "0", "foo", "v", "12"} {
		t.Run("kv="+bad, func(t *testing.T) {
			err := initialize(map[string]string{envKey: bad})
			if err == nil {
				t.Fatal("Initialize() error = nil, want error for unsupported KV version")
			}
			if !strings.Contains(err.Error(), envKey) {
				t.Fatalf("Initialize() error = %q, want it to name %s", err.Error(), envKey)
			}
		})
	}
}

// runKVVersionConfigDefaults asserts the parse function defaults to KV v2, maps
// "1" to v1, and keeps the default mount path.
func runKVVersionConfigDefaults(t *testing.T, envKey string, parse func(map[string]string) vaultcompat.Config) {
	t.Helper()

	cfg := parse(map[string]string{})
	if cfg.KVVersion != "2" {
		t.Fatalf("KVVersion = %q, want %q (backward-compatible default)", cfg.KVVersion, "2")
	}

	cfg = parse(map[string]string{envKey: "1"})
	if cfg.KVVersion != "1" {
		t.Fatalf("KVVersion = %q, want %q", cfg.KVVersion, "1")
	}

	if cfg.MountPath != "secret" {
		t.Fatalf("MountPath = %q, want %q", cfg.MountPath, "secret")
	}
}

// runKVVersionNormalizationCases asserts valid inputs (including whitespace and
// empty) normalize as expected and everything else is rejected.
func runKVVersionNormalizationCases(t *testing.T, normalize func(string) (string, error)) {
	t.Helper()

	valid := map[string]string{
		"1":   "1",
		"2":   "2",
		" 1 ": "1",
		" 2 ": "2",
		"":    "2",
	}
	for raw, want := range valid {
		if got, err := normalize(raw); err != nil || got != want {
			t.Fatalf("normalize(%q) = %q, %v; want %q, nil", raw, got, err, want)
		}
	}

	for _, bad := range []string{"3", "v1", "v2", "V1", "foo", "12", "v"} {
		if got, err := normalize(bad); err == nil {
			t.Fatalf("normalize(%q) = %q, nil; want error", bad, got)
		}
	}
}
