package providers

import (
	"strings"
	"testing"

	"github.com/docker/go-plugins-helpers/secrets"

	"github.com/sugar-org/swarm-external-secrets/internal/vaultcompat"
)

func newOpenBaoProviderForPathTest(mountPath, kvVersion string) *OpenBaoProvider {
	return &OpenBaoProvider{
		config: vaultcompat.Config{
			ProviderName: "openbao",
			EnvPrefix:    "OPENBAO",
			MountPath:    mountPath,
			PathLabel:    "openbao_path",
			FieldLabel:   "openbao_field",
			KVVersion:    kvVersion,
		},
	}
}

func TestOpenBaoProvider_BuildSecretPath(t *testing.T) {
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
			name:      "v2 custom mount service fallback",
			mountPath: "kv",
			kvVersion: "2",
			req:       secrets.Request{SecretName: "db-password", ServiceName: "my-service"},
			want:      "kv/data/my-service/db-password",
		},
		{
			name:      "v1 custom mount service fallback",
			mountPath: "kv",
			kvVersion: "1",
			req:       secrets.Request{SecretName: "db-password", ServiceName: "my-service"},
			want:      "kv/my-service/db-password",
		},
		{
			name:      "v2 secret name only without service",
			mountPath: "secret",
			kvVersion: "2",
			req:       secrets.Request{SecretName: "db-password"},
			want:      "secret/data/db-password",
		},
		{
			name:      "v1 secret name only without service",
			mountPath: "secret",
			kvVersion: "1",
			req:       secrets.Request{SecretName: "db-password"},
			want:      "secret/db-password",
		},
		{
			name:      "v2 explicit openbao_path",
			mountPath: "secret",
			kvVersion: "2",
			req: secrets.Request{
				SecretName:   "ignored",
				SecretLabels: map[string]string{"openbao_path": "database/mysql"},
			},
			want: "secret/data/database/mysql",
		},
		{
			name:      "v1 explicit openbao_path",
			mountPath: "secret",
			kvVersion: "1",
			req: secrets.Request{
				SecretName:   "ignored",
				SecretLabels: map[string]string{"openbao_path": "database/mysql"},
			},
			want: "secret/database/mysql",
		},
		{
			name:      "v2 explicit openbao_path custom mount",
			mountPath: "kv",
			kvVersion: "2",
			req: secrets.Request{
				SecretName:   "ignored",
				SecretLabels: map[string]string{"openbao_path": "database/mysql"},
			},
			want: "kv/data/database/mysql",
		},
		{
			name:      "v1 explicit openbao_path custom mount",
			mountPath: "kv",
			kvVersion: "1",
			req: secrets.Request{
				SecretName:   "ignored",
				SecretLabels: map[string]string{"openbao_path": "database/mysql"},
			},
			want: "kv/database/mysql",
		},
		{
			name:      "v2 explicit path normalization preserved",
			mountPath: "secret",
			kvVersion: "2",
			req: secrets.Request{
				SecretName:   "ignored",
				SecretLabels: map[string]string{"openbao_path": "/secret/data/database/mysql/"},
			},
			want: "secret/data/database/mysql",
		},
		{
			name:      "v1 explicit path normalization preserves literal data",
			mountPath: "secret",
			kvVersion: "1",
			req: secrets.Request{
				SecretName:   "ignored",
				SecretLabels: map[string]string{"openbao_path": "/secret/data/database/mysql/"},
			},
			want: "secret/data/database/mysql",
		},
		{
			name:      "v1 relative data path keeps data folder",
			mountPath: "secret",
			kvVersion: "1",
			req: secrets.Request{
				SecretName:   "ignored",
				SecretLabels: map[string]string{"openbao_path": "data/mysql"},
			},
			want: "secret/data/mysql",
		},
		{
			name:      "v1 mount-qualified path preserves literal data folder",
			mountPath: "secret",
			kvVersion: "1",
			req: secrets.Request{
				SecretName:   "ignored",
				SecretLabels: map[string]string{"openbao_path": "secret/data/mysql"},
			},
			want: "secret/data/mysql",
		},
		{
			name:      "v1 relative data path keeps data folder on custom mount",
			mountPath: "kv",
			kvVersion: "1",
			req: secrets.Request{
				SecretName:   "ignored",
				SecretLabels: map[string]string{"openbao_path": "data/mysql"},
			},
			want: "kv/data/mysql",
		},
		{
			name:      "v1 mount-qualified path preserves literal data folder on custom mount",
			mountPath: "kv",
			kvVersion: "1",
			req: secrets.Request{
				SecretName:   "ignored",
				SecretLabels: map[string]string{"openbao_path": "kv/data/mysql"},
			},
			want: "kv/data/mysql",
		},
		{
			name:      "v2 relative data path normalization unchanged",
			mountPath: "secret",
			kvVersion: "2",
			req: secrets.Request{
				SecretName:   "ignored",
				SecretLabels: map[string]string{"openbao_path": "data/mysql"},
			},
			want: "secret/data/mysql",
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
			p := newOpenBaoProviderForPathTest(tt.mountPath, tt.kvVersion)
			if got := p.BuildSecretPath(tt.req); got != tt.want {
				t.Fatalf("BuildSecretPath() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestOpenBaoProvider_Initialize_RejectsUnsupportedKVVersion(t *testing.T) {
	for _, bad := range []string{"3", "v1", "v2", "V1", "0", "foo", "v", "12"} {
		t.Run("kv="+bad, func(t *testing.T) {
			p := &OpenBaoProvider{}
			err := p.Initialize(map[string]string{"OPENBAO_KV_VERSION": bad})
			if err == nil {
				t.Fatal("Initialize() error = nil, want error for unsupported KV version")
			}
			if !strings.Contains(err.Error(), "OPENBAO_KV_VERSION") {
				t.Fatalf("Initialize() error = %q, want it to name OPENBAO_KV_VERSION", err.Error())
			}
		})
	}
}

func TestParseOpenBaoConfig_KVVersionDefault(t *testing.T) {
	cfg := vaultcompat.ParseOpenBaoConfig(map[string]string{})
	if cfg.KVVersion != "2" {
		t.Fatalf("KVVersion = %q, want %q (backward-compatible default)", cfg.KVVersion, "2")
	}

	cfg = vaultcompat.ParseOpenBaoConfig(map[string]string{"OPENBAO_KV_VERSION": "1"})
	if cfg.KVVersion != "1" {
		t.Fatalf("KVVersion = %q, want %q", cfg.KVVersion, "1")
	}

	if cfg.MountPath != "secret" {
		t.Fatalf("MountPath = %q, want %q", cfg.MountPath, "secret")
	}
}

func TestNormalizeOpenBaoKVVersion(t *testing.T) {
	valid := map[string]string{
		"1":   "1",
		"2":   "2",
		" 1 ": "1",
		" 2 ": "2",
		"":    "2",
	}
	for raw, want := range valid {
		if got, err := vaultcompat.NormalizeOpenBaoKVVersion(raw); err != nil || got != want {
			t.Fatalf("NormalizeOpenBaoKVVersion(%q) = %q, %v; want %q, nil", raw, got, err, want)
		}
	}

	for _, bad := range []string{"3", "v1", "v2", "V1", "foo", "12", "v"} {
		if got, err := vaultcompat.NormalizeOpenBaoKVVersion(bad); err == nil {
			t.Fatalf("NormalizeOpenBaoKVVersion(%q) = %q, nil; want error", bad, got)
		}
	}
}

// TestOpenBaoProvider_BuildSecretPathThroughConfig proves the provider
// configuration (ParseOpenBaoConfig + NormalizeOpenBaoKVVersion) drives path
// construction end to end: unset defaults to v2, "1" selects v1, "2" selects
// v2. Invalid values never reach path construction because Initialize rejects
// them first (see TestOpenBaoProvider_Initialize_RejectsUnsupportedKVVersion).
func TestOpenBaoProvider_BuildSecretPathThroughConfig(t *testing.T) {
	tests := []struct {
		name    string
		version string // "" means unset
		want    string
	}{
		{name: "default/unset is v2", version: "", want: "secret/data/my-service/db-password"},
		{name: "1 is v1", version: "1", want: "secret/my-service/db-password"},
		{name: "2 is v2", version: "2", want: "secret/data/my-service/db-password"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pluginConfig := map[string]string{}
			if tt.version != "" {
				pluginConfig["OPENBAO_KV_VERSION"] = tt.version
			}
			cfg := vaultcompat.ParseOpenBaoConfig(pluginConfig)
			kvVersion, err := vaultcompat.NormalizeOpenBaoKVVersion(cfg.KVVersion)
			if err != nil {
				t.Fatalf("NormalizeOpenBaoKVVersion(%q) error = %v", cfg.KVVersion, err)
			}
			cfg.KVVersion = kvVersion

			p := &OpenBaoProvider{config: cfg}
			req := secrets.Request{SecretName: "db-password", ServiceName: "my-service"}
			if got := p.BuildSecretPath(req); got != tt.want {
				t.Fatalf("BuildSecretPath() = %q, want %q", got, tt.want)
			}
		})
	}
}
