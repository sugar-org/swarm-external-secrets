package providers

import (
	"testing"

	"github.com/docker/go-plugins-helpers/secrets"

	"github.com/sugar-org/swarm-external-secrets/internal/vaultcompat"
)

const openBaoPathLabel = "openbao_path"

func newOpenBaoProviderForPathTest(mountPath, kvVersion string) secretPathBuilder {
	return &OpenBaoProvider{
		config: vaultcompat.Config{
			ProviderName: "openbao",
			EnvPrefix:    "OPENBAO",
			MountPath:    mountPath,
			PathLabel:    openBaoPathLabel,
			FieldLabel:   "openbao_field",
			KVVersion:    kvVersion,
		},
	}
}

// TestOpenBaoProvider_BuildSecretPath runs the shared KV v1/v2 path matrix with
// the OpenBao path label.
func TestOpenBaoProvider_BuildSecretPath(t *testing.T) {
	runSharedKVPathCases(t, openBaoPathLabel, newOpenBaoProviderForPathTest)
}

// TestOpenBaoProvider_Initialize_RejectsUnsupportedKVVersion keeps the
// OpenBao-specific contract: Initialize names OPENBAO_KV_VERSION when it fails.
func TestOpenBaoProvider_Initialize_RejectsUnsupportedKVVersion(t *testing.T) {
	runUnsupportedKVVersionRejection(t, "OPENBAO_KV_VERSION", func(config map[string]string) error {
		return (&OpenBaoProvider{}).Initialize(config)
	})
}

func TestParseOpenBaoConfig_KVVersionDefault(t *testing.T) {
	runKVVersionConfigDefaults(t, "OPENBAO_KV_VERSION", vaultcompat.ParseOpenBaoConfig)
}

func TestNormalizeOpenBaoKVVersion(t *testing.T) {
	runKVVersionNormalizationCases(t, vaultcompat.NormalizeOpenBaoKVVersion)
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
