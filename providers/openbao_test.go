package providers

import (
	"testing"

	"github.com/sugar-org/swarm-external-secrets/internal/vaultcompat"
)

const openBaoPathLabel = "openbao_path"

// openBaoProviderFromConfig adapts a config into the provider under test, so the
// shared path helpers can drive OpenBao without a provider-specific signature.
func openBaoProviderFromConfig(cfg vaultcompat.Config) secretPathBuilder {
	return &OpenBaoProvider{config: cfg}
}

// TestOpenBaoProvider_BuildSecretPath runs the shared KV v1/v2 path matrix with
// the OpenBao path label.
func TestOpenBaoProvider_BuildSecretPath(t *testing.T) {
	runSharedKVPathCases(t, openBaoPathLabel, openBaoProviderFromConfig)
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
// construction end to end; invalid values never reach path construction because
// Initialize rejects them first (see the rejection test above).
func TestOpenBaoProvider_BuildSecretPathThroughConfig(t *testing.T) {
	runSharedKVVersionConfigDrivenPath(t, "OPENBAO_KV_VERSION",
		vaultcompat.ParseOpenBaoConfig,
		vaultcompat.NormalizeOpenBaoKVVersion,
		openBaoProviderFromConfig)
}

func TestOpenBaoProvider_GetSecret_Base64Decode(t *testing.T) {
	testBase64Decode(t, func(serverURL string) SecretsProvider {
		provider := &OpenBaoProvider{}
		if err := provider.Initialize(map[string]string{
			"OPENBAO_ADDR":  serverURL,
			"OPENBAO_TOKEN": "test-token",
		}); err != nil {
			t.Fatalf("Initialize() error = %v", err)
		}
		if got := provider.GetProviderName(); got != "openbao" {
			t.Fatalf("GetProviderName() = %q, want openbao", got)
		}
		return provider
	})
}
