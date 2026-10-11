package providers

import (
	"testing"
)

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
