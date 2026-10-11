package providers

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestOpenBaoProvider_GetSecret_Base64Decode(t *testing.T) {
	binaryPayload := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01, 0x02}
	encodedPayload := base64.StdEncoding.EncodeToString(binaryPayload)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/secret/data/app/binary":
			_, _ = fmt.Fprintf(w, `{"data":{"data":{"keystore":"%s"}}}`, encodedPayload)
		default:
			t.Fatalf("unexpected request path: %s", r.URL.Path)
		}
	}))
	defer server.Close()

	provider := &OpenBaoProvider{}
	if err := provider.Initialize(map[string]string{
		"OPENBAO_ADDR":  server.URL,
		"OPENBAO_TOKEN": "test-token",
	}); err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}
	defer func() { _ = provider.Close() }()

	if got := provider.GetProviderName(); got != "openbao" {
		t.Fatalf("GetProviderName() = %q, want openbao", got)
	}

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
