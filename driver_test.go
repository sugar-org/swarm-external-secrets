package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/docker/docker/api/types/swarm"
	"github.com/docker/go-plugins-helpers/secrets"

	"github.com/sugar-org/vault-swarm-plugin/providers"
)

type fakeProvider struct {
	name     string
	secrets  map[string]map[string]string
	requests []secrets.Request
}

func (f *fakeProvider) Initialize(config map[string]string) error {
	return nil
}

func (f *fakeProvider) GetSecret(ctx context.Context, req secrets.Request) ([]byte, error) {
	f.requests = append(f.requests, req)

	path := providerPathFromLabels(req.SecretLabels, f.name)
	field := providerFieldFromLabels(req.SecretLabels, f.name)
	if field == "" {
		field = "value"
	}

	fields, exists := f.secrets[path]
	if !exists {
		return nil, fmt.Errorf("missing path %s", path)
	}
	value, exists := fields[field]
	if !exists {
		return nil, fmt.Errorf("missing field %s", field)
	}
	return []byte(value), nil
}

func (f *fakeProvider) SupportsRotation() bool {
	return true
}

func (f *fakeProvider) CheckSecretChanged(ctx context.Context, secretInfo *providers.SecretInfo) (bool, error) {
	return false, nil
}

func (f *fakeProvider) GetProviderName() string {
	return f.name
}

func (f *fakeProvider) Matches(requested string) bool {
	return strings.EqualFold(requested, f.name)
}

func (f *fakeProvider) Close() error {
	return nil
}

func providerPathFromLabels(labels map[string]string, providerName string) string {
	switch providerName {
	case "vault":
		return labels["vault_path"]
	case "aws":
		return labels["aws_secret_name"]
	case "gcp":
		return labels["gcp_secret_name"]
	case "azure":
		return labels["azure_secret_name"]
	case "openbao":
		return labels["openbao_path"]
	default:
		return ""
	}
}

func providerFieldFromLabels(labels map[string]string, providerName string) string {
	switch providerName {
	case "vault":
		return labels["vault_field"]
	case "aws":
		return labels["aws_field"]
	case "gcp":
		return labels["gcp_field"]
	case "azure":
		return labels["azure_field"]
	case "openbao":
		return labels["openbao_field"]
	default:
		return ""
	}
}

func TestGetAggregatedSecretJSON(t *testing.T) {
	provider := &fakeProvider{
		name: "vault",
		secrets: map[string]map[string]string{
			"database/mysql":    {"password": "mysql-pass"},
			"database/postgres": {"password": "pg-pass"},
		},
	}
	driver := &SecretsDriver{provider: provider}

	value, err := driver.getAggregatedSecret(context.Background(), secrets.Request{
		SecretName: "app_credentials",
		SecretLabels: map[string]string{
			secretSourcesLabel: `[
				{"path":"database/mysql","field":"password","key":"MYSQL_PASSWORD"},
				{"path":"database/postgres","field":"password","key":"POSTGRES_PASSWORD"}
			]`,
		},
	})
	if err != nil {
		t.Fatalf("getAggregatedSecret returned error: %v", err)
	}

	var got map[string]string
	if err := json.Unmarshal(value, &got); err != nil {
		t.Fatalf("aggregated secret is not JSON: %v", err)
	}

	want := map[string]string{
		"MYSQL_PASSWORD":    "mysql-pass",
		"POSTGRES_PASSWORD": "pg-pass",
	}
	assertStringMap(t, got, want)

	if len(provider.requests) != 2 {
		t.Fatalf("provider requests = %d, want 2", len(provider.requests))
	}
	if provider.requests[0].SecretLabels["vault_path"] != "database/mysql" {
		t.Fatalf("first vault_path = %q, want database/mysql", provider.requests[0].SecretLabels["vault_path"])
	}
	if provider.requests[1].SecretLabels["vault_field"] != "password" {
		t.Fatalf("second vault_field = %q, want password", provider.requests[1].SecretLabels["vault_field"])
	}
}

func TestGetAggregatedSecretEnvFormat(t *testing.T) {
	provider := &fakeProvider{
		name: "aws",
		secrets: map[string]map[string]string{
			"prod/api": {"token": "abc"},
			"prod/db":  {"password": "xyz"},
		},
	}
	driver := &SecretsDriver{provider: provider}

	value, err := driver.getAggregatedSecret(context.Background(), secrets.Request{
		SecretName: "app_credentials",
		SecretLabels: map[string]string{
			secretSourcesLabel: `[
				{"path":"prod/api","field":"token","key":"API_TOKEN"},
				{"path":"prod/db","field":"password","key":"DB_PASSWORD"}
			]`,
			secretFormatLabel: "env",
		},
	})
	if err != nil {
		t.Fatalf("getAggregatedSecret returned error: %v", err)
	}

	want := "API_TOKEN=abc\nDB_PASSWORD=xyz\n"
	if string(value) != want {
		t.Fatalf("aggregated env payload = %q, want %q", string(value), want)
	}
}

func TestGetAggregatedSecretRejectsUnsupportedFormat(t *testing.T) {
	provider := &fakeProvider{
		name: "vault",
		secrets: map[string]map[string]string{
			"prod/api": {"token": "abc"},
		},
	}
	driver := &SecretsDriver{provider: provider}
	_, err := driver.getAggregatedSecret(context.Background(), secrets.Request{
		SecretName: "app_credentials",
		SecretLabels: map[string]string{
			secretSourcesLabel: `[{"path":"prod/api","field":"token","key":"API_TOKEN"}]`,
			secretFormatLabel:  "xml",
		},
	})
	if err == nil {
		t.Fatal("expected unsupported format error")
	}
}

func TestRenderAggregatedSecretEnvRejectsInvalidKey(t *testing.T) {
	tests := []struct {
		name string
		key  string
	}{
		{name: "starts with number", key: "1KEY"},
		{name: "contains dash", key: "MY-KEY"},
		{name: "contains dot", key: "MY.KEY"},
		{name: "lowercase", key: "my_key"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := renderAggregatedSecret(map[string]string{tt.key: "value"}, "env")
			if err == nil {
				t.Fatalf("expected error for invalid key %q", tt.key)
			}
		})
	}
}

func TestRenderAggregatedSecretEnvEscapesValues(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		wantEsc string
	}{
		{name: "newline", value: "hello\nworld", wantEsc: "hello\\nworld"},
		{name: "backslash", value: "path\\to\\file", wantEsc: "path\\\\to\\\\file"},
		{name: "carriage return", value: "hello\rworld", wantEsc: "hello\\rworld"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, err := renderAggregatedSecret(map[string]string{"KEY": tt.value}, "env")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !strings.Contains(string(out), tt.wantEsc) {
				t.Fatalf("expected escaped value %q in output %q", tt.wantEsc, string(out))
			}
		})
	}
}

func TestParseSecretSourcesRejectsDifferentProvider(t *testing.T) {
	provider := &fakeProvider{name: "vault"}
	_, err := parseSecretSources(map[string]string{
		secretSourcesLabel: `[{"provider":"aws","path":"prod/db","field":"password","key":"DB_PASSWORD"}]`,
	}, provider)
	if err == nil {
		t.Fatal("expected provider mismatch error")
	}
}

func TestParseSecretSourcesRejectsInvalidJSON(t *testing.T) {
	provider := &fakeProvider{name: "vault"}
	_, err := parseSecretSources(map[string]string{
		secretSourcesLabel: `[{"path":"prod/db","field":"password","key":"DB_PASSWORD"`,
	}, provider)
	if err == nil {
		t.Fatal("expected invalid JSON error")
	}
}

func TestParseSecretSourcesRejectsMissingRequiredFields(t *testing.T) {
	provider := &fakeProvider{name: "vault"}
	tests := []struct {
		name   string
		source string
	}{
		{
			name:   "missing path",
			source: `[{"field":"password","key":"DB_PASSWORD"}]`,
		},
		{
			name:   "missing key",
			source: `[{"path":"prod/db","field":"password"}]`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseSecretSources(map[string]string{
				secretSourcesLabel: tt.source,
			}, provider)
			if err == nil {
				t.Fatalf("expected error for %s", tt.name)
			}
		})
	}
}

func TestParseSecretSourcesRejectsDuplicateKey(t *testing.T) {
	provider := &fakeProvider{name: "vault"}
	_, err := parseSecretSources(map[string]string{
		secretSourcesLabel: `[
			{"path":"prod/api","field":"token","key":"APP_SECRET"},
			{"path":"prod/db","field":"password","key":"APP_SECRET"}
		]`,
	}, provider)
	if err == nil {
		t.Fatal("expected duplicate key error")
	}
}

func TestLabelsForSecretSourceAllProviders(t *testing.T) {
	tests := []struct {
		provider  string
		pathLabel string
		fieldKey  string
	}{
		{provider: "vault", pathLabel: "vault_path", fieldKey: "vault_field"},
		{provider: "aws", pathLabel: "aws_secret_name", fieldKey: "aws_field"},
		{provider: "gcp", pathLabel: "gcp_secret_name", fieldKey: "gcp_field"},
		{provider: "azure", pathLabel: "azure_secret_name", fieldKey: "azure_field"},
		{provider: "openbao", pathLabel: "openbao_path", fieldKey: "openbao_field"},
	}

	for _, tt := range tests {
		t.Run(tt.provider, func(t *testing.T) {
			labels := labelsForSecretSource(map[string]string{
				secretSourcesLabel: "[]",
				secretFormatLabel:  "json",
				"secret_reuse":     "true",
			}, tt.provider, secretSource{
				Path:  "app/path",
				Field: "password",
				Key:   "APP_PASSWORD",
			})

			if labels[tt.pathLabel] != "app/path" {
				t.Fatalf("%s = %q, want app/path", tt.pathLabel, labels[tt.pathLabel])
			}
			if labels[tt.fieldKey] != "password" {
				t.Fatalf("%s = %q, want password", tt.fieldKey, labels[tt.fieldKey])
			}
			if _, exists := labels[secretSourcesLabel]; exists {
				t.Fatalf("%s should not be forwarded to provider request", secretSourcesLabel)
			}
			if labels["secret_reuse"] != "true" {
				t.Fatal("expected unrelated labels to be preserved")
			}
		})
	}
}

func assertStringMap(t *testing.T, got, want map[string]string) {
	t.Helper()

	if len(got) != len(want) {
		t.Fatalf("map length = %d, want %d", len(got), len(want))
	}
	for key, wantValue := range want {
		if got[key] != wantValue {
			t.Fatalf("%s = %q, want %q", key, got[key], wantValue)
		}
	}
}

func TestBuildUpdatedSecretReferences(t *testing.T) {
	tests := []struct {
		name          string
		ref           *swarm.SecretReference
		oldSecretID   string
		newSecretName string
		wantUpdate    bool
		wantRef       *swarm.SecretReference
	}{
		{
			name: "updates exact name",
			ref: &swarm.SecretReference{
				SecretID:   "old-id",
				SecretName: "api",
			},
			oldSecretID:   "old-id",
			newSecretName: "api-123",
			wantUpdate:    true,
			wantRef: &swarm.SecretReference{
				SecretID:   "new-id",
				SecretName: "api-123",
			},
		},
		{
			name: "updates rotated name with matching ID",
			ref: &swarm.SecretReference{
				SecretID:   "old-id",
				SecretName: "api-1111111111111111111",
			},
			oldSecretID:   "old-id",
			newSecretName: "api-2222222222222222222",
			wantUpdate:    true,
			wantRef: &swarm.SecretReference{
				SecretID:   "new-id",
				SecretName: "api-2222222222222222222",
			},
		},
		{
			name: "preserves prefix collision",
			ref: &swarm.SecretReference{
				SecretID:   "prod-id",
				SecretName: "api-prod",
			},
			oldSecretID: "old-id",
		},
		{
			name: "does not match empty old ID",
			ref: &swarm.SecretReference{
				SecretName: "api-prod",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			secretRefs := []*swarm.SecretReference{tt.ref}
			updatedSecrets := make([]*swarm.SecretReference, len(secretRefs))

			needsUpdate := buildUpdatedSecretReferences(
				secretRefs,
				"api",
				tt.oldSecretID,
				tt.newSecretName,
				"new-id",
				updatedSecrets,
			)

			assertSecretReferenceUpdate(t, needsUpdate, tt.wantUpdate, updatedSecrets[0], tt.ref, tt.wantRef)
		})
	}
}

func assertSecretReferenceUpdate(
	t *testing.T,
	gotUpdate bool,
	wantUpdate bool,
	gotRef *swarm.SecretReference,
	originalRef *swarm.SecretReference,
	wantRef *swarm.SecretReference,
) {
	t.Helper()

	if gotUpdate != wantUpdate {
		t.Fatalf("needsUpdate = %v, want %v", gotUpdate, wantUpdate)
	}
	if !wantUpdate {
		assertSecretReferencePreserved(t, gotRef, originalRef)
		return
	}
	assertSecretReference(t, gotRef, wantRef)
}

func assertSecretReferencePreserved(t *testing.T, gotRef, originalRef *swarm.SecretReference) {
	t.Helper()

	if gotRef != originalRef {
		t.Fatal("expected unrelated secret reference to be preserved")
	}
}

func assertSecretReference(t *testing.T, gotRef, wantRef *swarm.SecretReference) {
	t.Helper()

	if gotRef.SecretID != wantRef.SecretID {
		t.Fatalf("SecretID = %q, want %q", gotRef.SecretID, wantRef.SecretID)
	}
	if gotRef.SecretName != wantRef.SecretName {
		t.Fatalf("SecretName = %q, want %q", gotRef.SecretName, wantRef.SecretName)
	}
}
