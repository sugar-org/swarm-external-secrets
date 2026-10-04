package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/docker/docker/api/types/swarm"

	"github.com/sugar-org/swarm-external-secrets/providers"
)

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

func secretWithBase64Label(name, label string) *providers.SecretInfo {
	info := &providers.SecretInfo{DockerSecretName: name}
	if label != "" {
		info.Labels = map[string]string{"base64_decode": label}
	}
	return info
}

func checkSecretError(t *testing.T, err error, input []byte, errContains []string) {
	t.Helper()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	errMsg := err.Error()
	for _, sub := range errContains {
		if !strings.Contains(errMsg, sub) {
			t.Errorf("error %q should contain %q", errMsg, sub)
		}
	}
	if len(input) > 0 && strings.Contains(errMsg, string(input)) {
		t.Errorf("error %q leaked input secret value %q", errMsg, string(input))
	}
}

func TestTransformSecret_Base64Decode(t *testing.T) {
	binaryData := []byte{0x00, 0xFF, 0xFE, 0x80, 0x7F, 0x12, 0x34, 0x56}
	validBase64Binary := base64.StdEncoding.EncodeToString(binaryData)
	validBase64Text := base64.StdEncoding.EncodeToString([]byte("hello world"))

	tests := []struct {
		name        string
		secretInfo  *providers.SecretInfo
		input       []byte
		want        []byte
		wantErr     bool
		errContains []string
	}{
		{
			name:       "label absent preserves raw value",
			secretInfo: secretWithBase64Label("test-secret", ""),
			input:      []byte("not-decoded-value"),
			want:       []byte("not-decoded-value"),
		},
		{
			name:       "label false preserves raw value",
			secretInfo: secretWithBase64Label("test-secret", "false"),
			input:      []byte("not-decoded-value"),
			want:       []byte("not-decoded-value"),
		},
		{
			name:       "label with 1 does not decode (strict boolean)",
			secretInfo: secretWithBase64Label("test-secret", "1"),
			input:      []byte(validBase64Text),
			want:       []byte(validBase64Text),
		},
		{
			name:       "label true decodes valid base64 text",
			secretInfo: secretWithBase64Label("test-secret", "true"),
			input:      []byte(validBase64Text),
			want:       []byte("hello world"),
		},
		{
			name:       "label TRUE (uppercase) decodes valid base64",
			secretInfo: secretWithBase64Label("test-secret", "TRUE"),
			input:      []byte(validBase64Text),
			want:       []byte("hello world"),
		},
		{
			name:       "label true trims surrounding whitespace and newlines",
			secretInfo: secretWithBase64Label("test-secret", " true "),
			input:      []byte("  " + validBase64Text + " \r\n"),
			want:       []byte("hello world"),
		},
		{
			name:       "label true decodes binary non-UTF-8 bytes correctly without corruption",
			secretInfo: secretWithBase64Label("kafka-keystore", "true"),
			input:      []byte(validBase64Binary),
			want:       binaryData,
		},
		{
			name:       "label true with empty value decodes to empty bytes without error",
			secretInfo: secretWithBase64Label("empty-secret", "true"),
			input:      []byte(""),
			want:       []byte{},
		},
		{
			name:       "label true with whitespace-only value decodes to empty bytes without error",
			secretInfo: secretWithBase64Label("whitespace-secret", "true"),
			input:      []byte("   \r\n\t  "),
			want:       []byte{},
		},
		{
			name:        "label true with invalid base64 returns error with secret/field name but no secret bytes",
			secretInfo:  secretWithBase64Label("my-secret", "true"),
			input:       []byte("super-secret-not-base64!@#$"),
			wantErr:     true,
			errContains: []string{"failed to base64-decode secret", `"my-secret"`},
		},
		{
			name:       "nil secretInfo preserves raw value",
			secretInfo: nil,
			input:      []byte("raw-bytes"),
			want:       []byte("raw-bytes"),
		},
		{
			name:       "nil labels in secretInfo preserves raw value",
			secretInfo: &providers.SecretInfo{DockerSecretName: "secret-without-labels"},
			input:      []byte("raw-bytes"),
			want:       []byte("raw-bytes"),
		},
	}

	driver := &SecretsDriver{}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := driver.transformSecret(context.Background(), tt.secretInfo, tt.input)
			if tt.wantErr {
				checkSecretError(t, err, tt.input, tt.errContains)
				return
			}
			if err != nil {
				t.Fatalf("transformSecret() unexpected error = %v", err)
			}
			if !bytes.Equal(got, tt.want) {
				t.Errorf("transformSecret() got = %v, want %v", got, tt.want)
			}
		})
	}
}
