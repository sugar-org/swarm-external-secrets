package main

import (
	"context"
	"crypto/sha256"
	"fmt"
	"slices"
	"testing"

	"github.com/docker/docker/api/types/swarm"
	"github.com/docker/go-plugins-helpers/secrets"

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

// ---------------------------------------------------------------------------
// Mock provider for rotation-detection tests
// ---------------------------------------------------------------------------

// mockProvider is a minimal SecretsProvider that returns a controlled value
// from GetSecret. Only the fields needed for the tracking/rotation tests are
// implemented; the rest are no-ops.
type mockProvider struct {
	value []byte // value returned by GetSecret
}

func (m *mockProvider) Initialize(_ map[string]string) error              { return nil }
func (m *mockProvider) GetSecret(_ context.Context, _ *providers.SecretInfo) ([]byte, error) {
	return m.value, nil
}
func (m *mockProvider) SupportsRotation() bool                            { return true }
func (m *mockProvider) GetSecretFieldLabel() string                       { return "mock_field" }
func (m *mockProvider) BuildSecretPath(_ secrets.Request) string          { return "" }
func (m *mockProvider) GetProviderName() string                           { return "mock" }
func (m *mockProvider) Close() error                                      { return nil }

// ---------------------------------------------------------------------------
// Helper: build a minimal SecretsDriver with only the tracker initialised
// ---------------------------------------------------------------------------

func newTestDriver() *SecretsDriver {
	return &SecretsDriver{
		secretTracker: make(map[string]*providers.SecretInfo),
	}
}

func hashOf(v []byte) string {
	return fmt.Sprintf("%x", sha256.Sum256(v))
}

// ---------------------------------------------------------------------------
// Regression tests for trackSecret() baseline-overwrite fix
// ---------------------------------------------------------------------------

// TestTrackSecret_InitializesLastHash verifies that the first call to
// trackSecret establishes the change-detection baseline.
func TestTrackSecret_InitializesLastHash(t *testing.T) {
	d := newTestDriver()
	v1 := []byte("provider-value-v1")

	info := &providers.SecretInfo{
		DockerSecretName: "my-secret",
		SecretPath:       "path/secret",
		SecretField:      "password",
		ServiceNames:     []string{"svc-a"},
		Provider:         "aws",
		Labels:           map[string]string{"kms_decrypt": "true"},
	}

	d.trackSecret(info, v1)

	tracked := d.secretTracker["my-secret"]
	if tracked == nil {
		t.Fatal("expected secret to be tracked")
	}
	if tracked.LastHash != hashOf(v1) {
		t.Fatalf("LastHash = %q, want %q", tracked.LastHash, hashOf(v1))
	}
}

// TestTrackSecret_DoesNotOverwriteLastHashOnRetrack is the primary regression
// test for the baseline-overwrite bug. A second trackSecret call with a
// different provider value must NOT advance LastHash.
func TestTrackSecret_DoesNotOverwriteLastHashOnRetrack(t *testing.T) {
	d := newTestDriver()
	v1 := []byte("provider-value-v1")
	v2 := []byte("provider-value-v2")

	info1 := &providers.SecretInfo{
		DockerSecretName: "my-secret",
		SecretPath:       "path/secret",
		SecretField:      "password",
		ServiceNames:     []string{"svc-a"},
		Provider:         "aws",
		Labels:           map[string]string{"kms_decrypt": "true"},
	}
	d.trackSecret(info1, v1)

	// Simulate a second Get() that sees the new provider value v2.
	info2 := &providers.SecretInfo{
		DockerSecretName: "my-secret",
		SecretPath:       "path/secret",
		SecretField:      "password",
		ServiceNames:     []string{"svc-b"},
		Provider:         "aws",
		Labels:           map[string]string{"kms_decrypt": "true"},
	}
	d.trackSecret(info2, v2)

	tracked := d.secretTracker["my-secret"]
	if tracked.LastHash != hashOf(v1) {
		t.Fatalf("trackSecret overwrote LastHash: got %q, want %q (v1 baseline)",
			tracked.LastHash, hashOf(v1))
	}
}

// TestTrackSecret_MergesServiceNames verifies that multiple services sharing
// one Docker secret are properly aggregated.
func TestTrackSecret_MergesServiceNames(t *testing.T) {
	d := newTestDriver()
	v := []byte("shared-value")

	for _, svc := range []string{"svc-a", "svc-b", "svc-c"} {
		info := &providers.SecretInfo{
			DockerSecretName: "shared-secret",
			SecretPath:       "path/shared",
			SecretField:      "value",
			ServiceNames:     []string{svc},
			Provider:         "vault",
		}
		d.trackSecret(info, v)
	}

	tracked := d.secretTracker["shared-secret"]
	for _, want := range []string{"svc-a", "svc-b", "svc-c"} {
		if !slices.Contains(tracked.ServiceNames, want) {
			t.Fatalf("ServiceNames = %v, missing %q", tracked.ServiceNames, want)
		}
	}

	// Duplicate service name must not be appended again.
	dup := &providers.SecretInfo{
		DockerSecretName: "shared-secret",
		SecretPath:       "path/shared",
		SecretField:      "value",
		ServiceNames:     []string{"svc-a"},
		Provider:         "vault",
	}
	d.trackSecret(dup, v)
	count := 0
	for _, s := range tracked.ServiceNames {
		if s == "svc-a" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("svc-a appears %d times in ServiceNames, want 1", count)
	}
}

// TestTrackSecret_UpdatesLabelsOnRetrack verifies that label changes (e.g.
// from a stack redeploy) are propagated to the tracked entry.
func TestTrackSecret_UpdatesLabelsOnRetrack(t *testing.T) {
	d := newTestDriver()
	v := []byte("value")

	info1 := &providers.SecretInfo{
		DockerSecretName: "my-secret",
		SecretPath:       "path/secret",
		SecretField:      "password",
		ServiceNames:     []string{"svc-a"},
		Provider:         "aws",
		Labels:           map[string]string{"kms_decrypt": "true"},
	}
	d.trackSecret(info1, v)

	info2 := &providers.SecretInfo{
		DockerSecretName: "my-secret",
		SecretPath:       "path/secret",
		SecretField:      "password",
		ServiceNames:     []string{"svc-a"},
		Provider:         "aws",
		Labels:           map[string]string{"kms_decrypt": "false", "new_label": "yes"},
	}
	d.trackSecret(info2, v)

	tracked := d.secretTracker["my-secret"]
	if tracked.Labels["kms_decrypt"] != "false" {
		t.Fatalf("Labels[kms_decrypt] = %q, want %q", tracked.Labels["kms_decrypt"], "false")
	}
	if tracked.Labels["new_label"] != "yes" {
		t.Fatalf("Labels[new_label] = %q, want %q", tracked.Labels["new_label"], "yes")
	}
}

// TestTrackSecret_RepeatedSameValue verifies that repeated Get() calls with
// an unchanged provider value are harmless (idempotent).
func TestTrackSecret_RepeatedSameValue(t *testing.T) {
	d := newTestDriver()
	v := []byte("stable-value")

	info := &providers.SecretInfo{
		DockerSecretName: "my-secret",
		SecretPath:       "path/secret",
		SecretField:      "password",
		ServiceNames:     []string{"svc-a"},
		Provider:         "aws",
		Labels:           map[string]string{},
	}

	for i := 0; i < 10; i++ {
		d.trackSecret(info, v)
	}

	tracked := d.secretTracker["my-secret"]
	if tracked.LastHash != hashOf(v) {
		t.Fatalf("LastHash = %q, want %q", tracked.LastHash, hashOf(v))
	}
	if len(tracked.ServiceNames) != 1 {
		t.Fatalf("ServiceNames length = %d, want 1", len(tracked.ServiceNames))
	}
}

// TestHasSecretChanged_NotSuppressedByRetrack is a focused change-detection
// regression test: after tracking v1 and then retracking with v2 (simulating
// an ordinary Get() that observes the new provider value), hasSecretChanged()
// must still report a change because the baseline was not advanced.
//
// This test exercises the driver-level invariant. It does not reproduce the
// exact smoke-test-awssm interleaving from issue #196.
func TestHasSecretChanged_NotSuppressedByRetrack(t *testing.T) {
	v1 := []byte("ciphertext-v1")
	v2 := []byte("ciphertext-v2")

	mock := &mockProvider{value: v2}

	d := &SecretsDriver{
		secretTracker: make(map[string]*providers.SecretInfo),
		provider:      mock,
	}

	// Step 1: initial tracking establishes baseline at v1.
	info1 := &providers.SecretInfo{
		DockerSecretName: "my-secret",
		SecretPath:       "path/secret",
		SecretField:      "password",
		ServiceNames:     []string{"svc-a"},
		Provider:         "mock",
		Labels:           map[string]string{},
	}
	d.trackSecret(info1, v1)

	// Step 2: simulate a later Get() that observes v2 from the provider.
	info2 := &providers.SecretInfo{
		DockerSecretName: "my-secret",
		SecretPath:       "path/secret",
		SecretField:      "password",
		ServiceNames:     []string{"svc-a"},
		Provider:         "mock",
		Labels:           map[string]string{},
	}
	d.trackSecret(info2, v2)

	// Step 3: the rotation ticker calls hasSecretChanged.
	// The mock provider returns v2. Because the baseline is still v1,
	// hasSecretChanged must return true.
	tracked := d.secretTracker["my-secret"]
	if !d.hasSecretChanged(tracked) {
		t.Fatal("hasSecretChanged() = false after retrack with changed value; " +
			"rotation would be suppressed (baseline-overwrite bug)")
	}
}
