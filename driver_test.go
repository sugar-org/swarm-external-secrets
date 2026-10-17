package main

import (
	"strings"
	"testing"

	"github.com/docker/docker/api/types/swarm"
)

func TestFindActiveSecret(t *testing.T) {
	secrets := []swarm.Secret{
		{ID: "old-id", Spec: swarm.SecretSpec{Annotations: swarm.Annotations{Name: "api-1771066350000000000"}}},
		{ID: "other-id", Spec: swarm.SecretSpec{Annotations: swarm.Annotations{Name: "api-prod-1771066350000000001"}}},
	}
	services := []swarm.Service{{
		Spec: swarm.ServiceSpec{Annotations: swarm.Annotations{Name: "target-service"}, TaskTemplate: swarm.TaskSpec{ContainerSpec: &swarm.ContainerSpec{
			Secrets: []*swarm.SecretReference{{SecretID: "old-id", SecretName: "api-1771066350000000000"}},
		}}},
	}}

	got, err := findActiveSecret(secrets, services, "api", []string{"target-service"})
	if err != nil {
		t.Fatalf("findActiveSecret() error = %v", err)
	}
	if got == nil || got.ID != "old-id" {
		t.Fatalf("findActiveSecret() = %#v, want secret old-id", got)
	}
}

func TestFindActiveSecretPrefersReferencedVersionOverOrphan(t *testing.T) {
	secrets := []swarm.Secret{
		{ID: "orphan-id", Spec: swarm.SecretSpec{Annotations: swarm.Annotations{Name: "api"}}},
		{ID: "active-id", Spec: swarm.SecretSpec{Annotations: swarm.Annotations{Name: "api-1771066350000000000"}}},
	}
	services := []swarm.Service{{
		Spec: swarm.ServiceSpec{Annotations: swarm.Annotations{Name: "target-service"}, TaskTemplate: swarm.TaskSpec{ContainerSpec: &swarm.ContainerSpec{
			Secrets: []*swarm.SecretReference{{SecretID: "active-id"}},
		}}},
	}}

	got, err := findActiveSecret(secrets, services, "api", []string{"target-service"})
	if err != nil {
		t.Fatalf("findActiveSecret() error = %v", err)
	}
	if got == nil || got.ID != "active-id" {
		t.Fatalf("findActiveSecret() = %#v, want secret active-id", got)
	}
}

func TestFindActiveSecretRejectsAmbiguousMatches(t *testing.T) {
	secrets := []swarm.Secret{
		{ID: "first-id", Spec: swarm.SecretSpec{Annotations: swarm.Annotations{Name: "api-1771066350000000000"}}},
		{ID: "second-id", Spec: swarm.SecretSpec{Annotations: swarm.Annotations{Name: "api-1771066350000000001"}}},
	}
	services := []swarm.Service{
		{Spec: swarm.ServiceSpec{Annotations: swarm.Annotations{Name: "first-service"}, TaskTemplate: swarm.TaskSpec{ContainerSpec: &swarm.ContainerSpec{Secrets: []*swarm.SecretReference{{SecretID: "first-id"}}}}}},
		{Spec: swarm.ServiceSpec{Annotations: swarm.Annotations{Name: "second-service"}, TaskTemplate: swarm.TaskSpec{ContainerSpec: &swarm.ContainerSpec{Secrets: []*swarm.SecretReference{{SecretID: "second-id"}}}}}},
	}

	got, err := findActiveSecret(secrets, services, "api", []string{"first-service", "second-service"})
	if got != nil {
		t.Fatalf("findActiveSecret() = %#v, want nil", got)
	}
	if err == nil || !strings.Contains(err.Error(), "multiple active versions") {
		t.Fatalf("findActiveSecret() error = %v, want multiple active versions", err)
	}
}

func TestFindActiveSecretRejectsUnreferencedCandidate(t *testing.T) {
	secrets := []swarm.Secret{{
		ID: "orphan-id", Spec: swarm.SecretSpec{Annotations: swarm.Annotations{Name: "api-1771066350000000000"}},
	}}

	got, err := findActiveSecret(secrets, nil, "api", []string{"target-service"})
	if got != nil {
		t.Fatalf("findActiveSecret() = %#v, want nil", got)
	}
	if err == nil || !strings.Contains(err.Error(), "no active version") {
		t.Fatalf("findActiveSecret() error = %v, want no active version", err)
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
