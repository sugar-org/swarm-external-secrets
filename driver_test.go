package main

import (
	"testing"

	"github.com/docker/docker/api/types/swarm"
)

func TestBuildUpdatedSecretReferencesUpdatesExactName(t *testing.T) {
	secretRefs := []*swarm.SecretReference{
		{
			SecretID:   "old-id",
			SecretName: "api",
		},
	}
	updatedSecrets := make([]*swarm.SecretReference, len(secretRefs))

	needsUpdate := buildUpdatedSecretReferences(secretRefs, "api", "old-id", "api-123", "new-id", updatedSecrets)

	if !needsUpdate {
		t.Fatal("expected exact secret reference to be updated")
	}
	if updatedSecrets[0].SecretID != "new-id" {
		t.Fatalf("expected updated secret ID new-id, got %q", updatedSecrets[0].SecretID)
	}
	if updatedSecrets[0].SecretName != "api-123" {
		t.Fatalf("expected updated secret name api-123, got %q", updatedSecrets[0].SecretName)
	}
}

func TestBuildUpdatedSecretReferencesUpdatesMatchingIDForRotatedName(t *testing.T) {
	secretRefs := []*swarm.SecretReference{
		{
			SecretID:   "old-id",
			SecretName: "api-1111111111111111111",
		},
	}
	updatedSecrets := make([]*swarm.SecretReference, len(secretRefs))

	needsUpdate := buildUpdatedSecretReferences(secretRefs, "api", "old-id", "api-2222222222222222222", "new-id", updatedSecrets)

	if !needsUpdate {
		t.Fatal("expected rotated secret reference with matching ID to be updated")
	}
	if updatedSecrets[0].SecretID != "new-id" {
		t.Fatalf("expected updated secret ID new-id, got %q", updatedSecrets[0].SecretID)
	}
	if updatedSecrets[0].SecretName != "api-2222222222222222222" {
		t.Fatalf("expected updated secret name api-2222222222222222222, got %q", updatedSecrets[0].SecretName)
	}
}

func TestBuildUpdatedSecretReferencesDoesNotUpdatePrefixCollision(t *testing.T) {
	secretRefs := []*swarm.SecretReference{
		{
			SecretID:   "prod-id",
			SecretName: "api-prod",
		},
	}
	updatedSecrets := make([]*swarm.SecretReference, len(secretRefs))

	needsUpdate := buildUpdatedSecretReferences(secretRefs, "api", "old-id", "api-123", "new-id", updatedSecrets)

	if needsUpdate {
		t.Fatal("expected unrelated prefix-matching secret reference to be left unchanged")
	}
	if updatedSecrets[0] != secretRefs[0] {
		t.Fatal("expected unrelated secret reference to be preserved")
	}
}

func TestBuildUpdatedSecretReferencesDoesNotMatchEmptyOldID(t *testing.T) {
	secretRefs := []*swarm.SecretReference{
		{
			SecretName: "api-prod",
		},
	}
	updatedSecrets := make([]*swarm.SecretReference, len(secretRefs))

	needsUpdate := buildUpdatedSecretReferences(secretRefs, "api", "", "api-123", "new-id", updatedSecrets)

	if needsUpdate {
		t.Fatal("expected empty old secret ID not to match references with empty IDs")
	}
	if updatedSecrets[0] != secretRefs[0] {
		t.Fatal("expected secret reference to be preserved")
	}
}
