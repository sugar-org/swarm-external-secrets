package main

import (
	"testing"

	"github.com/docker/docker/api/types/swarm"
)

func TestBuildUpdatedSecretReferences(t *testing.T) {
	tests := []struct {
		name           string
		ref            *swarm.SecretReference
		oldSecretID    string
		newSecretName  string
		wantUpdate     bool
		wantSecretID   string
		wantSecretName string
	}{
		{
			name: "updates exact name",
			ref: &swarm.SecretReference{
				SecretID:   "old-id",
				SecretName: "api",
			},
			oldSecretID:    "old-id",
			newSecretName:  "api-123",
			wantUpdate:     true,
			wantSecretID:   "new-id",
			wantSecretName: "api-123",
		},
		{
			name: "updates rotated name with matching ID",
			ref: &swarm.SecretReference{
				SecretID:   "old-id",
				SecretName: "api-1111111111111111111",
			},
			oldSecretID:    "old-id",
			newSecretName:  "api-2222222222222222222",
			wantUpdate:     true,
			wantSecretID:   "new-id",
			wantSecretName: "api-2222222222222222222",
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

			if needsUpdate != tt.wantUpdate {
				t.Fatalf("needsUpdate = %v, want %v", needsUpdate, tt.wantUpdate)
			}

			if !tt.wantUpdate {
				if updatedSecrets[0] != tt.ref {
					t.Fatal("expected unrelated secret reference to be preserved")
				}
				return
			}

			if updatedSecrets[0].SecretID != tt.wantSecretID {
				t.Fatalf("SecretID = %q, want %q", updatedSecrets[0].SecretID, tt.wantSecretID)
			}
			if updatedSecrets[0].SecretName != tt.wantSecretName {
				t.Fatalf("SecretName = %q, want %q", updatedSecrets[0].SecretName, tt.wantSecretName)
			}
		})
	}
}
