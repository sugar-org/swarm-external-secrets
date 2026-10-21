package main

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/docker/docker/api/types/swarm"
	"github.com/sugar-org/swarm-external-secrets/providers"
)

type rotationDockerClient struct {
	secrets              map[string]swarm.Secret
	services             map[string]swarm.Service
	serviceOrder         []string
	failServiceID        string
	failedOnce           bool
	created              int
	listStarted          chan struct{}
	continueList         <-chan struct{}
	listOnce             sync.Once
	createContext        context.Context
	failedContext        context.Context
	pendingRollback      bool
	rollbackContextFresh bool
	cleanupContextFresh  bool
	mutateOnFailure      bool
	applyOnFailure       bool
}

func (c *rotationDockerClient) SecretList(context.Context, swarm.SecretListOptions) ([]swarm.Secret, error) {
	secrets := make([]swarm.Secret, 0, len(c.secrets))
	for _, secret := range c.secrets {
		secrets = append(secrets, secret)
	}
	return secrets, nil
}

func (c *rotationDockerClient) ServiceList(context.Context, swarm.ServiceListOptions) ([]swarm.Service, error) {
	if c.listStarted != nil {
		c.listOnce.Do(func() {
			close(c.listStarted)
			<-c.continueList
		})
	}
	services := make([]swarm.Service, 0, len(c.services))
	for _, id := range c.serviceOrder {
		services = append(services, cloneTestService(c.services[id]))
	}
	return services, nil
}

func (c *rotationDockerClient) SecretCreate(ctx context.Context, spec swarm.SecretSpec) (swarm.SecretCreateResponse, error) {
	c.created++
	c.createContext = ctx
	id := "new-id-" + string(rune('0'+c.created))
	c.secrets[id] = swarm.Secret{ID: id, Spec: spec}
	return swarm.SecretCreateResponse{ID: id}, nil
}

func (c *rotationDockerClient) SecretRemove(ctx context.Context, id string) error {
	if id == "new-id-1" {
		c.cleanupContextFresh = ctx != c.createContext
	}
	for _, service := range c.services {
		for _, ref := range service.Spec.TaskTemplate.ContainerSpec.Secrets {
			if ref.SecretID == id {
				return errors.New("secret is in use")
			}
		}
	}
	delete(c.secrets, id)
	return nil
}

func (c *rotationDockerClient) ServiceUpdate(ctx context.Context, id string, version swarm.Version, spec swarm.ServiceSpec, _ swarm.ServiceUpdateOptions) (swarm.ServiceUpdateResponse, error) {
	if id == c.failServiceID && !c.failedOnce {
		c.failedOnce = true
		c.failedContext = ctx
		c.pendingRollback = true
		if c.mutateOnFailure {
			service := c.services["first-id"]
			service.Spec.TaskTemplate.ContainerSpec.Image = "operator:v2"
			service.Spec.Labels["vault.secret.rotated"] = "concurrent-marker"
			service.Version.Index++
			c.services["first-id"] = cloneTestService(service)
		}
		if c.applyOnFailure {
			service := c.services[id]
			service.Spec = spec
			service.Version.Index++
			c.services[id] = cloneTestService(service)
		}
		return swarm.ServiceUpdateResponse{}, context.DeadlineExceeded
	}
	if c.pendingRollback && id == "first-id" {
		c.rollbackContextFresh = ctx != c.failedContext
		c.pendingRollback = false
	}
	service := c.services[id]
	if service.Version != version {
		return swarm.ServiceUpdateResponse{}, errors.New("version conflict")
	}
	service.Spec = spec
	service.Version.Index++
	c.services[id] = cloneTestService(service)
	return swarm.ServiceUpdateResponse{}, nil
}

func (c *rotationDockerClient) Close() error { return nil }

func cloneTestService(service swarm.Service) swarm.Service {
	service.Spec = cloneServiceSpec(service.Spec)
	return service
}

func TestUpdateDockerSecretRollsBackPartialServiceUpdateAndRetries(t *testing.T) {
	client := &rotationDockerClient{
		secrets: map[string]swarm.Secret{
			"old-id": {ID: "old-id", Spec: swarm.SecretSpec{Annotations: swarm.Annotations{Name: "api"}}},
		},
		services: map[string]swarm.Service{
			"first-id":  testService("first-id", "first-service", "old-id", "api"),
			"second-id": testService("second-id", "second-service", "old-id", "api"),
		},
		serviceOrder:    []string{"first-id", "second-id"},
		failServiceID:   "second-id",
		mutateOnFailure: true,
		applyOnFailure:  true,
	}
	driver := &SecretsDriver{dockerClient: client}
	secretInfo := &providers.SecretInfo{DockerSecretName: "api", ServiceNames: []string{"first-service", "second-service"}}

	if err := driver.updateDockerSecret(secretInfo, []byte("rotated")); err == nil {
		t.Fatal("first updateDockerSecret() error = nil, want injected service failure")
	}
	assertTestServiceSecret(t, client.services["first-id"], "old-id")
	assertTestServiceSecret(t, client.services["second-id"], "old-id")
	if _, exists := client.services["second-id"].Spec.Labels["vault.secret.rotated"]; exists {
		t.Fatal("failed service retained the attempted rotation label after rollback")
	}
	assertTestServiceLabelsPreserved(t, client.services["first-id"], "concurrent-marker")
	if got := client.services["first-id"].Spec.TaskTemplate.ContainerSpec.Image; got != "operator:v2" {
		t.Fatalf("service image after rollback = %q, want concurrent operator update", got)
	}
	if !client.rollbackContextFresh {
		t.Fatal("rollback reused the failed forward-update context")
	}
	if !client.cleanupContextFresh {
		t.Fatal("secret cleanup reused the secret-creation context")
	}
	if _, exists := client.secrets["new-id-1"]; exists {
		t.Fatal("partially applied secret still exists after rollback")
	}

	if err := driver.updateDockerSecret(secretInfo, []byte("rotated")); err != nil {
		t.Fatalf("retry updateDockerSecret() error = %v", err)
	}
	assertTestServiceSecret(t, client.services["first-id"], "new-id-2")
	assertTestServiceSecret(t, client.services["second-id"], "new-id-2")
}

func TestUpdateDockerSecretSnapshotsServiceNames(t *testing.T) {
	listStarted := make(chan struct{})
	continueList := make(chan struct{})
	client := &rotationDockerClient{
		secrets: map[string]swarm.Secret{
			"old-id":   {ID: "old-id", Spec: swarm.SecretSpec{Annotations: swarm.Annotations{Name: "api"}}},
			"other-id": {ID: "other-id", Spec: swarm.SecretSpec{Annotations: swarm.Annotations{Name: "api-1771066350000000000"}}},
		},
		services: map[string]swarm.Service{
			"first-id":  testService("first-id", "first-service", "old-id", "api"),
			"second-id": testService("second-id", "second-service", "other-id", "api-1771066350000000000"),
		},
		serviceOrder: []string{"first-id", "second-id"},
		listStarted:  listStarted,
		continueList: continueList,
	}
	serviceNames := make([]string, 1, 2)
	serviceNames[0] = "first-service"
	secretInfo := &providers.SecretInfo{DockerSecretName: "api", ServiceNames: serviceNames}
	driver := &SecretsDriver{
		dockerClient:  client,
		secretTracker: map[string]*providers.SecretInfo{"api": secretInfo},
	}

	result := make(chan error, 1)
	go func() {
		result <- driver.updateDockerSecret(secretInfo, []byte("rotated"))
	}()

	select {
	case <-listStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("updateDockerSecret() did not reach ServiceList")
	}
	driver.trackSecret(&providers.SecretInfo{
		DockerSecretName: "api",
		ServiceNames:     []string{"second-service"},
	}, []byte("current"))
	close(continueList)

	if err := <-result; err != nil {
		t.Fatalf("updateDockerSecret() error = %v", err)
	}
	if got := len(secretInfo.ServiceNames); got != 2 {
		t.Fatalf("tracked service names = %v, want both services", secretInfo.ServiceNames)
	}
}

func testService(id, name, secretID, secretName string) swarm.Service {
	return swarm.Service{
		ID:   id,
		Meta: swarm.Meta{Version: swarm.Version{Index: 1}},
		Spec: swarm.ServiceSpec{
			Annotations: swarm.Annotations{Name: name, Labels: map[string]string{"owner": "test"}},
			TaskTemplate: swarm.TaskSpec{ContainerSpec: &swarm.ContainerSpec{
				Image:   "app:v1",
				Secrets: []*swarm.SecretReference{{SecretID: secretID, SecretName: secretName}},
			}},
		},
	}
}

func assertTestServiceLabelsPreserved(t *testing.T, service swarm.Service, wantRotationLabel string) {
	t.Helper()
	if got := service.Spec.Labels["owner"]; got != "test" {
		t.Fatalf("service %s owner label = %q, want test", service.Spec.Name, got)
	}
	if got := service.Spec.Labels["vault.secret.rotated"]; got != wantRotationLabel {
		t.Fatalf("service %s rotation label = %q, want concurrent marker %q", service.Spec.Name, got, wantRotationLabel)
	}
}

func assertTestServiceSecret(t *testing.T, service swarm.Service, wantID string) {
	t.Helper()
	if got := service.Spec.TaskTemplate.ContainerSpec.Secrets[0].SecretID; got != wantID {
		t.Fatalf("service %s secret ID = %q, want %q", service.Spec.Name, got, wantID)
	}
}

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
