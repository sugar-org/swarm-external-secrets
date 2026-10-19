package secrettransform

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/aws/aws-sdk-go-v2/credentials"
)

func TestAWSKMSTransformerUsesSharedCredentials(t *testing.T) {
	empty := filepath.Join(t.TempDir(), "empty")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AWS_CONFIG_FILE", empty)
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", empty)

	shared := credentials.NewStaticCredentialsProvider("spiffe-akid", "spiffe-secret", "spiffe-session")
	transformer := NewAWSKMSTransformer(map[string]string{
		"AWS_REGION":            "us-east-1",
		"AWS_ACCESS_KEY_ID":     "static-akid",
		"AWS_SECRET_ACCESS_KEY": "static-secret",
	}, shared)

	cfg, err := transformer.loadAWSConfig(t.Context())
	if err != nil {
		t.Fatalf("loadAWSConfig() error = %v", err)
	}
	creds, err := cfg.Credentials.Retrieve(t.Context())
	if err != nil {
		t.Fatalf("Retrieve() error = %v", err)
	}
	if creds.AccessKeyID != "spiffe-akid" || creds.SessionToken != "spiffe-session" {
		t.Fatalf("KMS credentials = %q/%q, want the shared SPIFFE credentials", creds.AccessKeyID, creds.SessionToken)
	}
}
