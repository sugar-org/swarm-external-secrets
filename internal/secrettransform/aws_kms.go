package secrettransform

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"maps"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/kms"

	"github.com/sugar-org/swarm-external-secrets/providers"
)

// AWSKMSTransformer decrypts provider values when a secret opts in with labels.
type AWSKMSTransformer struct {
	settings    map[string]string
	credentials aws.CredentialsProvider
	mu          sync.Mutex
	client      kmsDecryptAPI
}

type kmsDecryptAPI interface {
	Decrypt(ctx context.Context, params *kms.DecryptInput, optFns ...func(*kms.Options)) (*kms.DecryptOutput, error)
}

// NewAWSKMSTransformer creates a lazy AWS KMS transformer. When credentials is
// non-nil, KMS calls use it instead of the settings-based credential chain.
func NewAWSKMSTransformer(settings map[string]string, credentials aws.CredentialsProvider) *AWSKMSTransformer {
	copied := make(map[string]string, len(settings))
	maps.Copy(copied, settings)

	return &AWSKMSTransformer{
		settings:    copied,
		credentials: credentials,
	}
}

func (t *AWSKMSTransformer) Transform(ctx context.Context, secretInfo *providers.SecretInfo, value []byte) ([]byte, error) {
	labels := secretInfo.Labels
	if !kmsDecryptEnabled(labels) {
		return value, nil
	}

	ciphertext, err := decodeCiphertext(value, labels)
	if err != nil {
		return nil, err
	}

	encryptionContext, err := parseEncryptionContext(labels)
	if err != nil {
		return nil, err
	}

	client, err := t.decryptClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("initialize aws kms client: %w", err)
	}

	output, err := client.Decrypt(ctx, &kms.DecryptInput{
		CiphertextBlob:    ciphertext,
		EncryptionContext: encryptionContext,
	})
	if err != nil {
		return nil, fmt.Errorf("decrypt kms ciphertext: %w", err)
	}

	return output.Plaintext, nil
}

func (t *AWSKMSTransformer) decryptClient(ctx context.Context) (kmsDecryptAPI, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.client != nil {
		return t.client, nil
	}

	cfg, err := t.loadAWSConfig(ctx)
	if err != nil {
		return nil, err
	}

	endpoint := setting(t.settings, "AWS_KMS_ENDPOINT")
	if endpoint == "" {
		endpoint = setting(t.settings, "AWS_ENDPOINT_URL")
	}

	t.client = kms.NewFromConfig(cfg, func(o *kms.Options) {
		if endpoint != "" {
			o.BaseEndpoint = aws.String(endpoint)
		}
	})

	return t.client, nil
}

func (t *AWSKMSTransformer) loadAWSConfig(ctx context.Context) (aws.Config, error) {
	var opts []func(*config.LoadOptions) error

	if region := setting(t.settings, "AWS_REGION"); region != "" {
		opts = append(opts, config.WithRegion(region))
	}
	if profile := setting(t.settings, "AWS_PROFILE"); profile != "" {
		opts = append(opts, config.WithSharedConfigProfile(profile))
	}

	cfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return aws.Config{}, err
	}

	if t.credentials != nil {
		cfg.Credentials = t.credentials
		return cfg, nil
	}

	accessKey := setting(t.settings, "AWS_ACCESS_KEY_ID")
	secretKey := setting(t.settings, "AWS_SECRET_ACCESS_KEY")
	if accessKey != "" && secretKey != "" {
		cfg.Credentials = credentials.NewStaticCredentialsProvider(accessKey, secretKey, "")
	}

	return cfg, nil
}

func kmsDecryptEnabled(labels map[string]string) bool {
	if labels == nil {
		return false
	}

	return strings.EqualFold(strings.TrimSpace(labels["kms_decrypt"]), "true")
}

func decodeCiphertext(value []byte, labels map[string]string) ([]byte, error) {
	encoding := strings.ToLower(strings.TrimSpace(labels["kms_ciphertext_encoding"]))
	if encoding == "" {
		encoding = "base64"
	}

	switch encoding {
	case "base64":
		ciphertext, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(value)))
		if err != nil {
			return nil, fmt.Errorf("decode kms ciphertext: %w", err)
		}
		return ciphertext, nil
	default:
		return nil, fmt.Errorf("unsupported kms ciphertext encoding %q", encoding)
	}
}

func parseEncryptionContext(labels map[string]string) (map[string]string, error) {
	raw := strings.TrimSpace(labels["kms_encryption_context"])
	if raw == "" {
		return nil, nil
	}

	var context map[string]string
	if err := json.Unmarshal([]byte(raw), &context); err != nil {
		return nil, fmt.Errorf("parse kms encryption context: %w", err)
	}

	return context, nil
}

func setting(settings map[string]string, key string) string {
	if settings == nil {
		return ""
	}
	return settings[key]
}
