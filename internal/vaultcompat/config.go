package vaultcompat

import (
	"fmt"
	"os"
	"strings"

	"github.com/sugar-org/swarm-external-secrets/internal/utils"
	"github.com/sugar-org/swarm-external-secrets/internal/vaultcompat/jwtsource"
)

type Config struct {
	ProviderName string
	EnvPrefix    string

	Address    string
	MountPath  string
	AuthMethod string

	Token    string
	RoleID   string
	SecretID string

	AppRoleAuthPath string

	JWTRole     string
	JWT         string
	JWTFile     string
	JWTAuthPath string

	CACert     string
	ClientCert string
	ClientKey  string
	SkipVerify bool

	PathLabel  string
	FieldLabel string

	// KVVersion selects the KV engine version: "1" or "2".
	// Empty means "2" for backward compatibility.
	KVVersion string
}

func ParseVaultConfig(config map[string]string) Config {
	cfg := parseConfig(Config{
		ProviderName: "vault",
		EnvPrefix:    "VAULT",
		PathLabel:    "vault_path",
		FieldLabel:   "vault_field",
	}, config, "")
	cfg.KVVersion = utils.GetConfigOrDefault(config, "VAULT_KV_VERSION", "2")
	return cfg
}

func ParseOpenBaoConfig(config map[string]string) Config {
	cfg := parseConfig(Config{
		ProviderName: "openbao",
		EnvPrefix:    "OPENBAO",
		PathLabel:    "openbao_path",
		FieldLabel:   "openbao_field",
	}, config, "http://localhost:8200")
	cfg.KVVersion = utils.GetConfigOrDefault(config, "OPENBAO_KV_VERSION", "2")
	return cfg
}

// normalizeKVVersion validates a KV engine version setting. Only "1" or "2"
// are accepted (surrounding whitespace ignored); empty means "2" for
// backward compatibility. Anything else is rejected with a clear error naming
// the environment variable.
func normalizeKVVersion(envName, raw string) (string, error) {
	v := strings.TrimSpace(raw)
	if v == "" {
		return "2", nil
	}
	switch v {
	case "1", "2":
		return v, nil
	default:
		return "", fmt.Errorf("unsupported %s %q: must be \"1\" or \"2\"", envName, raw)
	}
}

// NormalizeOpenBaoKVVersion validates the OPENBAO_KV_VERSION setting. Only
// "1" or "2" are accepted (surrounding whitespace ignored); empty means "2"
// for backward compatibility. Anything else is rejected with a clear error.
func NormalizeOpenBaoKVVersion(raw string) (string, error) {
	return normalizeKVVersion("OPENBAO_KV_VERSION", raw)
}

// NormalizeVaultKVVersion validates the VAULT_KV_VERSION setting. Only "1" or
// "2" are accepted (surrounding whitespace ignored); empty means "2" for
// backward compatibility. Anything else is rejected with a clear error.
func NormalizeVaultKVVersion(raw string) (string, error) {
	return normalizeKVVersion("VAULT_KV_VERSION", raw)
}

func parseConfig(base Config, config map[string]string, addressDefault string) Config {
	prefix := base.EnvPrefix

	base.Address = utils.GetConfigOrDefault(config, prefix+"_ADDR", addressDefault)
	base.Token = utils.GetConfigOrDefault(config, prefix+"_TOKEN", "")
	base.MountPath = utils.GetConfigOrDefault(config, prefix+"_MOUNT_PATH", "secret")
	base.AuthMethod = utils.GetConfigOrDefault(config, prefix+"_AUTH_METHOD", "token")
	base.RoleID = config[prefix+"_ROLE_ID"]
	base.SecretID = config[prefix+"_SECRET_ID"]
	base.AppRoleAuthPath = getConfigOrDefault(config, prefix+"_APPROLE_AUTH_PATH", "approle")
	base.JWTRole = config[prefix+"_JWT_ROLE"]
	base.JWT = utils.GetConfigOrDefault(config, prefix+"_JWT", "")
	base.JWTFile = utils.GetConfigOrDefault(config, prefix+"_JWT_FILE", "")
	base.JWTAuthPath = utils.GetConfigOrDefault(config, prefix+"_JWT_AUTH_PATH", "jwt")
	base.CACert = config[prefix+"_CACERT"]
	base.ClientCert = config[prefix+"_CLIENT_CERT"]
	base.ClientKey = config[prefix+"_CLIENT_KEY"]
	base.SkipVerify = utils.GetConfigOrDefault(config, prefix+"_SKIP_VERIFY", "false") == "true"

	return base
}

func (c Config) validateAuth() error {
	switch c.AuthMethod {
	case "token", "":
		if c.Token == "" {
			return fmt.Errorf("%s_TOKEN is required for token authentication", c.EnvPrefix)
		}
	case "approle":
		if c.RoleID == "" || c.SecretID == "" {
			return fmt.Errorf("%s_ROLE_ID and %s_SECRET_ID are required for approle authentication", c.EnvPrefix, c.EnvPrefix)
		}
	case "jwt":
		if c.JWTRole == "" {
			return fmt.Errorf("%s_JWT_ROLE is required for jwt authentication", c.EnvPrefix)
		}
		if _, err := c.buildJWTSource(); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported authentication method: %s", c.AuthMethod)
	}

	return nil
}

func (c Config) buildJWTSource() (jwtsource.Source, error) {
	if c.JWTFile != "" {
		if err := validateJWTFile(c.JWTFile, c.EnvPrefix+"_JWT_FILE"); err != nil {
			return nil, err
		}
	}
	if c.JWT == "" && c.JWTFile == "" {
		return nil, fmt.Errorf("%s_JWT or %s_JWT_FILE is required for jwt authentication", c.EnvPrefix, c.EnvPrefix)
	}

	var sources []jwtsource.Source
	if c.JWTFile != "" {
		sources = append(sources, jwtsource.File{Path: c.JWTFile})
	} else if c.JWT != "" {
		sources = append(sources, jwtsource.Static{Value: c.JWT})
	}

	switch len(sources) {
	case 0:
		return nil, fmt.Errorf("%s_JWT or %s_JWT_FILE is required for jwt authentication", c.EnvPrefix, c.EnvPrefix)
	case 1:
		return sources[0], nil
	default:
		return jwtsource.Chain{Sources: sources}, nil
	}
}

func (c Config) loginConfig() (loginCfg loginConfig, err error) {
	if err := c.validateAuth(); err != nil {
		return loginCfg, err
	}

	loginCfg = loginConfig{
		Method:          c.AuthMethod,
		Token:           c.Token,
		RoleID:          c.RoleID,
		SecretID:        c.SecretID,
		AppRoleAuthPath: c.AppRoleAuthPath,
		JWTRole:         c.JWTRole,
		JWTAuthPath:     c.JWTAuthPath,
	}

	if c.AuthMethod == "jwt" {
		loginCfg.JWTSource, err = c.buildJWTSource()
		if err != nil {
			return loginCfg, err
		}
	}

	return loginCfg, nil
}

type loginConfig struct {
	Method          string
	Token           string
	RoleID          string
	SecretID        string
	AppRoleAuthPath string
	JWTRole         string
	JWTAuthPath     string
	JWTSource       jwtsource.Source
}

func validateJWTFile(path, envName string) error {
	data, err := os.ReadFile(path) // #nosec G304 -- file path is explicit plugin configuration.
	if err != nil {
		return fmt.Errorf("failed to read %s: %v", envName, err)
	}

	if strings.TrimSpace(string(data)) == "" {
		return fmt.Errorf("%s is empty", envName)
	}

	return nil
}

func getConfigOrDefault(config map[string]string, key, defaultValue string) string {
	if value, exists := config[key]; exists && value != "" {
		return value
	}
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
