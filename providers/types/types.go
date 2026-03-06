package types

import "time"

// SecretInfo tracks information about secrets being managed
type SecretInfo struct {
	DockerSecretName string
	SecretPath       string
	SecretField      string
	ServiceNames     []string
	LastHash         string // Hash of the secret value for change detection
	LastUpdated      time.Time
	Provider         string // Which provider manages this secret
}
