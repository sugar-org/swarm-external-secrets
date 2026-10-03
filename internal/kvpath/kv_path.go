package kvpath

import (
	"fmt"
	"strings"
)

func BuildMountedKVv2SecretPath(mountPath, customPath, secretName string) string {
	mountPath = strings.Trim(mountPath, "/")
	if customPath != "" {
		return fmt.Sprintf("%s/data/%s", mountPath, NormalizeRelativePath(mountPath, customPath))
	}

	return fmt.Sprintf("%s/data/%s", mountPath, strings.Trim(secretName, "/"))
}

// BuildMountedKVv1SecretPath builds a KV v1 secret path without the "/data/"
// segment. Normalization of user-supplied paths matches the v2 helper so
// existing openbao_path values keep resolving to the same relative secret.
func BuildMountedKVv1SecretPath(mountPath, customPath, secretName string) string {
	mountPath = strings.Trim(mountPath, "/")
	if customPath != "" {
		return fmt.Sprintf("%s/%s", mountPath, NormalizeRelativePath(mountPath, customPath))
	}

	return fmt.Sprintf("%s/%s", mountPath, strings.Trim(secretName, "/"))
}

func NormalizeRelativePath(mountPath, path string) string {
	mountPath = strings.Trim(mountPath, "/")
	path = strings.Trim(path, "/")
	path = strings.TrimPrefix(path, mountPath+"/")
	path = strings.TrimPrefix(path, "data/")
	return strings.Trim(path, "/")
}

func TrimMountedKVSecretPath(secretPath, mountPath string) string {
	return strings.TrimPrefix(secretPath, strings.Trim(mountPath, "/")+"/data/")
}
