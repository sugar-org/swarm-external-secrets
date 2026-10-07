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

// BuildMountedKVv1SecretPath builds a KV v1 secret path without injecting
// the "/data/" segment. A literal "data/" folder is preserved because it is
// a valid secret name in KV v1 (e.g. "secret/data/mysql" reads secret
// "data/mysql" under mount "secret"). Only the mount prefix is removed from
// mount-qualified paths.
func BuildMountedKVv1SecretPath(mountPath, customPath, secretName string) string {
	mountPath = strings.Trim(mountPath, "/")
	if customPath != "" {
		return fmt.Sprintf("%s/%s", mountPath, NormalizeV1RelativePath(mountPath, customPath))
	}

	return fmt.Sprintf("%s/%s", mountPath, strings.Trim(secretName, "/"))
}

// NormalizeV1RelativePath normalizes a user-supplied path for a KV v1 mount.
// Unlike NormalizeRelativePath (KV v2), it never strips a "data/" segment,
// so relative paths such as "data/mysql" and mount-qualified paths such as
// "secret/data/mysql" keep their literal "data/" folder. Only the mount
// prefix is removed.
func NormalizeV1RelativePath(mountPath, path string) string {
	mountPath = strings.Trim(mountPath, "/")
	path = strings.Trim(path, "/")
	if rest, ok := strings.CutPrefix(path, mountPath+"/"); ok {
		return strings.Trim(rest, "/")
	}
	return path
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
