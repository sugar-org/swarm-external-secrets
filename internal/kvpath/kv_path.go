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
// segment. A mount-qualified path (e.g. "secret/data/database/mysql") is
// reduced to the secret relative to the mount with one leading "data/"
// segment removed ("database/mysql"); a relative path (e.g. "data/mysql")
// is kept as-is so a genuine "data/" folder is preserved.
func BuildMountedKVv1SecretPath(mountPath, customPath, secretName string) string {
	mountPath = strings.Trim(mountPath, "/")
	if customPath != "" {
		return fmt.Sprintf("%s/%s", mountPath, NormalizeV1RelativePath(mountPath, customPath))
	}

	return fmt.Sprintf("%s/%s", mountPath, strings.Trim(secretName, "/"))
}

// NormalizeV1RelativePath normalizes a user-supplied path for a KV v1 mount.
// Unlike NormalizeRelativePath (KV v2), it strips a leading "data/" segment
// only after removing a mount prefix, so relative paths such as "data/mysql"
// keep their "data/" folder.
func NormalizeV1RelativePath(mountPath, path string) string {
	mountPath = strings.Trim(mountPath, "/")
	path = strings.Trim(path, "/")
	if rest, ok := strings.CutPrefix(path, mountPath+"/"); ok {
		rest = strings.TrimPrefix(rest, "data/")
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
