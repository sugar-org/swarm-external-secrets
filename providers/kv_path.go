package providers

import "fmt"

func buildMountedKVv2SecretPath(mountPath, customPath, serviceName, secretName string) string {
	if customPath != "" {
		return fmt.Sprintf("%s/data/%s", mountPath, customPath)
	}

	if serviceName != "" {
		return fmt.Sprintf("%s/data/%s/%s", mountPath, serviceName, secretName)
	}

	return fmt.Sprintf("%s/data/%s", mountPath, secretName)
}
