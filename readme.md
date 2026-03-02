### Swarm External Secrets
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/sugar-org/swarm-external-secrets/badge)](https://scorecard.dev/viewer/?uri=github.com/sugar-org/swarm-external-secrets) ![Discord](https://img.shields.io/discord/1476983394977054740?logo=discord&color=blue) [![Join our Discord](https://img.shields.io/badge/Discord-Join%20Server-5865F2?logo=discord&logoColor=white)](https://discord.gg/4NYdBu7bZy)

---


A Docker Swarm secrets plugin that integrates with multiple secret management providers including HashiCorp Vault, AWS Secrets Manager, Azure Key Vault, and OpenBao.

### 🚀 Updates

#### 🎓 Google Summer of Code 2026
swarm-external-secrets is participating in Google Summer of Code 2026 incubated under the  organization [OpenScienceLabs](http://opensciencelabs.org/)!

For more information, check out [GSoC Contribution Guidelines](./CONTRIBUTING.md#google-summer-of-code-2026)

---

### Architecture 

![Architecture](https://raw.githubusercontent.com/sugar-org/swarm-external-secrets/refs/heads/main/docs/architecture.png)


## Documentation

Please refer to the [docs](https://sugar-org.github.io/swarm-external-secrets/) for more information.

## Supported Providers

## Features

- **Multi-Provider Support**: HashiCorp Vault, AWS Secrets Manager, Azure Key Vault, OpenBao
- **Multiple Auth Methods**: Support for various authentication methods per provider
- **Automatic Secret Rotation**: Monitor providers for changes and automatically update Docker secrets and services
- **Real-time Monitoring**: Web dashboard with system metrics, health status, and performance tracking
- **Flexible Path Mapping**: Customize secret paths and field extraction per provider
- **Production Ready**: Includes proper error handling, logging, cleanup, and monitoring
- **Backward Compatible**: Existing Vault configurations continue to work unchanged

## New: Multi-Provider Support

The plugin now supports multiple secret providers. Configure with `SECRETS_PROVIDER` environment variable:

```bash
# HashiCorp Vault (default)
docker plugin set swarm-external-secrets:latest SECRETS_PROVIDER="vault"

# AWS Secrets Manager  
docker plugin set swarm-external-secrets:latest SECRETS_PROVIDER="aws"

# Azure Key Vault
docker plugin set swarm-external-secrets:latest SECRETS_PROVIDER="azure"

# OpenBao
docker plugin set swarm-external-secrets:latest SECRETS_PROVIDER="openbao"
```

## New: Real-time Monitoring

Access the monitoring dashboard at `http://localhost:8080` (configurable port):

- **System Metrics**: Memory usage, goroutine count, GC statistics
- **Secret Rotation**: Success/failure rates, error tracking
- **Health Status**: Overall system health and provider connectivity
- **Performance Tracking**: Response times, ticker health, uptime

### Monitor Configuration
```bash
docker plugin set swarm-external-secrets:latest \
    ENABLE_MONITORING="true" \
    MONITORING_PORT="8080"
```

## Installation

1. Build and enable the plugin:
   ```bash
   ./scripts/build.sh
   ```

2. Configure the plugin:
   ```bash
   docker plugin set swarm-external-secrets:latest \
       VAULT_ADDR="https://your-vault-server:8200" \
       VAULT_AUTH_METHOD="token" \
       VAULT_TOKEN="your-vault-token" \
       VAULT_ENABLE_ROTATION="true"
   ```

3. Use in docker-compose.yml:

   **HashiCorp Vault:**
   ```yaml
   secrets:
     mysql_password:
       driver: swarm-external-secrets:latest
       labels:
         vault_path: "database/mysql"
         vault_field: "password"
   ```

   **AWS Secrets Manager:**
   ```yaml
   secrets:
     api_key:
       driver: swarm-external-secrets:latest
       labels:
         aws_secret_name: "prod/api/key"
         aws_field: "api_key"
   ```

   **Azure Key Vault:**
   ```yaml
   secrets:
     database_connection:
       driver: swarm-external-secrets:latest
       labels:
         azure_secret_name: "database-connection-string"
   ```

   **OpenBao:**
   ```yaml
   secrets:
     app_secret:
       driver: swarm-external-secrets:latest
       labels:
         openbao_path: "app/config"
         openbao_field: "secret_key"
   ```

| Provider | Status | Authentication | Rotation |
|----------|--------|---------------|----------|
| HashiCorp Vault | ✅ Stable | Token, AppRole | ✅ |
| AWS Secrets Manager | ✅ Stable | IAM, Access Keys | ✅ |
| Azure Key Vault | ✅ Stable | Service Principal, Access Token | ✅ |
| OpenBao | ✅ Stable | Token, AppRole | ✅ |
| GCP Secret Manager | 🚧 Placeholder | - | - |

## Quick Start Examples

### HashiCorp Vault
```bash
docker plugin set swarm-external-secrets:latest \
    SECRETS_PROVIDER="vault" \
    VAULT_ADDR="https://vault.example.com:8200" \
    VAULT_TOKEN="hvs.example-token"
```

### AWS Secrets Manager
```bash
docker plugin set swarm-external-secrets:latest \
    SECRETS_PROVIDER="aws" \
    AWS_REGION="us-west-2" \
    AWS_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE"
```

### Azure Key Vault
```bash
docker plugin set swarm-external-secrets:latest \
    SECRETS_PROVIDER="azure" \
    AZURE_VAULT_URL="https://myvault.vault.azure.net/" \
    AZURE_TENANT_ID="12345678-1234-1234-1234-123456789012"
```

### License

[BSD-3-Clause license](https://github.com/sugar-org/swarm-external-secrets/blob/main/LICENSE)
