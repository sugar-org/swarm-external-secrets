---
name: Getting Started
---
### Vault Swarm Plugin

A Docker Swarm secrets plugin that integrates with multiple secret management providers including HashiCorp Vault, AWS Secrets Manager, Azure Key Vault, and OpenBao.

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
docker plugin set vault-secrets-plugin:latest SECRETS_PROVIDER="vault"

# AWS Secrets Manager  
docker plugin set vault-secrets-plugin:latest SECRETS_PROVIDER="aws"

# Azure Key Vault
docker plugin set vault-secrets-plugin:latest SECRETS_PROVIDER="azure"

# OpenBao
docker plugin set vault-secrets-plugin:latest SECRETS_PROVIDER="openbao"
```

## New: Real-time Monitoring

Access the monitoring dashboard at `http://localhost:8080` (configurable port):

- **System Metrics**: Memory usage, goroutine count, GC statistics
- **Secret Rotation**: Success/failure rates, error tracking
- **Health Status**: Overall system health and provider connectivity
- **Performance Tracking**: Response times, ticker health, uptime

### Monitor Configuration
```bash
docker plugin set vault-secrets-plugin:latest \
    ENABLE_MONITORING="true" \
    MONITORING_PORT="8080"
```

## Installation

1. Build and enable the plugin:
   ```bash
   ./build.sh
   ```

2. Configure the plugin:
   ```bash
   docker plugin set vault-secrets-plugin:latest \
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
       driver: vault-secrets-plugin:latest
       labels:
         vault_path: "database/mysql"
         vault_field: "password"
   ```

   **AWS Secrets Manager:**
   ```yaml
   secrets:
     api_key:
       driver: vault-secrets-plugin:latest
       labels:
         aws_secret_name: "prod/api/key"
         aws_field: "api_key"
   ```

   **Azure Key Vault:**
   ```yaml
   secrets:
     database_connection:
       driver: vault-secrets-plugin:latest
       labels:
         azure_secret_name: "database-connection-string"
   ```

   **OpenBao:**
   ```yaml
   secrets:
     app_secret:
       driver: vault-secrets-plugin:latest
       labels:
         openbao_path: "app/config"
         openbao_field: "secret_key"
   ```
start the server
```bash
vault server -dev
```

create a vault role
```bash
vault write auth/approle/role/my-role \
    token_policies="default,web-app" \
    token_ttl=1h \
    token_max_ttl=4h \
    secret_id_ttl=24h \
    secret_id_num_uses=10

```

retrieve the role id 
```
vault read auth/approle/role/my-role/role-id
```
(or) 

for automation
```bash
vault read -format=json auth/approle/role/my-role/role-id \
  | jq -r .data.role_id

```
get the secret id
```bash
vault write -f auth/approle/role/my-role/secret-id

```
login with approle 
```bash
vault write auth/approle/login \
    role_id="192e9220-f35c-c2e9-2931-464696e0ff24" \
    secret_id="4e46a226-fdd5-5ed1-f7bb-7b92a0013cad"
```

write and attach policy for the approle 

```bash
vault policy write db-policy ./db-policy.hcl
```
```bash
vault write auth/approle/role/my-role \
    token_policies="db-policy" 
```

set and get the kv secrets 
```bash
vault kv put secret/database/mysql \
    root_password=admin \
    user_password=admin
```

```bash
vault kv get secret/database/mysql 
```

---
debug the plugin 

```bash
sudo journalctl -u docker.service -f \
  | grep plugin_id
```

## Documentation

- **[Multi-Provider Guide](docs/MULTI_PROVIDER.md)**: Complete configuration guide for all supported providers
- **[Monitoring Guide](docs/MONITORING.md)**: System monitoring, metrics, and performance tracking
- **[Original Vault Guide](docs/)**: HashiCorp Vault specific documentation

## Supported Providers

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
docker plugin set vault-secrets-plugin:latest \
    SECRETS_PROVIDER="vault" \
    VAULT_ADDR="https://vault.example.com:8200" \
    VAULT_TOKEN="hvs.example-token"
```

### AWS Secrets Manager
```bash
docker plugin set vault-secrets-plugin:latest \
    SECRETS_PROVIDER="aws" \
    AWS_REGION="us-west-2" \
    AWS_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE"
```

### Azure Key Vault
```bash
docker plugin set vault-secrets-plugin:latest \
    SECRETS_PROVIDER="azure" \
    AZURE_VAULT_URL="https://myvault.vault.azure.net/" \
    AZURE_TENANT_ID="12345678-1234-1234-1234-123456789012"
```