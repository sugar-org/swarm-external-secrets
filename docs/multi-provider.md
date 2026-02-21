# Multi-Provider Configuration Guide

The Vault Swarm Plugin supports multiple secrets providers, allowing you to use different backends for secret management while maintaining the same Docker Swarm secrets interface.

## Supported Providers

### 1. HashiCorp Vault (default)

**Provider Type:** `vault`

**Environment Variables:**

| Variable | Description | Default |
|---|---|---|
| `VAULT_ADDR` | Vault server address | `http://localhost:8200` |
| `VAULT_TOKEN` | Vault token for authentication | — |
| `VAULT_MOUNT_PATH` | Mount path for KV engine | `secret` |
| `VAULT_AUTH_METHOD` | Authentication method (`token`, `approle`) | `token` |
| `VAULT_ROLE_ID` | Role ID for AppRole authentication | — |
| `VAULT_SECRET_ID` | Secret ID for AppRole authentication | — |

**Example:**
```bash
docker plugin set swarm-external-secrets:latest \
    SECRETS_PROVIDER="vault" \
    VAULT_ADDR="https://vault.example.com:8200" \
    VAULT_TOKEN="hvs.example-token"
```

---

### 2. AWS Secrets Manager

**Provider Type:** `aws`

**Environment Variables:**

| Variable | Description | Default |
|---|---|---|
| `AWS_REGION` | AWS region | `us-east-1` |
| `AWS_ACCESS_KEY_ID` | AWS access key | — |
| `AWS_SECRET_ACCESS_KEY` | AWS secret key | — |
| `AWS_PROFILE` | AWS profile name | — |

**Example:**
```bash
docker plugin set swarm-external-secrets:latest \
    SECRETS_PROVIDER="aws" \
    AWS_REGION="us-west-2" \
    AWS_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE" \
    AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
```

**Secret Labels:**

- `aws_secret_name` — Custom secret name in AWS
- `aws_field` — Specific JSON field to extract

---

### 3. Azure Key Vault

**Provider Type:** `azure`

**Environment Variables:**

| Variable | Description |
|---|---|
| `AZURE_VAULT_URL` | Key Vault URL (required) |
| `AZURE_TENANT_ID` | Azure tenant ID |
| `AZURE_CLIENT_ID` | Service principal client ID |
| `AZURE_CLIENT_SECRET` | Service principal secret |
| `AZURE_ACCESS_TOKEN` | Direct access token (alternative) |

**Example:**
```bash
docker plugin set swarm-external-secrets:latest \
    SECRETS_PROVIDER="azure" \
    AZURE_VAULT_URL="https://myvault.vault.azure.net/" \
    AZURE_TENANT_ID="12345678-1234-1234-1234-123456789012" \
    AZURE_CLIENT_ID="87654321-4321-4321-4321-210987654321" \
    AZURE_CLIENT_SECRET="client-secret-value"
```

**Secret Labels:**

- `azure_secret_name` — Custom secret name in Azure Key Vault
- `azure_field` — Specific JSON field to extract

---

### 4. OpenBao

**Provider Type:** `openbao`

**Environment Variables:**

| Variable | Description | Default |
|---|---|---|
| `OPENBAO_ADDR` | OpenBao server address | `http://localhost:8200` |
| `OPENBAO_TOKEN` | OpenBao token for authentication | — |
| `OPENBAO_MOUNT_PATH` | Mount path for KV engine | `secret` |
| `OPENBAO_AUTH_METHOD` | Authentication method (`token`, `approle`) | `token` |
| `OPENBAO_ROLE_ID` | Role ID for AppRole authentication | — |
| `OPENBAO_SECRET_ID` | Secret ID for AppRole authentication | — |

**Example:**
```bash
docker plugin set swarm-external-secrets:latest \
    SECRETS_PROVIDER="openbao" \
    OPENBAO_ADDR="https://openbao.example.com:8200" \
    OPENBAO_TOKEN="ob_example-token"
```

---

### 5. GCP Secret Manager (Placeholder)

**Provider Type:** `gcp`

!!! warning
    Currently a placeholder implementation. Use other providers for production.

**Environment Variables:**

- `GCP_PROJECT_ID` — Google Cloud project ID (required)
- `GOOGLE_APPLICATION_CREDENTIALS` — Path to service account key
- `GCP_CREDENTIALS_JSON` — Service account key JSON

---

## Docker Compose Examples

### Vault Provider

```yaml
version: '3.8'
services:
  app:
    image: nginx
    secrets:
      - mysql_password
    deploy:
      replicas: 2

secrets:
  mysql_password:
    driver: swarm-external-secrets:latest
    labels:
      vault_path: "database/mysql"
      vault_field: "password"
```

### AWS Secrets Manager

```yaml
secrets:
  api_key:
    driver: swarm-external-secrets:latest
    labels:
      aws_secret_name: "prod/api/key"
      aws_field: "api_key"
```

### Azure Key Vault

```yaml
secrets:
  database_connection:
    driver: swarm-external-secrets:latest
    labels:
      azure_secret_name: "database-connection-string"
      azure_field: "connection_string"
```

## Provider-Specific Notes

### AWS Secrets Manager
- Supports IAM roles, access keys, and profiles
- JSON secrets are parsed automatically
- Rotation is supported with native AWS rotation

### Azure Key Vault
- Uses REST API with OAuth2 authentication
- Supports service principals and managed identities
- Secret names must follow Azure naming conventions

### OpenBao
- Fully compatible with Vault API
- Use for Vault migration or open-source requirements
- Supports all Vault authentication methods

### GCP Secret Manager
- Currently a placeholder — will error on initialization
- Future implementation will support service accounts and ADC
- Use other providers for production workloads
