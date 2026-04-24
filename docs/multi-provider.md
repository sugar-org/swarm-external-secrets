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
| `VAULT_SKIP_VERIFY` | Skip TLS verification (not recommended for production) | `false` |

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
| `OPENBAO_SKIP_VERIFY` | Skip TLS verification (not recommended for production) | `false` |

**Example:**
```bash
docker plugin set swarm-external-secrets:latest \
    SECRETS_PROVIDER="openbao" \
    OPENBAO_ADDR="https://openbao.example.com:8200" \
    OPENBAO_TOKEN="ob_example-token"
```

---

### 5. OCI Vault

**Provider Type:** `oci`

OCI Vault supports two authentication methods: API key (default) and instance principal. With API key auth, you provide credentials directly. With instance principal, the plugin authenticates using the compute instance's identity — no credentials needed, but the instance must have an appropriate IAM policy granting access to the vault.

**Environment Variables:**

| Variable | Description | Default |
|---|---|---|
| `OCI_AUTH_METHOD` | Authentication method (`api_key`, `instance_principal`) | `api_key` |
| `OCI_REGION` | OCI region (required for `api_key`) | — |
| `OCI_TENANCY_OCID` | Tenancy OCID (required for `api_key`) | — |
| `OCI_USER_OCID` | User OCID (required for `api_key`) | — |
| `OCI_FINGERPRINT` | API key fingerprint (required for `api_key`) | — |
| `OCI_PRIVATE_KEY` | Base64-encoded PEM private key (required for `api_key`) | — |
| `OCI_PRIVATE_KEY_PASSPHRASE` | Private key passphrase (only if key is encrypted) | — |
| `OCI_VAULT_OCID` | Vault OCID (required for name-based lookups) | — |


**Private Key Encoding:**

Docker plugin environment variables do not support multiline values, so the PEM private key must be base64-encoded. If your private key is passphrase-protected, also set `OCI_PRIVATE_KEY_PASSPHRASE`.

**Example:**

```bash
OCI_KEY=$(base64 < ~/.oci/oci_api_key.pem | tr -d '\n')

docker plugin set swarm-external-secrets:latest \
    SECRETS_PROVIDER="oci" \
    OCI_AUTH_METHOD="api_key" \
    OCI_REGION="us-ashburn-1" \
    OCI_TENANCY_OCID="ocid1.tenancy.oc1..example" \
    OCI_USER_OCID="ocid1.user.oc1..example" \
    OCI_FINGERPRINT="aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99" \
    OCI_PRIVATE_KEY="${OCI_KEY}" \
    OCI_VAULT_OCID="ocid1.vault.oc1..example"
```

**Secret Labels:**

| Label | Description |
|---|---|
| `oci_secret_ocid` | Fetch a secret directly by its OCID. No vault OCID is needed. |
| `oci_secret_name` | Override the secret name for name-based lookups. |
| `oci_vault_ocid` | Override the vault OCID for this specific secret. Takes priority over the plugin-level `OCI_VAULT_OCID`. |
| `oci_stage` | Secret version stage (`current`, `previous`, `latest`, `pending`, `deprecated`) or a numeric version number (e.g. `3`). Defaults to `current`. |
| `oci_field` | Extract a specific JSON field from the secret value. |

**How secret lookup works:**

The plugin resolves which secret to fetch using the following logic:

1. **By OCID** — If `oci_secret_ocid` is set, the plugin fetches the secret directly by its OCID (e.g. `ocid1.vaultsecret.oc1...`). No vault OCID is needed.

2. **By name** — Otherwise, the plugin performs a name-based lookup. If `oci_secret_name` is set, its value is used as-is. Otherwise the plugin constructs a name from the Docker service and secret names (`<service>-<secret>`, e.g. service `web` with secret `db_pass` becomes `web-db_pass`). Name-based lookups require a vault OCID.

3. **Vault OCID resolution** — For name-based lookups, the `oci_vault_ocid` label takes priority over the plugin-level `OCI_VAULT_OCID` environment variable. This lets you fetch secrets from different vaults without running separate plugin instances. If neither is set, the request fails.

4. **Field extraction** — If `oci_field` is set, the secret value is parsed as JSON and only the named field is returned. For example, if the secret contains `{"username":"admin","password":"s3cret"}`, setting `oci_field: "password"` returns `s3cret`. Non-JSON values are returned as-is.

---

### 6. GCP Secret Manager (Placeholder)

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

### OCI Vault

```yaml
secrets:
  # Look up by name — uses the plugin-level OCI_VAULT_OCID
  db_password:
    driver: swarm-external-secrets:latest
    labels:
      oci_secret_name: "my-database-password"
      oci_field: "password"

  # Look up by name from a different vault using a per-secret override
  analytics_key:
    driver: swarm-external-secrets:latest
    labels:
      oci_secret_name: "analytics-api-key"
      oci_vault_ocid: "ocid1.vault.oc1..other-vault"

  # Look up by OCID — no vault OCID needed
  api_token:
    driver: swarm-external-secrets:latest
    labels:
      oci_secret_ocid: "ocid1.vaultsecret.oc1..example"

  # Fetch the previous version of a secret (useful during rotation)
  db_password_previous:
    driver: swarm-external-secrets:latest
    labels:
      oci_secret_name: "my-database-password"
      oci_stage: "previous"
      oci_field: "password"
```

## Multiple Providers in the Same Swarm Cluster

For production isolation, run one provider per plugin instance (unique plugin name) and reference each instance as a separate secret driver.

### Example: Vault + OpenBao as Two Plugin Instances

```bash
# Vault plugin instance
docker plugin create vault-secret:latest ./plugin_vault
docker plugin set vault-secret:latest \
    SECRETS_PROVIDER="vault" \
    VAULT_ADDR="http://127.0.0.1:8200" \
    VAULT_AUTH_METHOD="token" \
    VAULT_TOKEN="<vault-token>"
docker plugin enable vault-secret:latest

# OpenBao plugin instance
docker plugin create openbao-secret:latest ./plugin_openbao
docker plugin set openbao-secret:latest \
    SECRETS_PROVIDER="openbao" \
    OPENBAO_ADDR="http://127.0.0.1:8201" \
    OPENBAO_AUTH_METHOD="token" \
    OPENBAO_TOKEN="<openbao-token>"
docker plugin enable openbao-secret:latest
```

### One Service Using Both Providers

```yaml
services:
  app:
    image: busybox:latest
    secrets:
      - vault_secret
      - openbao_secret

secrets:
  vault_secret:
    driver: vault-secret:latest
    labels:
      vault_path: "database/mysql"
      vault_field: "password"

  openbao_secret:
    driver: openbao-secret:latest
    labels:
      openbao_path: "database/mysql"
      openbao_field: "password"
```

### Two Services Using Different Providers

```yaml
services:
  app_vault:
    image: busybox:latest
    secrets:
      - vault_secret

  app_openbao:
    image: busybox:latest
    secrets:
      - openbao_secret

secrets:
  vault_secret:
    driver: vault-secret:latest
    labels:
      vault_path: "database/mysql"
      vault_field: "password"

  openbao_secret:
    driver: openbao-secret:latest
    labels:
      openbao_path: "database/mysql"
      openbao_field: "password"
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

### OCI Vault
- Supports API key and instance principal authentication
- `OCI_PRIVATE_KEY` must be base64-encoded (see [Private Key Encoding](#5-oci-vault))
- Secrets can be referenced by name (`oci_secret_name`, requires a vault OCID) or by OCID (`oci_secret_ocid`)
- The `oci_vault_ocid` label overrides the plugin-level `OCI_VAULT_OCID` per secret, allowing a single plugin instance to pull secrets from multiple vaults
- Rotation is supported

### GCP Secret Manager
- Currently a placeholder — will error on initialization
- Future implementation will support service accounts and ADC
- Use other providers for production workloads

## Secret Reuse Control

The `secret_reuse` label controls whether Docker Swarm should cache and reuse a secret value or fetch it fresh from the provider on every request.

**Default behaviour:** secrets are always fetched fresh from the provider.

**With `secret_reuse: "true"`:** Docker Swarm caches the secret value and reuses it without calling the provider again.

### Usage
```yaml
secrets: 
  mysql_password:
    driver: swarm-external-secrets:latest
    labels:
      vault_path: "database/mysql"
      vault_field: "password"
      secret_reuse: "true"   # reuse cached value, do not fetch again
```
