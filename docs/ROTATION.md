---
name : Vault Secret Rotation Feature
---
## Vault Secret Rotation Feature

This document describes the automatic secret rotation feature added to the vault-swarm-plugin.

## Overview

The plugin now automatically monitors secrets in Vault and updates the corresponding Docker Swarm secrets and services when changes are detected. This ensures that applications always use the latest secret values without manual intervention.

## How It Works

1. **Secret Tracking**: When a Docker service requests a secret, the plugin tracks the mapping between the Docker secret and its corresponding Vault path.

2. **Background Monitoring**: A background goroutine periodically checks Vault for changes to tracked secrets by comparing SHA256 hashes of secret values.

3. **Automatic Rotation**: When a change is detected:
   - A new version of the Docker secret is created with the updated value
   - Services using the secret are automatically updated to trigger redeployment
   - The old secret version is removed

## Configuration

The following environment variables control the rotation behavior:

- `VAULT_ENABLE_ROTATION`: Enable/disable automatic rotation (default: `true`)
- `VAULT_ROTATION_INTERVAL`: How often to check for changes (default: `5m`)

### Example Configuration

```bash
docker plugin install vault-secrets-plugin:latest

```

```bash
# Enable rotation with 2-minute check interval
docker plugin set vault-secrets-plugin:latest \
    VAULT_ENABLE_ROTATION="true" \
    VAULT_ROTATION_INTERVAL="2m"

# Disable rotation
docker plugin set vault-secrets-plugin:latest \
    VAULT_ENABLE_ROTATION="false"
```

## Usage Example

1. **Deploy a service with Vault secrets**:
   ```yaml
   secrets:
     mysql_password:
       driver: vault-secrets-plugin:latest
       labels:
         vault_path: "database/mysql"
         vault_field: "password"
   ```

2. **Update the secret in Vault**:
   ```bash
   vault kv put secret/database/mysql password=new_secure_password
   ```

3. **Automatic rotation**: Within the next rotation interval (default 5 minutes), the plugin will:
   - Detect the change in Vault
   - Update the Docker secret with the new value
   - Force update services using the secret

## Monitoring

Check plugin logs to monitor rotation activity:

```bash
# View plugin logs
sudo journalctl -u docker.service -f | grep vault

# Check for rotation events
docker service logs <service-name>
```

## Benefits

- **Zero downtime**: Services are updated gracefully
- **Automatic synchronization**: No manual intervention required
- **Security**: Old secrets are automatically cleaned up
- **Auditability**: All rotation events are logged

## Limitations

- Services must support graceful secret updates (restart when secrets change)
- Rotation frequency is limited by the configured interval
- Docker Swarm must be running in manager mode for secret management

## Troubleshooting

If rotation is not working:

1. Check if rotation is enabled: `VAULT_ENABLE_ROTATION=true`
2. Verify plugin has access to Docker socket
3. Ensure plugin is running on a manager node
4. Check plugin logs for error messages
5. Verify Vault connectivity and permissions

## Security Considerations

- The plugin requires Docker socket access to manage secrets and services
- Ensure proper Vault authentication and minimal required permissions
- Monitor logs for unauthorized rotation attempts
- Consider using shorter rotation intervals for highly sensitive secrets