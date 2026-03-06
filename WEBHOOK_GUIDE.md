# Webhook-based Secret Sync for Vault Provider

## Overview

The plugin now supports webhook-based secret synchronization for the HashiCorp Vault provider as an alternative to polling (ticker-based) synchronization.

## Features

- **Push-based updates**: Vault pushes change events directly to the plugin (when webhook support is available)
- **Reduced latency**: Immediate secret updates instead of waiting for the next polling interval
- **Lower API traffic**: No unnecessary polling when secrets haven't changed
- **Backward compatible**: Defaults to ticker mode, existing deployments unaffected

## Configuration

### Environment Variables
```bash
USE_WEBHOOK=false       # Enable webhook mode (default: false)
WEBHOOK_PORT=9095       # Webhook listener port (default: 9095)
WEBHOOK_SECRET=         # Optional HMAC-SHA256 secret for webhook validation
```

### Enable Webhook Mode
```bash
docker plugin set vault-secrets-plugin:latest \
    SECRETS_PROVIDER="vault" \
    USE_WEBHOOK="true" \
    WEBHOOK_PORT="9095" \
    WEBHOOK_SECRET="your-secret-here"
```

### Disable Webhook Mode (Use Ticker)
```bash
docker plugin set vault-secrets-plugin:latest \
    USE_WEBHOOK="false"
```

## How It Works

### Webhook Mode (USE_WEBHOOK=true)
1. Plugin starts an HTTP server on the configured port
2. Vault sends webhook events when secrets change
3. Plugin receives the event and triggers immediate reconciliation
4. Secret is rotated in Docker Swarm without waiting for ticker interval

### Ticker Mode (USE_WEBHOOK=false - default)
1. Plugin polls Vault at regular intervals (e.g., every 30s)
2. Checks for secret changes by comparing hashes
3. Rotates secrets when changes are detected

## Webhook Payload Format

The plugin expects HCP Vault Secrets webhook format:
```json
{
  "resource_id": "secret-id",
  "resource_name": "secrets/project/proj/app/app-name",
  "event_id": "secrets.event:123",
  "event_action": "update",
  "event_description": "Update an existing KV secret",
  "event_source": "hashicorp.secrets.secret",
  "event_version": "1",
  "event_payload": {
    "app_name": "my-app",
    "name": "database-password",
    "type": "static",
    "version": 2
  }
}
```

## Supported Events

- `create` - New secret created
- `update` - Existing secret updated
- `rotate` - Secret rotated
- `delete` - Secret deleted

## Security

### Webhook Signature Validation

When `WEBHOOK_SECRET` is set, the plugin validates incoming webhooks using HMAC-SHA256:
```bash
# Set a secret for webhook validation
docker plugin set vault-secrets-plugin:latest \
    WEBHOOK_SECRET="my-secure-webhook-secret"
```

The plugin expects the signature in the `X-HCP-Webhook-Signature` header.

### Network Requirements

- The webhook endpoint must be reachable from Vault's network
- For production, use HTTPS with a reverse proxy (nginx, Caddy, etc.)
- Air-gapped environments should keep `USE_WEBHOOK=false`

## Provider Compatibility

| Provider              | Webhook Support | Ticker Support |
|-----------------------|-----------------|----------------|
| Vault                 |       Yes       |      Yes       |
| AWS Secrets Manager   |       No        |      Yes       |
| Azure Key Vault       |       No        |      Yes       |
| GCP Secret Manager    |       No        |      Yes       |
| OpenBao               |       No        |      Yes       |

**Note**: When `USE_WEBHOOK=true` for non-Vault providers, it has no effect and ticker mode is used.

## Testing

### Simulated Webhook Test
```bash
# Send a test webhook
curl -X POST http://localhost:9095/webhook \
  -H "Content-Type: application/json" \
  -d '{
    "event_action": "update",
    "event_payload": {
      "name": "my-secret",
      "app_name": "my-app"
    }
  }'
```

### Health Check
```bash
curl http://localhost:9095/health
```

## Troubleshooting

### Webhook server not starting

Check plugin logs:
```bash
sudo journalctl -u docker.service -f | grep vault
```

Look for:
- `Starting Vault provider with WEBHOOK mode`
- `Webhook server starting on port 9095`

### Port already in use

Change the webhook port:
```bash
docker plugin set vault-secrets-plugin:latest WEBHOOK_PORT="9096"
```

### Webhooks not being received

1. Verify the webhook endpoint is accessible from Vault
2. Check firewall rules
3. Ensure port forwarding is configured correctly
4. Verify webhook URL in Vault configuration

## Migration Guide

### From Ticker to Webhook
```bash
# 1. Disable the plugin
docker plugin disable vault-secrets-plugin:latest

# 2. Enable webhook mode
docker plugin set vault-secrets-plugin:latest USE_WEBHOOK="true"

# 3. Re-enable the plugin
docker plugin enable vault-secrets-plugin:latest
```

### From Webhook to Ticker
```bash
# 1. Disable the plugin
docker plugin disable vault-secrets-plugin:latest

# 2. Disable webhook mode
docker plugin set vault-secrets-plugin:latest USE_WEBHOOK="false"

# 3. Re-enable the plugin
docker plugin enable vault-secrets-plugin:latest
```

## Limitations

1. **HCP Vault Secrets Deprecation**: HCP Vault Secrets (which has native webhook support) is being deprecated on August 27, 2025
2. **Self-hosted Vault**: Self-hosted Vault doesn't have native webhook support yet
3. **Future Compatibility**: This feature is implemented for future Vault webhook support or custom webhook integrations

## Examples

See `webhook-test/` directory for:
- Standalone webhook listener example
- Test scripts for webhook payloads
- Integration test examples
