# Debugging

This page covers useful commands for debugging the plugin using HashiCorp Vault.

## Start a Dev Vault Server

```bash
vault server -dev
```

## Create an AppRole

```bash
vault write auth/approle/role/my-role \
    token_policies="default,web-app" \
    token_ttl=1h \
    token_max_ttl=4h \
    secret_id_ttl=24h \
    secret_id_num_uses=10
```

## Retrieve the Role ID

```bash
vault read auth/approle/role/my-role/role-id
```

For automation:

```bash
vault read -format=json auth/approle/role/my-role/role-id \
  | jq -r .data.role_id
```

## Get the Secret ID

```bash
vault write -f auth/approle/role/my-role/secret-id
```

## Login with AppRole

```bash
vault write auth/approle/login \
    role_id="192e9220-f35c-c2e9-2931-464696e0ff24" \
    secret_id="4e46a226-fdd5-5ed1-f7bb-7b92a0013cad"
```

## Write and Attach Policy

```bash
vault policy write db-policy ./db-policy.hcl
```

```bash
vault write auth/approle/role/my-role \
    token_policies="db-policy"
```

## JWT authentication

JWT login and client-token renewal (including max-TTL re-login) are documented in
[Vault and OpenBao JWT](jwt.md).

Enable JWT auth and a role, then configure the plugin with `VAULT_AUTH_METHOD=jwt`
(or `OPENBAO_AUTH_METHOD=jwt`). Current Vault/OpenBao JWT auth requires the
identity token to include at least one of `iat`, `nbf`, or `exp`.

The issued client token policy should allow renew-self:

```hcl
path "auth/token/renew-self" {
  capabilities = ["update"]
}
```

Renewal and re-auth log lines (with `vault` or `openbao` as the provider name):

```text
Successfully renewed vault token
Renewing vault token failed, attempting re-authentication
Successfully re-authenticated with vault
```

## Set and Get KV Secrets

```bash
vault kv put secret/database/mysql \
    root_password=admin \
    user_password=admin
```

```bash
vault kv get secret/database/mysql
```

## Debug the Plugin

The plugin now writes logs to a host-mounted file by default:

```bash
tail -F /run/swarm-external-secrets/plugin.log
```

On Linux, the default plugin log path is `/run/swarm-external-secrets/plugin.log`.
macOS and Windows filesystems do not support this `/run/**` path by default. On
those hosts, create a log directory with read/write permissions and set
`PLUGIN_LOG_PATH` to that file:

```bash
mkdir -p ./logs
touch ./logs/plugin.log
docker plugin set swarm-external-secrets:latest \
  PLUGIN_LOG_PATH="$PWD/logs/plugin.log"
```

You can override path and level:

```bash
docker plugin set swarm-external-secrets:latest \
  PLUGIN_LOG_PATH="/run/swarm-external-secrets/plugin.log" \
  PLUGIN_LOG_LEVEL="debug"
```

To expose plugin logs through `docker compose logs`, use the bundled override file:

```bash
sudo mkdir -p /run/swarm-external-secrets
sudo touch /run/swarm-external-secrets/plugin.log
docker compose -f docker-compose.yml -f docker-compose.logs.yml up -d
docker compose -f docker-compose.yml -f docker-compose.logs.yml logs -f secrets-logger
```

The sidecar service in `docker-compose.logs.yml` is:

```yaml
services:
  secrets-logger:
    image: alpine:3.20
    command: sh -c "tail -F /run/swarm-external-secrets/plugin.log"
    volumes:
      - /run/swarm-external-secrets:/run/swarm-external-secrets:ro
```

The plugin mount for this path is defined in `config.json`, so make sure the host directory and log file exist:

```bash
sudo mkdir -p /run/swarm-external-secrets
sudo touch /run/swarm-external-secrets/plugin.log
```

For macOS and Windows, use the same read/write host directory configured with
`PLUGIN_LOG_PATH` instead of `/run/swarm-external-secrets`.

Daemon logs remain available for fallback troubleshooting:

```bash
sudo journalctl -u docker.service -f \
  | grep plugin_id
```

or

```bash
sudo journalctl -u docker.service -f | grep "$(docker plugin ls --format '{{.ID}}')"
```
