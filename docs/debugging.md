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

## Configure Logging

By default, the plugin logs at **info** level. You can increase verbosity using either:

- `--debug` (sets log level to `debug`)
- `LOG_LEVEL` (optional integer `0-6`; `6` enables `trace`)

Example:

```bash
docker plugin set swarm-external-secrets:latest LOG_LEVEL="6"
```

```bash
sudo journalctl -u docker.service -f \
  | grep plugin_id
```

or

```bash
sudo journalctl -u docker.service -f | grep "$(docker plugin ls --format '{{.ID}}')"
```
