# Vault and OpenBao JWT authentication

The plugin can log in to HashiCorp Vault and OpenBao with a signed JWT, then
keep the **issued client token** alive. That client-token renewal is not the
same as [secret rotation](rotation.md).

OpenBao uses the same behavior with `OPENBAO_*` variables instead of `VAULT_*`.

## Plugin configuration

Set `VAULT_AUTH_METHOD=jwt` (or `OPENBAO_AUTH_METHOD=jwt`). You must also set a
role name and provide a JWT from the environment **or** a file.

| Variable | Description | Default |
|---|---|---|
| `VAULT_AUTH_METHOD` / `OPENBAO_AUTH_METHOD` | Set to `jwt` | `token` |
| `VAULT_JWT_ROLE` / `OPENBAO_JWT_ROLE` | JWT/OIDC role name (required) | — |
| `VAULT_JWT` / `OPENBAO_JWT` | Signed JWT string | — |
| `VAULT_JWT_FILE` / `OPENBAO_JWT_FILE` | Path to a file containing the JWT | — |
| `VAULT_JWT_AUTH_PATH` / `OPENBAO_JWT_AUTH_PATH` | Auth mount path | `jwt` |

Either `*_JWT` or `*_JWT_FILE` is required. If both are set, the **file** is
used. The file is read again on every re-login, so you can rotate the identity
JWT on disk without reconfiguring the plugin. A JWT stored in `*_JWT` is fixed
until the next `docker plugin set`.

`*_JWT_FILE` is opened **inside the plugin**. The plugin bind-mounts host
`/run/swarm-external-secrets`, so put the file there (or another mounted path)
and point the env var at that in-plugin path.

### Environment JWT

```bash
docker plugin set swarm-external-secrets:latest \
    SECRETS_PROVIDER="vault" \
    VAULT_ADDR="https://vault.example.com:8200" \
    VAULT_AUTH_METHOD="jwt" \
    VAULT_JWT_ROLE="swarm-external-secrets" \
    VAULT_JWT="<signed-jwt>" \
    VAULT_JWT_AUTH_PATH="jwt"
```

OpenBao:

```bash
docker plugin set swarm-external-secrets:latest \
    SECRETS_PROVIDER="openbao" \
    OPENBAO_ADDR="https://openbao.example.com:8200" \
    OPENBAO_AUTH_METHOD="jwt" \
    OPENBAO_JWT_ROLE="swarm-external-secrets" \
    OPENBAO_JWT="<signed-jwt>" \
    OPENBAO_JWT_AUTH_PATH="jwt"
```

### JWT file

```bash
sudo mkdir -p /run/swarm-external-secrets
sudo install -m 0644 ./workload.jwt /run/swarm-external-secrets/workload.jwt

docker plugin set swarm-external-secrets:latest \
    SECRETS_PROVIDER="vault" \
    VAULT_ADDR="https://vault.example.com:8200" \
    VAULT_AUTH_METHOD="jwt" \
    VAULT_JWT_ROLE="swarm-external-secrets" \
    VAULT_JWT_FILE="/run/swarm-external-secrets/workload.jwt"
```

## JWT role and policy

Enable JWT auth and create a role whose policies can read your KV secrets.
The issued token must also be allowed to renew itself:

```hcl
path "secret/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

path "auth/token/renew-self" {
  capabilities = ["update"]
}
```

Current Vault and OpenBao JWT auth reject identity tokens that omit **all** of
`iat`, `nbf`, and `exp`. Include at least one (typically `iat` and `exp`) and
match `iss`, `sub`, and `aud` to the role (`bound_issuer`, `bound_subject`,
`bound_audiences`).

A full local setup used by CI is in `scripts/tests/smoke-test-vault-jwt.sh` and
`scripts/tests/smoke-test-openbao-jwt.sh` in this repository.

## Client-token renewal

After a successful AppRole or JWT login, Vault/OpenBao returns a **client
token** with a TTL. The plugin renews that token; it does not mint a new
identity JWT.

| Auth method | Client-token renewal | Re-login when renew fails |
|---|---|---|
| `token` | No. A static `VAULT_TOKEN` / `OPENBAO_TOKEN` is used until it expires. | No |
| `approle` | Yes | Yes (`role_id` / `secret_id`) |
| `jwt` | Yes | Yes (same JWT, or a freshly read `*_JWT_FILE`) |

When the issued token is renewable and has a positive TTL, a background worker:

1. Waits until about **two-thirds** of the remaining lease TTL.
2. Calls `auth/token/renew-self`.
3. If renew fails (including when **max TTL** is reached), logs in again with
   AppRole or JWT.
4. If a secret read returns `401` or `403`, logs in again and retries the read.

Retries after a failed renew use a 5s wait that doubles up to one minute.

Look for these plugin log lines (`vault` or `openbao` depending on the
provider):

- `Successfully renewed vault token`
- `Renewing vault token failed, attempting re-authentication`
- `Successfully re-authenticated with vault`

Enable `LOG_LEVEL=debug` (or `6`) if you need the debug-level renewal lines.

!!! warning "Static tokens do not auto-renew"
    `VAULT_AUTH_METHOD=token` (the default) never starts the renewal worker.
    Use AppRole or JWT when the plugin must outlive a short-lived client token.

!!! note "Secret rotation is separate"
    `ENABLE_ROTATION` watches KV values and updates Swarm secrets. Token
    renewal keeps the plugin authenticated. See [Secret rotation](rotation.md).

## CI smoke tests

The `smoke-test-jwt-renewal` job in `.github/workflows/smoke-tests.yml` runs
the Vault and OpenBao JWT scripts with a 10s token TTL, 25s max TTL, and a 45s
wait so CI asserts both renew-self and max-TTL re-login, then redeploys a
stack to prove reads still work.
