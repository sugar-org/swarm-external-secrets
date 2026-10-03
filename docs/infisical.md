# Infisical

This document describes how to use [Infisical](https://infisical.com) as a first-class secrets provider with Swarm External Secrets.

## Overview

The Infisical provider fetches secret values from an Infisical project/environment (and optional folder path) using either:

1. **Universal Auth** (recommended for production) — machine identity `Client ID` + `Client Secret`
2. **Bearer access token** — a pre-issued Infisical access token (`INFISICAL_TOKEN`)

When a Docker service requests a secret, the plugin uses the official Infisical Go SDK to retrieve it and returns the plaintext value to Swarm. With rotation enabled, the plugin periodically re-reads the secret and cutovers Swarm secret versions when the value changes.

## Configuration

| Variable | Description | Default |
|---|---|---|
| `INFISICAL_CLIENT_ID` | Machine identity Client ID (Universal Auth) | — |
| `INFISICAL_CLIENT_SECRET` | Machine identity Client Secret (Universal Auth) | — |
| `INFISICAL_TOKEN` | Pre-issued bearer/access token (optional alternative to Universal Auth) | — |
| `INFISICAL_PROJECT_ID` | Infisical project ID (**required**) | — |
| `INFISICAL_ENVIRONMENT` | Environment slug (`dev`, `staging`, `prod`, …) | `dev` |
| `INFISICAL_SECRET_PATH` | Default folder path for secrets | `/` |
| `INFISICAL_SITE_URL` | Infisical site/API base URL | `https://app.infisical.com` |

You must set either `INFISICAL_TOKEN` **or** both `INFISICAL_CLIENT_ID` and `INFISICAL_CLIENT_SECRET`.

### Site URL

Choose the correct base URL for your deployment:

- Infisical Cloud US: `https://app.infisical.com` (also `https://us.infisical.com`)
- Infisical Cloud EU: `https://eu.infisical.com`
- Self-hosted: your Infisical origin (for example `https://infisical.example.com`)

### Example (Universal Auth)

```bash
docker plugin set swarm-external-secrets:latest \
    SECRETS_PROVIDER="infisical" \
    INFISICAL_CLIENT_ID="..." \
    INFISICAL_CLIENT_SECRET="..." \
    INFISICAL_PROJECT_ID="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" \
    INFISICAL_ENVIRONMENT="prod" \
    INFISICAL_SECRET_PATH="/" \
    ENABLE_ROTATION="true" \
    ROTATION_INTERVAL="30s"
```

### Example (access token)

```bash
docker plugin set swarm-external-secrets:latest \
    SECRETS_PROVIDER="infisical" \
    INFISICAL_TOKEN="eyJ..." \
    INFISICAL_PROJECT_ID="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" \
    INFISICAL_ENVIRONMENT="dev"
```

## Secret labels

| Label | Description |
|---|---|
| `infisical_secret_name` | Infisical secret key (e.g. `MYSQL_PASSWORD`) |
| `infisical_field` | Optional JSON field to extract when the Infisical value is a JSON object (defaults to `value`) |
| `infisical_project_id` | Optional per-secret project override |
| `infisical_environment` | Optional per-secret environment override |
| `infisical_secret_path` | Optional per-secret folder path override |

If `infisical_secret_name` is omitted, the Docker secret name is uppercased (`mysql_password` → `MYSQL_PASSWORD`).

### Compose example

```yaml
version: "3.8"

services:
  api:
    image: myorg/api:latest
    secrets:
      - mysql_password
    deploy:
      replicas: 1

secrets:
  mysql_password:
    driver: swarm-external-secrets:latest
    labels:
      infisical_secret_name: "MYSQL_PASSWORD"
      # Optional overrides:
      # infisical_environment: "prod"
      # infisical_secret_path: "/database"
```

## Machine identity setup

1. In Infisical, create a **Machine Identity** and enable **Universal Auth**.
2. Generate a Client Secret for the identity.
3. Add the identity to your project with a role that can read the secrets you need.
4. Copy the Client ID, Client Secret, and Project ID into the plugin settings above.

See Infisical's [Universal Auth](https://infisical.com/docs/documentation/platform/identities/universal-auth) docs for details.

## Rotation

Rotation uses the same poll-based path as other providers:

1. On first `Get`, the plugin tracks the secret hash.
2. Every `ROTATION_INTERVAL`, it re-fetches from Infisical.
3. On change, it creates a new Swarm secret version and updates referencing services.

Universal Auth tokens are refreshed by the Infisical SDK (`AutoTokenRefresh`). A static `INFISICAL_TOKEN` is used as-is.

## Smoke test

End-to-end Swarm smoke coverage (fetch + rotation) lives in `scripts/tests/smoke-test-infisical.sh`.

By default, this test starts real Infisical, PostgreSQL, Redis, and an HTTPS proxy in Docker Compose. It generates a temporary certificate, bootstraps an organization and project, and creates Universal Auth credentials at runtime. No cloud account or repository secrets are required, including on fork pull requests.

Requires Docker Engine with Swarm and managed-plugin support, Docker Compose, OpenSSL, curl, and jq. Run on a disposable Docker host: the shared smoke helper replaces `swarm-external-secrets:latest`.

```bash
bash scripts/tests/smoke-test-infisical.sh
```

The HTTPS proxy binds to `127.0.0.1:8443`; override `INFISICAL_LOCAL_PORT` if needed. The generated certificate is trusted only by this test's curl calls and plugin rootfs, without disabling TLS verification. Cleanup removes the local deployment and temporary files.

To test an existing deployment instead, set `INFISICAL_SMOKE_EXTERNAL=true` and provide:

| Variable | Description |
|---|---|
| `INFISICAL_PROJECT_ID` | Project that the smoke identity can read/write |
| `INFISICAL_SMOKE_TOKEN` | Access/service token with secret CRUD **or** |
| `INFISICAL_SMOKE_CLIENT_ID` / `INFISICAL_SMOKE_CLIENT_SECRET` | Universal Auth machine identity with secret CRUD |

Optional: `INFISICAL_ENVIRONMENT` (default `dev`), `INFISICAL_SECRET_PATH` (default `/`), `INFISICAL_SITE_URL`.

```bash
export INFISICAL_SMOKE_EXTERNAL=true
export INFISICAL_PROJECT_ID="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
export INFISICAL_SMOKE_CLIENT_ID="..."
export INFISICAL_SMOKE_CLIENT_SECRET="..."
# optional: export INFISICAL_ENVIRONMENT=dev

bash scripts/tests/smoke-test-infisical.sh
```

The script seeds a unique secret, deploys a Swarm stack through the plugin, verifies the value, rotates the secret in Infisical, and verifies cutover. Cleanup deletes the seeded secret.

## Implementation notes

- Uses the official Infisical Go SDK authentication helpers with a provider-owned HTTP client and synchronized token lifecycle.
- Universal Auth tokens are renewed before expiry on the next read, with reauthentication when renewal fails or maximum TTL is reached. Pre-issued bearer tokens are not renewed; replace them externally before expiry.
- Authentication and reads propagate cancellation and enforce a 30-second HTTP timeout. Closing the provider cancels authentication in progress.
- Reads use context-aware `net/http` requests to `GET /api/v3/secrets/raw/{secretName}`, rather than the SDK's unbounded retrieval path.
- Transient network failures, HTTP 429, and HTTP 500/502/503/504 responses get at most three total attempts with exponential backoff and jitter. Backoff, including `Retry-After`, is capped at five seconds and respects the caller's deadline. HTTP 400/401/403/404 responses are not retried.
- Secret path encoding for tracking: `{projectID}/{environment}[/{folders...}]/{secretName}`
