#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

# -------------------------
# Variables
# -------------------------

PROVIDER="${1:-vault}"
STACK_NAME="smoke_stack_$(date +%s)"
SERVICE_NAME="smoke_service"
SECRET_NAME="smoke_secret"
VAULT_CONTAINER="smoke-vault"
EXPECTED_SECRET="smoke_test_value_123"

# -------------------------
# Logging
# -------------------------

log() {
  echo "[SMOKE TEST] $1"
}

# -------------------------
# Cleanup (must be early)
# -------------------------

cleanup() {
  log "Cleaning up..."
  docker service rm "$SERVICE_NAME" 2>/dev/null || true
  docker secret rm "$SECRET_NAME" 2>/dev/null || true
  docker plugin disable swarm-external-secrets:latest --force 2>/dev/null || true
  docker plugin rm swarm-external-secrets:latest --force 2>/dev/null || true
  docker rm -f "$VAULT_CONTAINER" 2>/dev/null || true
  docker swarm leave --force >/dev/null 2>&1 || true
}

trap cleanup EXIT

# -------------------------
# Wait for Vault readiness
# -------------------------

wait_for_vault() {
  log "Waiting for Vault to become ready..."

  for i in {1..20}; do
    if docker exec "$VAULT_CONTAINER" \
      env VAULT_ADDR="http://127.0.0.1:8200" \
      VAULT_TOKEN="root" \
      vault status >/dev/null 2>&1; then
      log "Vault is ready."
      return 0
    fi
    sleep 1
  done

  log "Vault failed to start."
  docker logs "$VAULT_CONTAINER"
  exit 1
}

# -------------------------
# Initialize Docker Swarm
# -------------------------

init_swarm() {
  log "Checking Docker Swarm status..."

  if ! docker info 2>/dev/null | grep -q "Swarm: active"; then
    log "Docker Swarm not active. Initializing..."
    docker swarm init >/dev/null
  else
    log "Docker Swarm already active"
  fi
}

# -------------------------
# Setup Vault (dev mode)
# -------------------------

setup_vault() {
  log "Starting Vault container (dev mode)..."

  docker run -d \
    --name "$VAULT_CONTAINER" \
    -e VAULT_DEV_ROOT_TOKEN_ID=root \
    -e VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200 \
    -p 8200:8200 \
    hashicorp/vault:1.16 \
    server -dev -dev-root-token-id=root >/dev/null

  wait_for_vault

  log "Writing test secret to Vault..."

  docker exec \
    -e VAULT_ADDR="http://127.0.0.1:8200" \
    -e VAULT_TOKEN="root" \
    "$VAULT_CONTAINER" \
    vault kv put secret/smoke password="$EXPECTED_SECRET" >/dev/null
}
build_plugin() {
  log "Building Docker plugin..."

  ./scripts/build.sh >/dev/null

  # Ensure plugin exists
  if ! docker plugin inspect swarm-external-secrets:latest >/dev/null 2>&1; then
    log "Plugin build failed."
    exit 1
  fi

  # Always disable before configuring (deterministic behavior)
  docker plugin disable swarm-external-secrets:latest --force >/dev/null 2>&1 || true

  log "Configuring plugin for Vault..."

  docker plugin set swarm-external-secrets:latest \
    SECRETS_PROVIDER="vault" \
    VAULT_ADDR="http://127.0.0.1:8200" \
    VAULT_AUTH_METHOD="token" \
    VAULT_TOKEN="root" \
    VAULT_MOUNT_PATH="secret" \
    VAULT_ENABLE_ROTATION="false" >/dev/null

  log "Enabling plugin..."

  docker plugin enable swarm-external-secrets:latest >/dev/null
}

# -------------------------
# Main Execution
# -------------------------

main() {
  init_swarm
  setup_vault
  build_plugin
}
main