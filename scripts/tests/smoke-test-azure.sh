#!/usr/bin/env bash

set -ex
SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd)"
REPO_ROOT="$(realpath -- "${SCRIPT_DIR}/../..")"
# shellcheck source=smoke-test-helper.sh
source "${SCRIPT_DIR}/smoke-test-helper.sh"

# Configuration
LOCALSTACK_CONTAINER="smoke-localstack-azure"
LOCALSTACK_ENDPOINT="http://localhost:4566"
AZURE_VAULT_URL="${LOCALSTACK_ENDPOINT}/azure/keyvault/vaults/smoke-vault"
STACK_NAME="smoke-azure"
SECRET_NAME="smoke_secret"
AZURE_SECRET_NAME="smoke-secret"
SECRET_VALUE="azure-smoke-pass-v1"
SECRET_VALUE_ROTATED="azure-smoke-pass-v2"
COMPOSE_FILE="${SCRIPT_DIR}/smoke-azure-compose.yml"

# Helper to call the LocalStack Azure Key Vault REST API
kv_put_secret() {
    local name="$1"
    local value="$2"
    curl -s -X PUT \
        "${AZURE_VAULT_URL}/secrets/${name}?api-version=7.4" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer test" \
        -d "{\"value\":\"${value}\"}"
}

# Cleanup trap
cleanup() {
    echo -e "${RED}Running Azure Key Vault smoke test cleanup...${DEF}"
    remove_stack "${STACK_NAME}"
    docker secret rm "${SECRET_NAME}" 2>/dev/null || true
    if [ -n "${LOCALSTACK_CONTAINER}" ]; then
        docker stop "${LOCALSTACK_CONTAINER}" 2>/dev/null || true
        docker rm   "${LOCALSTACK_CONTAINER}" 2>/dev/null || true
    fi
    remove_plugin
}
trap cleanup EXIT

# Start LocalStack Azure container (skip if already running, e.g. in CI)
if curl -s "${LOCALSTACK_ENDPOINT}/_localstack/health" >/dev/null 2>&1; then
    info "LocalStack already running, skipping container start."
    LOCALSTACK_CONTAINER=""
else
    info "Starting LocalStack Azure container..."
    docker run -d \
        --name "${LOCALSTACK_CONTAINER}" \
        -p 4566:4566 \
        -e LOCALSTACK_AUTH_TOKEN="${LOCALSTACK_AUTH_TOKEN:?LOCALSTACK_AUTH_TOKEN is required}" \
        localstack/localstack-azure-alpha:latest
fi

# Wait for LocalStack to be ready
info "Waiting for LocalStack to be ready..."
elapsed=0
until curl -s "${LOCALSTACK_ENDPOINT}/_localstack/health" | grep -q "available" 2>/dev/null; do
    sleep 2
    elapsed=$((elapsed + 2))
    [ "${elapsed}" -lt 60 ] || die "LocalStack did not become ready within 60s."
done
success "LocalStack is ready."

# Write test secret via Azure Key Vault REST API
info "Writing test secret to Azure Key Vault..."
kv_put_secret "${AZURE_SECRET_NAME}" "${SECRET_VALUE}"
success "Secret written: ${AZURE_SECRET_NAME}=${SECRET_VALUE}"

# Build plugin
info "Building plugin and setting Azure Key Vault config..."
build_plugin
docker plugin disable "${PLUGIN_NAME}" --force 2>/dev/null || true
docker plugin set "${PLUGIN_NAME}" \
    SECRETS_PROVIDER="azure" \
    AZURE_VAULT_URL="${AZURE_VAULT_URL}" \
    AZURE_ACCESS_TOKEN="test" \
    ENABLE_ROTATION="true" \
    ROTATION_INTERVAL="10s" \
    ENABLE_MONITORING="false"
success "Plugin configured with Azure Key Vault settings."

# Enable plugin
info "Enabling plugin..."
enable_plugin

# Deploy stack
info "Deploying swarm stack..."
deploy_stack "${COMPOSE_FILE}" "${STACK_NAME}" 60

# Log service output
info "Logging service output..."
sleep 10
log_stack "${STACK_NAME}" "app"

# Compare password == logged secret
info "Verifying secret value matches expected password..."
verify_secret "${STACK_NAME}" "app" "${SECRET_NAME}" "${SECRET_VALUE}" 60

# Rotate the password and verify
info "Rotating secret in Azure Key Vault..."
kv_put_secret "${AZURE_SECRET_NAME}" "${SECRET_VALUE_ROTATED}"
success "Secret rotated to: ${SECRET_VALUE_ROTATED}"

info "Waiting for plugin rotation interval (15s)..."
sleep 30

info "Logging service output after rotation..."
log_stack "${STACK_NAME}" "app"

info "Verifying rotated secret value..."
verify_secret "${STACK_NAME}" "app" "${SECRET_NAME}" "${SECRET_VALUE_ROTATED}" 180

success "Azure Key Vault smoke test PASSED"
