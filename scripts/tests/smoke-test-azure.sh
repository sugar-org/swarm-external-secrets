#!/usr/bin/env bash

set -ex
SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd)"
REPO_ROOT="$(realpath -- "${SCRIPT_DIR}/../..")"
# shellcheck source=smoke-test-helper.sh
source "${SCRIPT_DIR}/smoke-test-helper.sh"

# Configuration
AZURE_KV_MOCK_HOST="127.0.0.1"
AZURE_KV_MOCK_PORT="8081"
AZURE_KV_MOCK_TOKEN="smoke-token"
AZURE_KV_MOCK_TENANT="smoke-tenant"
AZURE_VAULT_URL="http://${AZURE_KV_MOCK_HOST}:${AZURE_KV_MOCK_PORT}"
STACK_NAME="smoke-azure"
SECRET_NAME="smoke_secret"
SECRET_PATH="database-connection-string"
SECRET_FIELD="password"
SECRET_VALUE="azure-smoke-pass-v1"
SECRET_VALUE_ROTATED="azure-smoke-pass-v2"
COMPOSE_FILE="${SCRIPT_DIR}/smoke-azure-compose.yml"

# Cleanup trap
cleanup() {
    echo -e "${RED}Running Azure Key Vault smoke test cleanup...${DEF}"
    remove_stack "${STACK_NAME}"
    docker secret rm "${SECRET_NAME}" 2>/dev/null || true
    if [ -n "${AZURE_KV_MOCK_PID:-}" ]; then
        kill "${AZURE_KV_MOCK_PID}" 2>/dev/null || true
    fi
    remove_plugin
}
trap cleanup EXIT

set_mock_secret() {
    local value="$1"
    curl -sS -X POST "${AZURE_VAULT_URL}/mock/set" \
        -H "Content-Type: application/json" \
        -d "{\"name\":\"${SECRET_PATH}\",\"value\":\"{\\\"${SECRET_FIELD}\\\":\\\"${value}\\\"}\"}" >/dev/null
}

# Start Azure KV mock server
info "Starting Azure Key Vault mock server..."
AZURE_KV_MOCK_HOST="${AZURE_KV_MOCK_HOST}" \
AZURE_KV_MOCK_PORT="${AZURE_KV_MOCK_PORT}" \
AZURE_KV_MOCK_TOKEN="${AZURE_KV_MOCK_TOKEN}" \
AZURE_KV_MOCK_TENANT="${AZURE_KV_MOCK_TENANT}" \
python3 "${SCRIPT_DIR}/azure_kv_mock_server.py" &
AZURE_KV_MOCK_PID=$!

info "Waiting for Azure Key Vault mock to be ready..."
elapsed=0
until curl -s "${AZURE_VAULT_URL}/health" | grep -q "\"ok\"" 2>/dev/null; do
    sleep 1
    elapsed=$((elapsed + 1))
    [ "${elapsed}" -lt 20 ] || die "Azure KV mock did not become ready within 20s."
done
success "Azure Key Vault mock is ready."

# Write initial test secret
info "Writing test secret to Azure KV mock..."
set_mock_secret "${SECRET_VALUE}"
success "Secret written: ${SECRET_PATH} ${SECRET_FIELD}=${SECRET_VALUE}"

# Build plugin
info "Building plugin and setting Azure config..."
build_plugin
docker plugin disable "${PLUGIN_NAME}" --force 2>/dev/null || true
docker plugin set "${PLUGIN_NAME}" \
    SECRETS_PROVIDER="azure" \
    AZURE_VAULT_URL="${AZURE_VAULT_URL}" \
    AZURE_ACCESS_TOKEN="${AZURE_KV_MOCK_TOKEN}" \
    ENABLE_ROTATION="true" \
    ROTATION_INTERVAL="10s" \
    ENABLE_MONITORING="false"
success "Plugin configured with Azure settings."

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

# Verify initial secret
info "Verifying secret value matches expected password..."
verify_secret "${STACK_NAME}" "app" "${SECRET_NAME}" "${SECRET_VALUE}" 60

# Rotate the secret and verify
info "Rotating secret in Azure KV mock..."
set_mock_secret "${SECRET_VALUE_ROTATED}"
success "Secret rotated to: ${SECRET_VALUE_ROTATED}"

info "Waiting for plugin rotation interval (30s)..."
sleep 30

info "Logging service output after rotation..."
log_stack "${STACK_NAME}" "app"

info "Verifying rotated secret value..."
verify_secret "${STACK_NAME}" "app" "${SECRET_NAME}" "${SECRET_VALUE_ROTATED}" 180

success "Azure Key Vault smoke test PASSED"
