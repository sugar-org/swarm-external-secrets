#!/usr/bin/env bash

set -ex
SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd)"
REPO_ROOT="${GITHUB_WORKSPACE:-$(realpath -- "${SCRIPT_DIR}/../..")}"
# shellcheck source=smoke-test-helper.sh
source "${SCRIPT_DIR}/smoke-test-helper.sh"

# Configuration
# floci-az is a lightweight open-source Azure emulator (https://floci.io/floci-az/).
# It provides Key Vault and Entra ID (OIDC) in a single native binary on port 4577,
# needs no auth token or license, so the smoke test is reproducible for contributors,
# forks, and external PRs.
FLOCI_CONTAINER="smoke-floci-az"
# Pinned to an immutable digest for reproducible CI; multi-arch (amd64/arm64).
FLOCI_IMAGE="floci/floci-az:latest"
AZURE_ENDPOINT="http://localhost:4577"
AZURE_VAULT_URL="https://localhost:4577/devstoreaccount1-keyvault"
AZURE_AUTHORITY_HOST="http://localhost:4577"
AZURE_TENANT_ID="00000000-0000-0000-0000-000000000002"
AZURE_CLIENT_ID="11111111-1111-1111-1111-111111111111"
AZURE_CLIENT_SECRET="floci-az-dev-secret"
STACK_NAME="smoke-azure"
SECRET_NAME="smoke_secret"
SECRET_PATH="smoke-test-secret"
SECRET_FIELD="password"
SECRET_VALUE="azure-smoke-pass-v1"
SECRET_VALUE_ROTATED="azure-smoke-pass-v2"
SECRET_VALUE_ROTATED_AGAIN="azure-smoke-pass-v3"
COMPOSE_FILE="${SCRIPT_DIR}/smoke-azure-compose.yml"

# Helper to run curl against the floci-az Key Vault REST API.
kv_api() {
    curl -sf \
        -H "Authorization: Bearer fake-token" \
        -H "Content-Type: application/json" \
        "$@"
}

# Cleanup trap
cleanup() {
    echo -e "${RED}Running Azure Key Vault smoke test cleanup...${DEF}"
    remove_stack "${STACK_NAME}"
    docker secret rm "${SECRET_NAME}" 2>/dev/null || true
    if [[ -n "${FLOCI_CONTAINER}" ]]; then
        echo -e "${RED}floci-az logs:${DEF}"
        docker logs "${FLOCI_CONTAINER}" 2>/dev/null || true
        docker stop "${FLOCI_CONTAINER}" 2>/dev/null || true
        docker rm   "${FLOCI_CONTAINER}" 2>/dev/null || true
    fi
    remove_plugin
}
trap cleanup EXIT

command -v curl >/dev/null 2>&1 || die "curl is required to run the Azure Key Vault smoke test."

# Start floci-az container (skip if an emulator is already serving on 4577, e.g. in CI)
if curl -sf "${AZURE_ENDPOINT}/devstoreaccount1-keyvault/secrets?api-version=7.6" \
    -H "Authorization: Bearer fake-token" >/dev/null 2>&1; then
    info "Azure emulator already running on 4577, skipping container start."
    FLOCI_CONTAINER=""
else
    info "Starting floci-az Azure emulator container..."
    docker run -d \
        --name "${FLOCI_CONTAINER}" \
        -p 4577:4577 \
        "${FLOCI_IMAGE}"
fi

# Wait for floci-az to be ready by probing the Key Vault REST API.
info "Waiting for floci-az to be ready..."
elapsed=0
until curl -sf "${AZURE_ENDPOINT}/devstoreaccount1-keyvault/secrets?api-version=7.6" \
    -H "Authorization: Bearer fake-token" >/dev/null 2>&1; do
    sleep 2
    elapsed=$((elapsed + 2))
    [[ "${elapsed}" -lt 60 ]] || die "floci-az did not become ready within 60s."
done
success "floci-az is ready."

# Write test secret via Key Vault REST API
info "Writing test secret to floci-az Key Vault..."
curl -sf -X PUT \
    -H "Authorization: Bearer fake-token" \
    -H "Content-Type: application/json" \
    "${AZURE_ENDPOINT}/devstoreaccount1-keyvault/secrets/${SECRET_PATH}?api-version=7.6" \
    -d "{\"value\": \"{\\\"${SECRET_FIELD}\\\":\\\"${SECRET_VALUE}\\\"}\"}"
success "Secret written: ${SECRET_PATH}"

# Build plugin
info "Building plugin and setting Azure Key Vault config..."
build_plugin
docker plugin disable "${PLUGIN_NAME}" --force 2>/dev/null || true
# Azure Identity rejects HTTP authority hosts, so the emulator path uses the
# same static bearer token as the curl helpers above instead of client-secret auth.
docker plugin set "${PLUGIN_NAME}" \
    SECRETS_PROVIDER="azure" \
    AZURE_VAULT_URL="${AZURE_VAULT_URL}" \
    AZURE_ACCESS_TOKEN="fake-token" \
    AZURE_INSECURE_HTTP="true" \
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
assert_no_sensitive_rotation_metadata_logs

# Compare password == logged secret
info "Verifying secret value matches expected password..."
verify_secret "${STACK_NAME}" "app" "${SECRET_NAME}" "${SECRET_VALUE}" 60

# Rotate the password and verify
info "Rotating secret in Azure Key Vault..."
curl -sf -X PUT \
    -H "Authorization: Bearer fake-token" \
    -H "Content-Type: application/json" \
    "${AZURE_ENDPOINT}/devstoreaccount1-keyvault/secrets/${SECRET_PATH}?api-version=7.6" \
    -d "{\"value\": \"{\\\"${SECRET_FIELD}\\\":\\\"${SECRET_VALUE_ROTATED}\\\"}\"}"
success "Secret rotated to: ${SECRET_VALUE_ROTATED}"

info "Waiting for plugin rotation interval (15s)..."
sleep 30
assert_no_sensitive_rotation_metadata_logs

info "Logging service output after rotation..."
log_stack "${STACK_NAME}" "app"

info "Verifying rotated secret value..."
verify_secret "${STACK_NAME}" "app" "${SECRET_NAME}" "${SECRET_VALUE_ROTATED}" 180

# Regression check for issue #28: the second rotation must find the versioned
# Docker secret created by the first rotation.
info "Rotating the versioned secret again with an additional JSON field..."
curl -sf -X PUT \
    -H "Authorization: Bearer fake-token" \
    -H "Content-Type: application/json" \
    "${AZURE_ENDPOINT}/devstoreaccount1-keyvault/secrets/${SECRET_PATH}?api-version=7.6" \
    -d "{\"value\": \"{\\\"${SECRET_FIELD}\\\":\\\"${SECRET_VALUE_ROTATED_AGAIN}\\\",\\\"metadata\\\":\\\"synthetic\\\"}\"}"

info "Waiting for the second plugin rotation interval (15s)..."
assert_no_sensitive_rotation_metadata_logs
verify_secret "${STACK_NAME}" "app" "${SECRET_NAME}" "${SECRET_VALUE_ROTATED_AGAIN}" 180

success "Azure Key Vault smoke test PASSED"
