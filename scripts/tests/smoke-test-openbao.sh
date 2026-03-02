#!/usr/bin/env bash

set -ex
SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd)"
REPO_ROOT="$(realpath -- "${SCRIPT_DIR}/../..")"
# shellcheck source=smoke-test-helper.sh
source "${SCRIPT_DIR}/smoke-test-helper.sh"

# Configuration
OPENBAO_CONTAINER="smoke-openbao"
OPENBAO_ROOT_TOKEN="smoke-root-token"
OPENBAO_ADDR="http://127.0.0.1:8200"
STACK_NAME="smoke-openbao"
SECRET_NAME="smoke_secret"
SECRET_PATH="database/mysql"
SECRET_FIELD="password"
SECRET_VALUE="openbao-smoke-pass-v1"
SECRET_VALUE_ROTATED="openbao-smoke-pass-v2"
COMPOSE_FILE="${SCRIPT_DIR}/smoke-openbao-compose.yml"
POLICY_FILE="${REPO_ROOT}/vault_conf/admin.hcl"

# Cleanup trap
cleanup() {
    echo -e "${RED}Running OpenBao smoke test cleanup...${DEF}"
    remove_stack "${STACK_NAME}"
    docker secret rm "${SECRET_NAME}" 2>/dev/null || true
    docker stop "${OPENBAO_CONTAINER}" 2>/dev/null || true
    docker rm   "${OPENBAO_CONTAINER}" 2>/dev/null || true
    remove_plugin
}
trap cleanup EXIT

# Create openbao container
info "Starting OpenBao dev container..."
docker run -d \
    --name "${OPENBAO_CONTAINER}" \
    -p 8200:8200 \
    -e "BAO_DEV_ROOT_TOKEN_ID=${OPENBAO_ROOT_TOKEN}" \
    quay.io/openbao/openbao:latest server -dev

# Wait for OpenBao to be ready
info "Waiting for OpenBao to be ready..."
elapsed=0
until docker exec "${OPENBAO_CONTAINER}" bao status -address="http://127.0.0.1:8200" >/dev/null 2>&1; do
    sleep 2
    elapsed=$((elapsed + 2))
    [ "${elapsed}" -lt 30 ] || die "OpenBao did not become ready within 30s."
done
success "OpenBao is ready."

# Apply policy from vault_conf/admin.hcl
info "Applying policy to OpenBao..."
docker cp "${POLICY_FILE}" "${OPENBAO_CONTAINER}:/tmp/admin.hcl"
docker exec "${OPENBAO_CONTAINER}" \
    env BAO_ADDR="http://127.0.0.1:8200" BAO_TOKEN="${OPENBAO_ROOT_TOKEN}" \
    bao policy write smoke-policy /tmp/admin.hcl
success "Policy applied."

# Add passwords (write test secret)
info "Writing test secret to OpenBao..."
docker exec "${OPENBAO_CONTAINER}" \
    env BAO_ADDR="http://127.0.0.1:8200" BAO_TOKEN="${OPENBAO_ROOT_TOKEN}" \
    bao kv put \
    "secret/${SECRET_PATH}" \
    "${SECRET_FIELD}=${SECRET_VALUE}"
success "Secret written: secret/${SECRET_PATH} ${SECRET_FIELD}=${SECRET_VALUE}"

# Get the tmp auth token from openbao
info "Getting auth token from OpenBao..."
OPENBAO_TOKEN=$(docker exec "${OPENBAO_CONTAINER}" \
    env BAO_ADDR="http://127.0.0.1:8200" BAO_TOKEN="${OPENBAO_ROOT_TOKEN}" \
    bao token create \
    -policy="smoke-policy" \
    -field=token)
success "Got auth token: ${OPENBAO_TOKEN}"

# Put the auth token in the plugin
info "Building plugin and setting OpenBao auth token..."
build_plugin
docker plugin set "${PLUGIN_NAME}" \
    SECRETS_PROVIDER="openbao" \
    OPENBAO_ADDR="${OPENBAO_ADDR}" \
    OPENBAO_AUTH_METHOD="token" \
    OPENBAO_TOKEN="${OPENBAO_TOKEN}" \
    OPENBAO_MOUNT_PATH="secret" \
    ENABLE_ROTATION="true" \
    ROTATION_INTERVAL="10s" \
    ENABLE_MONITORING="false"
success "Plugin configured with OpenBao token."

# Run (enable) the plugin
info "Enabling plugin..."
enable_plugin

# Run docker stack deploy
info "Deploying swarm stack..."
deploy_stack "${COMPOSE_FILE}" "${STACK_NAME}" 60

# Log docker service output
info "Logging service output..."
sleep 10
log_stack "${STACK_NAME}" "app"

# Compare password == logged secret
info "Verifying secret value matches expected password..."
verify_secret "${STACK_NAME}" "app" "${SECRET_NAME}" "${SECRET_VALUE}" 60

# Capture container ID now, before rotation, to verify in-place update
info "Capturing running container ID before rotation..."
APP_CONTAINER_ID=$(get_running_container_id "${STACK_NAME}" "app")
success "Container to watch: ${APP_CONTAINER_ID:0:12}"

# Rotate the password and verify
info "Rotating secret in OpenBao..."
docker exec "${OPENBAO_CONTAINER}" \
    env BAO_ADDR="http://127.0.0.1:8200" BAO_TOKEN="${OPENBAO_ROOT_TOKEN}" \
    bao kv put \
    "secret/${SECRET_PATH}" \
    "${SECRET_FIELD}=${SECRET_VALUE_ROTATED}"
success "Secret rotated to: ${SECRET_VALUE_ROTATED}"

info "Waiting for plugin rotation interval (15s)..."
sleep 15

info "Waiting for new container to start after rotation (10s)..."
sleep 10

info "Logging service output after rotation..."
log_stack "${STACK_NAME}" "app"

info "Verifying rotated secret value (must update in-place, same container)..."
verify_secret "${STACK_NAME}" "app" "${SECRET_NAME}" "${SECRET_VALUE_ROTATED}" 180


success "OpenBao smoke test PASSED (incl. rotation)"
