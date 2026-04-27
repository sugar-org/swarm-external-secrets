#!/usr/bin/env bash

set -ex
SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd)"
REPO_ROOT="$(realpath -- "${SCRIPT_DIR}/../..")"

# shellcheck source=smoke-test-helper.sh
source "${SCRIPT_DIR}/smoke-test-helper.sh"

# Configuration
VAULT_CONTAINER="smoke-vault"
VAULT_ROOT_TOKEN="smoke-root-token"
VAULT_ADDR="http://127.0.0.1:8200"
STACK_NAME="smoke-vault"
SECRET_NAME="smoke_secret"
SECRET_PATH="database/mysql"
SECRET_FIELD="password"
SECRET_VALUE="vault-smoke-pass-v1"
SECRET_VALUE_ROTATED="vault-smoke-pass-v2"
COMPOSE_FILE="${SCRIPT_DIR}/smoke-vault-compose.yml"

# Multi-source test values
MULTI_SOURCE_MYSQL_ROOT="mysql-root-pass-v1"
MULTI_SOURCE_MYSQL_USER="mysql-user-pass-v1"
MULTI_SOURCE_REDIS="redis-pass-v1"
MULTI_SOURCE_MYSQL_ROOT_ROTATED="mysql-root-pass-v2"
MULTI_SOURCE_MYSQL_USER_ROTATED="mysql-user-pass-v2"
MULTI_SOURCE_REDIS_ROTATED="redis-pass-v2"
POLICY_FILE="${REPO_ROOT}/vault_conf/admin.hcl"
EXIT_CODE=0
# Cleanup trap
cleanup() {
    echo -e "${RED}Running Vault smoke test cleanup...${DEF}"
    remove_stack "${STACK_NAME}"
    docker secret rm "${SECRET_NAME}" 2>/dev/null || true
    docker stop "${VAULT_CONTAINER}" 2>/dev/null || true
    docker rm   "${VAULT_CONTAINER}" 2>/dev/null || true
    remove_plugin
    exit "${EXIT_CODE}"
}
trap cleanup EXIT

# Create hashicorp/vault container
info "Starting HashiCorp Vault dev container..."
docker run -d \
    --name "${VAULT_CONTAINER}" \
    -p 8200:8200 \
    -e "VAULT_DEV_ROOT_TOKEN_ID=${VAULT_ROOT_TOKEN}" \
    hashicorp/vault:latest server -dev

# Wait for Vault to be ready
info "Waiting for Vault to be ready..."
elapsed=0
until docker exec "${VAULT_CONTAINER}" \
        vault status -address="${VAULT_ADDR}" &>/dev/null; do
    sleep 2
    elapsed=$((elapsed + 2))
    [[ "${elapsed}" -lt 30 ]] || die "Vault did not become ready within 30s."
done
success "Vault is ready."

# Apply policy from vault_conf/admin.hcl
info "Applying policy to Vault..."
docker cp "${POLICY_FILE}" "${VAULT_CONTAINER}:/tmp/admin.hcl"
docker exec "${VAULT_CONTAINER}" \
    env VAULT_ADDR="${VAULT_ADDR}" VAULT_TOKEN="${VAULT_ROOT_TOKEN}" \
    vault policy write smoke-policy /tmp/admin.hcl
success "Policy applied."

# Add passwords (write test secret)
info "Writing test secret to Vault..."
docker exec "${VAULT_CONTAINER}" \
    env VAULT_ADDR="${VAULT_ADDR}" VAULT_TOKEN="${VAULT_ROOT_TOKEN}" \
    vault kv put \
    "secret/${SECRET_PATH}" \
    "${SECRET_FIELD}=${SECRET_VALUE}"
success "Secret written: secret/${SECRET_PATH} ${SECRET_FIELD}=${SECRET_VALUE}"

# Write multi-source secrets to Vault
info "Writing multi-source secrets to Vault..."
docker exec "${VAULT_CONTAINER}" \
    env VAULT_ADDR="${VAULT_ADDR}" VAULT_TOKEN="${VAULT_ROOT_TOKEN}" \
    vault kv put \
    "secret/database/mysql" \
    "password=${SECRET_VALUE}" \
    "root_password=${MULTI_SOURCE_MYSQL_ROOT}" \
    "user_password=${MULTI_SOURCE_MYSQL_USER}"
docker exec "${VAULT_CONTAINER}" \
    env VAULT_ADDR="${VAULT_ADDR}" VAULT_TOKEN="${VAULT_ROOT_TOKEN}" \
    vault kv put \
    "secret/database/redis" \
    "password=${MULTI_SOURCE_REDIS}"
success "Multi-source secrets written."

# Get the tmp auth token from vault
info "Getting auth token from Vault..."
VAULT_TOKEN=$(docker exec "${VAULT_CONTAINER}" \
    env VAULT_ADDR="${VAULT_ADDR}" VAULT_TOKEN="${VAULT_ROOT_TOKEN}" \
    vault token create \
        -policy="smoke-policy" \
        -field=token)
success "Got auth token: ${VAULT_TOKEN}"

# Put the auth token in the plugin
info "Building plugin and setting Vault auth token..."
build_plugin

docker plugin set "${PLUGIN_NAME}" \
    SECRETS_PROVIDER="vault" \
    VAULT_ADDR="${VAULT_ADDR}" \
    VAULT_AUTH_METHOD="token" \
    VAULT_TOKEN="${VAULT_TOKEN}" \
    VAULT_MOUNT_PATH="secret" \
    ENABLE_ROTATION="true" \
    ROTATION_INTERVAL="10s" \
    VAULT_SKIP_VERIFY="false" \
    ENABLE_MONITORING="false"
success "Plugin configured with Vault token."

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
assert_no_sensitive_rotation_metadata_logs

# Compare password == logged secret
info "Verifying secret value matches expected password..."
verify_secret "${STACK_NAME}" "app" "${SECRET_NAME}" "${SECRET_VALUE}" 60

# Verify multi-source JSON secret
info "Verifying multi-source JSON secret (app_credentials)..."
verify_secret_contains "${STACK_NAME}" "app" "app_credentials" "MYSQL_ROOT_PASSWORD" 60
verify_secret_contains "${STACK_NAME}" "app" "app_credentials" "MYSQL_USER_PASSWORD" 60
verify_secret_contains "${STACK_NAME}" "app" "app_credentials" "REDIS_PASSWORD" 60

# Verify multi-source ENV secret
info "Verifying multi-source ENV secret (app_credentials_env)..."
verify_secret_contains "${STACK_NAME}" "app" "app_credentials_env" "MYSQL_ROOT_PASSWORD" 60
verify_secret_contains "${STACK_NAME}" "app" "app_credentials_env" "REDIS_PASSWORD" 60

# Capture container ID now, before rotation, to verify in-place update
info "Capturing running container ID before rotation..."
APP_CONTAINER_ID=$(get_running_container_id "${STACK_NAME}" "app")
success "Container to watch: ${APP_CONTAINER_ID:0:12}"

# Rotate single secret and verify
info "Rotating secret in Vault..."
docker exec "${VAULT_CONTAINER}" \
    env VAULT_ADDR="${VAULT_ADDR}" VAULT_TOKEN="${VAULT_ROOT_TOKEN}" \
    vault kv put \
    "secret/${SECRET_PATH}" \
    "${SECRET_FIELD}=${SECRET_VALUE_ROTATED}"
success "Secret rotated to: ${SECRET_VALUE_ROTATED}"

info "Waiting for plugin rotation interval (15s)..."
sleep 15

info "Waiting for new container to start after rotation (10s)..."
sleep 10
assert_no_sensitive_rotation_metadata_logs

info "Logging service output after rotation..."
log_stack "${STACK_NAME}" "app"

info "Verifying rotated secret value (waiting for in-place update, up to 180s)..."
verify_secret "${STACK_NAME}" "app" "${SECRET_NAME}" "${SECRET_VALUE_ROTATED}" 180

# Rotate multi-source secrets and verify
info "Rotating multi-source secrets in Vault..."
docker exec "${VAULT_CONTAINER}" \
    env VAULT_ADDR="${VAULT_ADDR}" VAULT_TOKEN="${VAULT_ROOT_TOKEN}" \
    vault kv put \
    "secret/database/mysql" \
    "password=${SECRET_VALUE_ROTATED}" \
    "root_password=${MULTI_SOURCE_MYSQL_ROOT_ROTATED}" \
    "user_password=${MULTI_SOURCE_MYSQL_USER_ROTATED}"
docker exec "${VAULT_CONTAINER}" \
    env VAULT_ADDR="${VAULT_ADDR}" VAULT_TOKEN="${VAULT_ROOT_TOKEN}" \
    vault kv put \
    "secret/database/redis" \
    "password=${MULTI_SOURCE_REDIS_ROTATED}"
success "Multi-source secrets rotated."

info "Waiting for multi-source rotation to propagate (20s)..."
sleep 20

info "Verifying rotated multi-source JSON secret..."
verify_secret_contains "${STACK_NAME}" "app" "app_credentials" "${MULTI_SOURCE_MYSQL_ROOT_ROTATED}" 60
verify_secret_contains "${STACK_NAME}" "app" "app_credentials" "${MULTI_SOURCE_MYSQL_USER_ROTATED}" 60
verify_secret_contains "${STACK_NAME}" "app" "app_credentials" "${MULTI_SOURCE_REDIS_ROTATED}" 60

info "Verifying rotated multi-source ENV secret..."
verify_secret_contains "${STACK_NAME}" "app" "app_credentials_env" "${MULTI_SOURCE_MYSQL_ROOT_ROTATED}" 60
verify_secret_contains "${STACK_NAME}" "app" "app_credentials_env" "${MULTI_SOURCE_REDIS_ROTATED}" 60

success "Vault smoke test PASSED (incl. multi-source)"
