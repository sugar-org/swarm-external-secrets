#!/usr/bin/env bash

set -ex

SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd)"
REPO_ROOT="$(realpath -- "${SCRIPT_DIR}/../..")"

# shellcheck source=smoke-test-helper.sh disable=SC1091
source "${SCRIPT_DIR}/smoke-test-helper.sh"

# Configuration
VAULT_CONTAINER="smoke-vault-b64"
VAULT_ROOT_TOKEN="smoke-root-token"
VAULT_ADDR="http://127.0.0.1:8200"
POLICY_FILE="${REPO_ROOT}/vault_conf/admin.hcl"

STACK_NAME="smoke-vault-b64"
STACK_NAME_INVALID="smoke-vault-b64-inv"
SECRET_PATH="database/credentials"

RAW_VALUE="hello-base64"
BASE64_VALUE="aGVsbG8tYmFzZTY0"
INVALID_VALUE="invalid-base64-payload-not-b64!@#$"

TEST_DIR="$(mktemp -d)"
COMPOSE_FILE_VALID="${TEST_DIR}/compose-valid.yml"
COMPOSE_FILE_INVALID="${TEST_DIR}/compose-invalid.yml"

EXIT_CODE=0

# Cleanup trap
cleanup() {
    local rc=$?
    if [[ "${EXIT_CODE}" -ne 0 ]]; then
        rc="${EXIT_CODE}"
    fi
    echo -e "${RED}Running base64 decode smoke test cleanup...${DEF}"
    remove_stack "${STACK_NAME_INVALID}" 2>/dev/null || true
    remove_stack "${STACK_NAME}" 2>/dev/null || true
    docker secret rm "${STACK_NAME}_secret_b64_decoded" 2>/dev/null || true
    docker secret rm "${STACK_NAME}_secret_b64_plain" 2>/dev/null || true
    docker secret rm "${STACK_NAME}_secret_b64_ws" 2>/dev/null || true
    docker secret rm "${STACK_NAME_INVALID}_secret_b64_invalid" 2>/dev/null || true
    docker stop "${VAULT_CONTAINER}" 2>/dev/null || true
    docker rm   "${VAULT_CONTAINER}" 2>/dev/null || true
    remove_plugin
    if [[ -n "${TEST_DIR:-}" && -d "${TEST_DIR}" ]]; then
        rm -rf "${TEST_DIR}"
    fi
    exit "${rc}"
}
trap cleanup EXIT

# Start HashiCorp Vault dev container
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

# Write test secrets to Vault
info "Writing test secrets to Vault..."
docker exec "${VAULT_CONTAINER}" \
    env VAULT_ADDR="${VAULT_ADDR}" VAULT_TOKEN="${VAULT_ROOT_TOKEN}" \
    vault kv put \
    "secret/${SECRET_PATH}" \
    "payload=${BASE64_VALUE}" \
    "whitespace_payload=  ${BASE64_VALUE}  " \
    "invalid_payload=${INVALID_VALUE}"
success "Secrets written to secret/${SECRET_PATH}."

# Get auth token from Vault
info "Getting auth token from Vault..."
VAULT_TOKEN=$(docker exec "${VAULT_CONTAINER}" \
    env VAULT_ADDR="${VAULT_ADDR}" VAULT_TOKEN="${VAULT_ROOT_TOKEN}" \
    vault token create \
        -policy="smoke-policy" \
        -field=token)
success "Got auth token."

# Build plugin and set Vault configuration
info "Building plugin and configuring Vault provider..."
build_plugin

docker plugin set "${PLUGIN_NAME}" \
    SECRETS_PROVIDER="vault" \
    VAULT_ADDR="${VAULT_ADDR}" \
    VAULT_AUTH_METHOD="token" \
    VAULT_TOKEN="${VAULT_TOKEN}" \
    VAULT_MOUNT_PATH="secret" \
    ENABLE_ROTATION="false" \
    ENABLE_MONITORING="false"
success "Plugin configured with Vault token."

# Enable plugin
info "Enabling plugin..."
enable_plugin

# Write valid test compose file
cat <<EOF > "${COMPOSE_FILE_VALID}"
version: '3.8'

services:
  app:
    image: busybox:latest
    command: >
      sh -c "
        while true; do
          sleep 5
        done
      "
    secrets:
      - secret_b64_decoded
      - secret_b64_plain
      - secret_b64_ws
    deploy:
      replicas: 1
      restart_policy:
        condition: any
    networks:
      - smoke-network

secrets:
  secret_b64_decoded:
    driver: ${PLUGIN_NAME}
    labels:
      vault_path: "${SECRET_PATH}"
      vault_field: "payload"
      base64_decode: "true"
  secret_b64_plain:
    driver: ${PLUGIN_NAME}
    labels:
      vault_path: "${SECRET_PATH}"
      vault_field: "payload"
      base64_decode: "false"
  secret_b64_ws:
    driver: ${PLUGIN_NAME}
    labels:
      vault_path: "${SECRET_PATH}"
      vault_field: "whitespace_payload"
      base64_decode: "true"

networks:
  smoke-network:
    driver: overlay
EOF

# Deploy valid swarm stack
info "Deploying valid base64 test stack..."
deploy_stack "${COMPOSE_FILE_VALID}" "${STACK_NAME}" 60

# Retrieve running container ID
info "Retrieving running container ID..."
APP_CONTAINER_ID=$(get_running_container_id "${STACK_NAME}" "app")
[[ -n "${APP_CONTAINER_ID}" ]] || die "Failed to get running container ID for stack '${STACK_NAME}'"

# Case 1: secret with base64_decode=true is delivered decoded
info "Verifying Case 1: secret with base64_decode=true is delivered decoded..."
ACTUAL_DECODED=$(docker exec "${APP_CONTAINER_ID}" cat /run/secrets/secret_b64_decoded 2>/dev/null || true)
if [[ "${ACTUAL_DECODED}" == "${RAW_VALUE}" ]]; then
    success "Case 1 PASS: secret with base64_decode=true delivered decoded value '${ACTUAL_DECODED}'"
else
    die "Case 1 FAIL: expected '${RAW_VALUE}', got '${ACTUAL_DECODED}'"
fi

# Case 2: secret with base64_decode=false is delivered unchanged as raw base64 (opt-in verified)
info "Verifying Case 2: secret with base64_decode=false is delivered unchanged as raw base64..."
ACTUAL_PLAIN=$(docker exec "${APP_CONTAINER_ID}" cat /run/secrets/secret_b64_plain 2>/dev/null || true)
if [[ "${ACTUAL_PLAIN}" == "${BASE64_VALUE}" ]]; then
    success "Case 2 PASS: secret with base64_decode=false delivered raw base64 value '${ACTUAL_PLAIN}' (opt-in verified)"
else
    die "Case 2 FAIL: expected '${BASE64_VALUE}', got '${ACTUAL_PLAIN}'"
fi

# Optional Case: secret with surrounding whitespace is decoded correctly
info "Verifying Optional Case: secret with surrounding whitespace is decoded correctly..."
ACTUAL_WS=$(docker exec "${APP_CONTAINER_ID}" cat /run/secrets/secret_b64_ws 2>/dev/null || true)
if [[ "${ACTUAL_WS}" == "${RAW_VALUE}" ]]; then
    success "Optional Case PASS: secret with surrounding whitespace decoded correctly to '${ACTUAL_WS}'"
else
    die "Optional Case FAIL: expected '${RAW_VALUE}', got '${ACTUAL_WS}'"
fi

# Clean up valid stack
info "Removing valid test stack..."
remove_stack "${STACK_NAME}"

# Write invalid test compose file
cat <<EOF > "${COMPOSE_FILE_INVALID}"
version: '3.8'

services:
  invalid_app:
    image: busybox:latest
    command: >
      sh -c "
        while true; do
          sleep 5
        done
      "
    secrets:
      - secret_b64_invalid
    deploy:
      replicas: 1
      restart_policy:
        condition: none
    networks:
      - smoke-network-inv

secrets:
  secret_b64_invalid:
    driver: ${PLUGIN_NAME}
    labels:
      vault_path: "${SECRET_PATH}"
      vault_field: "invalid_payload"
      base64_decode: "true"

networks:
  smoke-network-inv:
    driver: overlay
EOF

# Deploy invalid stack to test failure behavior
info "Deploying stack with invalid base64 secret to verify Case 3..."
docker stack deploy -c "${COMPOSE_FILE_INVALID}" "${STACK_NAME_INVALID}"

info "Waiting for service '${STACK_NAME_INVALID}_invalid_app' to fail due to invalid base64..."
elapsed=0
saw_error=0
error_details=""

while [ "${elapsed}" -lt 60 ]; do
    task_err=$(docker service ps "${STACK_NAME_INVALID}_invalid_app" --no-trunc --format '{{.Error}}' 2>/dev/null || true)
    daemon_err=$(docker_daemon_logs 2>/dev/null || true)

    if echo "${task_err}" | grep -qi "base64"; then
        saw_error=1
        error_details="${task_err}"
        break
    fi

    if echo "${daemon_err}" | grep -q "failed to base64-decode secret"; then
        saw_error=1
        error_details=$(echo "${daemon_err}" | grep "failed to base64-decode secret" | tail -1)
        break
    fi

    sleep 2
    elapsed=$((elapsed + 2))
done

# Confirm the service container NEVER reached Running state
running_count=$(docker stack ps "${STACK_NAME_INVALID}" \
    --filter "desired-state=running" \
    --format '{{.CurrentState}}' 2>/dev/null \
    | grep -c "Running" || true)

if [ "${running_count}" -gt 0 ]; then
    die "Case 3 FAIL: service with invalid base64 unexpectedly reached running state"
fi

if [ "${saw_error}" -eq 0 ]; then
    info "Service ps diagnostics:"
    docker service ps "${STACK_NAME_INVALID}_invalid_app" --no-trunc || true
    die "Case 3 FAIL: service did not report base64 decode error within 60s"
fi

# Confirm error output does NOT leak the invalid secret value
combined_error_output="${error_details} $(docker_daemon_logs 2>/dev/null || true)"
if echo "${combined_error_output}" | grep -Fq "${INVALID_VALUE}"; then
    die "Case 3 FAIL: error output leaked secret value '${INVALID_VALUE}'"
fi

success "Case 3 PASS: invalid base64 secret failed clearly without leaking secret value (error: ${error_details})"

# Clean up invalid stack
info "Removing invalid test stack..."
remove_stack "${STACK_NAME_INVALID}"

success "All base64 decode smoke tests PASSED"
