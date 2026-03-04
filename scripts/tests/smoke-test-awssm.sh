#!/usr/bin/env bash

set -ex
SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd)"
REPO_ROOT="$(realpath -- "${SCRIPT_DIR}/../..")"
# shellcheck source=smoke-test-helper.sh
source "${SCRIPT_DIR}/smoke-test-helper.sh"

# Configuration
LOCALSTACK_CONTAINER="smoke-localstack"
LOCALSTACK_ENDPOINT="http://localhost:4566"
AWS_REGION="us-east-1"
AWS_ACCESS_KEY_ID="test"
AWS_SECRET_ACCESS_KEY="test"
STACK_NAME="smoke-awssm"
SECRET_NAME="smoke_secret"
SECRET_PATH="database/mysql"
SECRET_FIELD="password"
SECRET_VALUE="awssm-smoke-pass-v1"
SECRET_VALUE_ROTATED="awssm-smoke-pass-v2"
COMPOSE_FILE="${SCRIPT_DIR}/smoke-awssm-compose.yml"

# Helper to run awslocal either on host or inside container
awslocal_cmd() {
    if [ -n "${LOCALSTACK_CONTAINER}" ]; then
        docker exec "${LOCALSTACK_CONTAINER}" awslocal "$@"
    else
        AWS_ACCESS_KEY_ID="${AWS_ACCESS_KEY_ID}" \
        AWS_SECRET_ACCESS_KEY="${AWS_SECRET_ACCESS_KEY}" \
        AWS_DEFAULT_REGION="${AWS_REGION}" \
        awslocal "$@"
    fi
}

# Cleanup trap
cleanup() {
    echo -e "${RED}Running AWS Secrets Manager smoke test cleanup...${DEF}"
    remove_stack "${STACK_NAME}"
    docker secret rm "${SECRET_NAME}" 2>/dev/null || true
    if [ -n "${LOCALSTACK_CONTAINER}" ]; then
        docker stop "${LOCALSTACK_CONTAINER}" 2>/dev/null || true
        docker rm   "${LOCALSTACK_CONTAINER}" 2>/dev/null || true
    fi
    remove_plugin
}
trap cleanup EXIT

# Start LocalStack container (skip if already running, e.g. in CI)
if curl -s "${LOCALSTACK_ENDPOINT}/_localstack/health" >/dev/null 2>&1; then
    info "LocalStack already running, skipping container start."
    LOCALSTACK_CONTAINER=""
else
    info "Starting LocalStack container..."
    docker run -d \
        --name "${LOCALSTACK_CONTAINER}" \
        -p 4566:4566 \
        -e SERVICES=secretsmanager \
        localstack/localstack:latest
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

# Write test secret
info "Writing test secret to AWS Secrets Manager..."
awslocal_cmd secretsmanager create-secret \
    --region "${AWS_REGION}" \
    --name "${SECRET_PATH}" \
    --secret-string "{\"${SECRET_FIELD}\":\"${SECRET_VALUE}\"}"
success "Secret written: ${SECRET_PATH} ${SECRET_FIELD}=${SECRET_VALUE}"

# Build plugin
info "Building plugin and setting AWS Secrets Manager config..."
build_plugin
docker plugin disable "${PLUGIN_NAME}" --force 2>/dev/null || true
docker plugin set "${PLUGIN_NAME}" \
    SECRETS_PROVIDER="aws" \
    AWS_REGION="${AWS_REGION}" \
    AWS_ACCESS_KEY_ID="${AWS_ACCESS_KEY_ID}" \
    AWS_SECRET_ACCESS_KEY="${AWS_SECRET_ACCESS_KEY}" \
    AWS_ENDPOINT_URL="${LOCALSTACK_ENDPOINT}" \
    ENABLE_ROTATION="true" \
    ROTATION_INTERVAL="10s" \
    ENABLE_MONITORING="false"
success "Plugin configured with AWS Secrets Manager settings."

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
info "Rotating secret in AWS Secrets Manager..."
awslocal_cmd secretsmanager put-secret-value \
    --region "${AWS_REGION}" \
    --secret-id "${SECRET_PATH}" \
    --secret-string "{\"${SECRET_FIELD}\":\"${SECRET_VALUE_ROTATED}\"}"
success "Secret rotated to: ${SECRET_VALUE_ROTATED}"

info "Waiting for plugin rotation interval (15s)..."
sleep 30

info "Logging service output after rotation..."
log_stack "${STACK_NAME}" "app"

info "Verifying rotated secret value..."
verify_secret "${STACK_NAME}" "app" "${SECRET_NAME}" "${SECRET_VALUE_ROTATED}" 180

success "AWS Secrets Manager smoke test PASSED"
