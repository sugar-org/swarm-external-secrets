#!/usr/bin/env bash

# Kumo emulates STS, Secrets Manager, and KMS but does not validate the JWT
# signature or IAM trust policy. This test proves the managed-plugin socket
# mount, SPIRE attestation, JWT retrieval, STS exchange, secret read, KMS
# decryption with the assumed role, and rotation.
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd)"
REPO_ROOT="$(realpath -- "${SCRIPT_DIR}/../..")"
# shellcheck source=smoke-test-helper.sh
source "${SCRIPT_DIR}/smoke-test-helper.sh"

select_smoke_mode() {
    case "${AWS_SPIFFE_SMOKE_MODE:-auto}" in
        local)
            printf 'local'
            ;;
        aws | real)
            printf 'aws'
            ;;
        auto)
            local name
            for name in AWS_ROLE_ARN AWS_SECRET_ID AWS_OIDC_ISSUER_URL SPIFFE_SOCKET_SOURCE; do
                if [[ -n "${!name:-}" ]]; then
                    printf 'aws'
                    return
                fi
            done
            printf 'local'
            ;;
        *)
            die "AWS_SPIFFE_SMOKE_MODE must be auto, local, or aws."
            ;;
    esac
}

validate_real_aws_config() {
    local required=(
        AWS_REGION
        AWS_ROLE_ARN
        AWS_SECRET_ID
        AWS_OIDC_ISSUER_URL
        SPIFFE_SOCKET_SOURCE
        AWS_JWT_AUDIENCE
    )
    local missing=()
    local name

    for name in "${required[@]}"; do
        if [[ -z "${!name:-}" ]]; then
            missing+=("${name}")
        fi
    done

    if ((${#missing[@]} > 0)); then
        die "Real AWS mode is missing required variables: ${missing[*]}"
    fi
}

run_real_aws_smoke() {
    validate_real_aws_config

    AWS_SECRET_FIELD="${AWS_SECRET_FIELD:-}"
    SPIFFE_ENDPOINT_SOCKET="${SPIFFE_ENDPOINT_SOCKET:-unix:///run/host/api.sock}"
    STACK_NAME="smoke-awssm-spiffe-real"
    COMPOSE_FILE="${SCRIPT_DIR}/smoke-awssm-spiffe-real-compose.yml"
    export AWS_SECRET_FIELD AWS_SECRET_ID

    # Invoked indirectly by the EXIT trap.
    # shellcheck disable=SC2329
    real_cleanup() {
        remove_stack "${STACK_NAME}"
        docker secret rm aws_spiffe_real >/dev/null 2>&1 || true
        remove_plugin
    }
    trap real_cleanup EXIT

    [[ -S "${SPIFFE_SOCKET_SOURCE}/api.sock" ]] ||
        die "SPIRE Workload API socket not found at ${SPIFFE_SOCKET_SOURCE}/api.sock"

    local discovery_document
    local issuer
    discovery_document="$(curl -fsS "${AWS_OIDC_ISSUER_URL%/}/.well-known/openid-configuration")"
    issuer="$(printf '%s' "${discovery_document}" | jq -r '.issuer')"
    [[ "${issuer}" == "${AWS_OIDC_ISSUER_URL%/}" ]] ||
        die "OIDC discovery issuer ${issuer} does not match AWS_OIDC_ISSUER_URL"

    build_plugin
    docker plugin set "${PLUGIN_NAME}" \
        "spire-agent-socket.source=${SPIFFE_SOCKET_SOURCE}" \
        SECRETS_PROVIDER="aws" \
        AWS_REGION="${AWS_REGION}" \
        AWS_AUTH_METHOD="spiffe" \
        AWS_ROLE_ARN="${AWS_ROLE_ARN}" \
        AWS_JWT_AUDIENCE="${AWS_JWT_AUDIENCE}" \
        SPIFFE_ENDPOINT_SOCKET="${SPIFFE_ENDPOINT_SOCKET}" \
        ENABLE_ROTATION="false" \
        ENABLE_MONITORING="false"
    enable_plugin

    deploy_stack "${COMPOSE_FILE}" "${STACK_NAME}" 90

    local container_id
    container_id="$(get_running_container_id "${STACK_NAME}" "app")"
    [[ -n "${container_id}" ]] || die "Real-AWS validation task has no running container."
    docker exec "${container_id}" test -s /run/secrets/aws_spiffe_real ||
        die "AWS secret was not mounted or was empty."

    success "Real AWS SPIFFE/OIDC trust validation PASSED"
}

SMOKE_MODE="$(select_smoke_mode)"
if [[ "${SMOKE_MODE}" == "aws" ]]; then
    info "Selected real AWS mode."
    run_real_aws_smoke
    exit 0
fi
info "Selected local Kumo mode."

SPIRE_VERSION="${SPIRE_VERSION:-1.15.2}"
SPIRE_SERVER_IMAGE="ghcr.io/spiffe/spire-server:${SPIRE_VERSION}"
SPIRE_AGENT_IMAGE="ghcr.io/spiffe/spire-agent:${SPIRE_VERSION}"
KUMO_IMAGE="${KUMO_IMAGE:-ghcr.io/sivchari/kumo@sha256:e0c98c28ba2de1f873a0a97e918d79cd778b94af2f15329e3ead14c82c7e30ae}"
SPIRE_SERVER_CONTAINER="smoke-spire-server"
SPIRE_AGENT_CONTAINER="smoke-spire-agent"
SPIRE_NETWORK="smoke-spiffe"
KUMO_CONTAINER="smoke-kumo-spiffe"
KUMO_ENDPOINT="http://localhost:4566"
AWS_REGION="us-east-1"
AWS_ROLE_ARN="arn:aws:iam::000000000000:role/swarm-external-secrets-spiffe-smoke"
STACK_NAME="smoke-awssm-spiffe"
SECRET_NAME="smoke_secret"
SECRET_PATH="database/mysql"
SECRET_FIELD="password"
SECRET_VALUE="awssm-spiffe-smoke-pass-v1"
SECRET_VALUE_ROTATED="awssm-spiffe-smoke-pass-v2"
COMPOSE_FILE="${SCRIPT_DIR}/smoke-awssm-compose.yml"
STATE_DIR="$(mktemp -d)"
SPIRE_SOCKET_DIR="/run/swarm-external-secrets-spire-smoke"
SPIRE_BOOTSTRAP_DIR="${STATE_DIR}/bootstrap"

mkdir -p "${SPIRE_BOOTSTRAP_DIR}"
chmod 0755 "${STATE_DIR}" "${SPIRE_BOOTSTRAP_DIR}"

docker run --rm -v /run:/host-run alpine:latest mkdir -p \
    /host-run/swarm-external-secrets \
    /host-run/swarm-external-secrets-spire-smoke
docker run --rm -v /run:/host-run alpine:latest \
    chmod 0777 /host-run/swarm-external-secrets-spire-smoke

aws_cmd() {
    AWS_ACCESS_KEY_ID="test" \
        AWS_SECRET_ACCESS_KEY="test" \
        AWS_DEFAULT_REGION="${AWS_REGION}" \
        aws --endpoint-url "${KUMO_ENDPOINT}" "$@"
}

cleanup() {
    info "Running AWS SPIFFE smoke test cleanup..."
    remove_stack "${STACK_NAME}"
    docker secret rm "${SECRET_NAME}" >/dev/null 2>&1 || true
    aws_cmd secretsmanager delete-secret \
        --region "${AWS_REGION}" \
        --secret-id "${SECRET_PATH}" \
        --force-delete-without-recovery >/dev/null 2>&1 || true
    docker rm -f \
        "${SPIRE_AGENT_CONTAINER}" \
        "${SPIRE_SERVER_CONTAINER}" >/dev/null 2>&1 || true
    if [[ -n "${KUMO_CONTAINER}" ]]; then
        docker rm -f "${KUMO_CONTAINER}" >/dev/null 2>&1 || true
    fi
    docker network rm "${SPIRE_NETWORK}" >/dev/null 2>&1 || true
    docker run --rm -v /run:/host-run alpine:latest \
        rm -rf /host-run/swarm-external-secrets-spire-smoke >/dev/null 2>&1 || true
    remove_plugin
    rm -rf "${STATE_DIR}"
}
trap cleanup EXIT

if curl -fsS "${KUMO_ENDPOINT}/health" >/dev/null 2>&1; then
    info "Using the existing Kumo instance."
    KUMO_CONTAINER=""
else
    info "Starting Kumo with STS and Secrets Manager..."
    docker run -d \
        --name "${KUMO_CONTAINER}" \
        -p 4566:4566 \
        "${KUMO_IMAGE}" >/dev/null
fi

info "Waiting for Kumo..."
elapsed=0
until curl -fsS "${KUMO_ENDPOINT}/health" >/dev/null 2>&1; do
    sleep 2
    elapsed=$((elapsed + 2))
    [[ "${elapsed}" -lt 60 ]] || die "Kumo did not become ready within 60s."
done

docker network create "${SPIRE_NETWORK}" >/dev/null

info "Starting the SPIRE Server..."
docker run -d \
    --name "${SPIRE_SERVER_CONTAINER}" \
    --network "${SPIRE_NETWORK}" \
    --entrypoint /opt/spire/bin/spire-server \
    -v "${SCRIPT_DIR}/spire/server.conf:/opt/spire/conf/server/server.conf:ro" \
    "${SPIRE_SERVER_IMAGE}" \
    run -config /opt/spire/conf/server/server.conf >/dev/null

info "Waiting for the SPIRE Server API..."
elapsed=0
until docker exec "${SPIRE_SERVER_CONTAINER}" \
    /opt/spire/bin/spire-server healthcheck \
    -socketPath /tmp/spire-server/private/api.sock >/dev/null 2>&1; do
    sleep 2
    elapsed=$((elapsed + 2))
    [[ "${elapsed}" -lt 60 ]] || die "SPIRE Server did not become ready within 60s."
done

docker exec "${SPIRE_SERVER_CONTAINER}" \
    /opt/spire/bin/spire-server bundle show \
    -socketPath /tmp/spire-server/private/api.sock \
    -format pem >"${SPIRE_BOOTSTRAP_DIR}/bootstrap.crt"

docker exec "${SPIRE_SERVER_CONTAINER}" \
    /opt/spire/bin/spire-server token generate \
    -socketPath /tmp/spire-server/private/api.sock \
    -spiffeID spiffe://example.org/agent/swarm-smoke \
    -output json |
    jq -r '.value' >"${SPIRE_BOOTSTRAP_DIR}/join-token"

[[ -s "${SPIRE_BOOTSTRAP_DIR}/join-token" ]] || die "SPIRE Server did not issue a join token."
chmod 0644 "${SPIRE_BOOTSTRAP_DIR}/bootstrap.crt" "${SPIRE_BOOTSTRAP_DIR}/join-token"

info "Starting the node-level SPIRE Agent..."
docker run -d \
    --name "${SPIRE_AGENT_CONTAINER}" \
    --network "${SPIRE_NETWORK}" \
    --pid host \
    --entrypoint /opt/spire/bin/spire-agent \
    -v "${SCRIPT_DIR}/spire/agent.conf:/opt/spire/conf/agent/agent.conf:ro" \
    -v "${SPIRE_SOCKET_DIR}:/run/spire/agent-sockets" \
    -v "${SPIRE_BOOTSTRAP_DIR}:/run/spire/bootstrap:ro" \
    "${SPIRE_AGENT_IMAGE}" \
    run -config /opt/spire/conf/agent/agent.conf >/dev/null

info "Waiting for the SPIRE Workload API socket..."
elapsed=0
until docker run --rm -v "${SPIRE_SOCKET_DIR}:/socket:ro" alpine:latest \
    test -S /socket/api.sock >/dev/null 2>&1; do
    sleep 2
    elapsed=$((elapsed + 2))
    [[ "${elapsed}" -lt 60 ]] || die "SPIRE Agent did not create its Workload API socket within 60s."
done

# UID-only selection is intentionally limited to this disposable smoke test.
# Production deployments must use a stronger selector such as unix:sha256.
docker exec "${SPIRE_SERVER_CONTAINER}" \
    /opt/spire/bin/spire-server entry create \
    -socketPath /tmp/spire-server/private/api.sock \
    -parentID spiffe://example.org/agent/swarm-smoke \
    -spiffeID spiffe://example.org/swarm-external-secrets \
    -selector unix:uid:0 >/dev/null

# smoke-awssm-compose.yml sets kms_decrypt=true, so the plugin's KMS client must
# reuse the SPIFFE-assumed role credentials to read these values.
KMS_KEY_ID="$(aws_cmd kms create-key \
    --region "${AWS_REGION}" \
    --query 'KeyMetadata.KeyId' \
    --output text)"

encrypt_with_kms() {
    aws_cmd kms encrypt \
        --region "${AWS_REGION}" \
        --key-id "${KMS_KEY_ID}" \
        --plaintext "$1" \
        --cli-binary-format raw-in-base64-out \
        --query 'CiphertextBlob' \
        --output text
}

aws_cmd secretsmanager create-secret \
    --region "${AWS_REGION}" \
    --name "${SECRET_PATH}" \
    --secret-string "{\"${SECRET_FIELD}\":\"$(encrypt_with_kms "${SECRET_VALUE}")\"}" >/dev/null

info "Building and configuring the managed plugin for SPIFFE authentication..."
build_plugin
docker plugin set "${PLUGIN_NAME}" \
    "spire-agent-socket.source=${SPIRE_SOCKET_DIR}" \
    SECRETS_PROVIDER="aws" \
    AWS_REGION="${AWS_REGION}" \
    AWS_AUTH_METHOD="spiffe" \
    AWS_ROLE_ARN="${AWS_ROLE_ARN}" \
    AWS_JWT_AUDIENCE="000000000000" \
    SPIFFE_ENDPOINT_SOCKET="unix:///run/host/api.sock" \
    AWS_ENDPOINT_URL="${KUMO_ENDPOINT}" \
    AWS_STS_ENDPOINT_URL="${KUMO_ENDPOINT}" \
    ENABLE_ROTATION="true" \
    ROTATION_INTERVAL="10s" \
    ENABLE_MONITORING="false"
enable_plugin

deploy_stack "${COMPOSE_FILE}" "${STACK_NAME}" 60
verify_secret "${STACK_NAME}" "app" "${SECRET_NAME}" "${SECRET_VALUE}" 90

aws_cmd secretsmanager update-secret \
    --region "${AWS_REGION}" \
    --secret-id "${SECRET_PATH}" \
    --secret-string "{\"${SECRET_FIELD}\":\"$(encrypt_with_kms "${SECRET_VALUE_ROTATED}")\"}" >/dev/null

verify_secret "${STACK_NAME}" "app" "${SECRET_NAME}" "${SECRET_VALUE_ROTATED}" 180
assert_no_sensitive_rotation_metadata_logs
success "AWS SPIFFE/OIDC smoke test PASSED"
