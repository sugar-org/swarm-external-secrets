#!/usr/bin/env bash

set -ex

SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd)"
REPO_ROOT="$(realpath -- "${SCRIPT_DIR}/../..")"

# shellcheck source=smoke-test-helper.sh
source "${SCRIPT_DIR}/smoke-test-helper.sh"

OPENBAO_CONTAINER="smoke-openbao-jwt"
OPENBAO_ROOT_TOKEN="smoke-root-token"
OPENBAO_ADDR="http://127.0.0.1:8200"
STACK_NAME="smoke-openbao-jwt"
SECRET_NAME="smoke_secret"
SECRET_PATH="database/mysql"
SECRET_FIELD="password"
SECRET_VALUE="openbao-jwt-smoke-pass-v1"
COMPOSE_FILE="${SCRIPT_DIR}/smoke-openbao-compose.yml"
POLICY_FILE="${REPO_ROOT}/vault_conf/admin.hcl"
JWT_WORKDIR="$(mktemp -d)"
JWT_ROLE="swarm-external-secrets"
JWT_TOKEN_TTL="10s"
JWT_TOKEN_MAX_TTL="25s"
RENEWAL_WAIT_SECONDS=45
LOG_EXPORT_DIR="${REPO_ROOT}/.tmp/smoke-openbao-jwt"
PLUGIN_LOG_PATH="/run/swarm-external-secrets/plugin.log"
PLUGIN_LOG_EXPORT="${LOG_EXPORT_DIR}/plugin.log"
DAEMON_LOG_EXPORT="${LOG_EXPORT_DIR}/docker-daemon.log"
EXIT_CODE=0

base64url() {
    openssl base64 -A | tr '+/' '-_' | tr -d '='
}

generate_local_jwt() {
    openssl genrsa -out "${JWT_WORKDIR}/jwt-private.pem" 2048 >/dev/null 2>&1
    openssl rsa -in "${JWT_WORKDIR}/jwt-private.pem" -pubout -out "${JWT_WORKDIR}/jwt-public.pem" >/dev/null 2>&1

    local header payload unsigned signature
    header="$(printf '{"alg":"RS256","typ":"JWT"}' | base64url)"
    payload="$(printf '{"iss":"swarm-external-secrets-local","sub":"swarm-external-secrets","aud":"vault"}' | base64url)"
    unsigned="${header}.${payload}"
    signature="$(printf '%s' "${unsigned}" | openssl dgst -sha256 -sign "${JWT_WORKDIR}/jwt-private.pem" -binary | base64url)"
    printf '%s.%s\n' "${unsigned}" "${signature}" > "${JWT_WORKDIR}/workload.jwt"
}

prepare_plugin_log_path() {
    mkdir -p "${LOG_EXPORT_DIR}"
    : > "${PLUGIN_LOG_EXPORT}"

    if [[ "$(uname -s)" = "Darwin" ]]; then
        info "Preparing plugin log path inside Docker Desktop VM..."
        docker run --rm --privileged --pid=host justincormack/nsenter1 \
            sh -lc "mkdir -p /run/swarm-external-secrets && touch '${PLUGIN_LOG_PATH}' && chmod -R 777 /run/swarm-external-secrets"
        return
    fi

    info "Preparing plugin log path on Linux host..."
    if [[ "$(id -u)" -eq 0 ]]; then
        mkdir -p /run/swarm-external-secrets
        touch "${PLUGIN_LOG_PATH}"
    else
        sudo mkdir -p /run/swarm-external-secrets
        sudo touch "${PLUGIN_LOG_PATH}"
    fi
}

export_plugin_logs() {
    mkdir -p "${LOG_EXPORT_DIR}"

    if [[ "$(uname -s)" = "Darwin" ]]; then
        docker run --rm --privileged --pid=host justincormack/nsenter1 \
            sh -lc "cat '${PLUGIN_LOG_PATH}' 2>/dev/null" > "${PLUGIN_LOG_EXPORT}" || true
    elif [[ -r "${PLUGIN_LOG_PATH}" ]]; then
        cp "${PLUGIN_LOG_PATH}" "${PLUGIN_LOG_EXPORT}" || true
    elif command -v sudo >/dev/null 2>&1; then
        sudo cp "${PLUGIN_LOG_PATH}" "${PLUGIN_LOG_EXPORT}" 2>/dev/null || true
        sudo chown "$(id -u):$(id -g)" "${PLUGIN_LOG_EXPORT}" 2>/dev/null || true
    fi

    docker_daemon_logs > "${DAEMON_LOG_EXPORT}" || true
    info "Exported plugin logs to: ${PLUGIN_LOG_EXPORT}"
    info "Exported Docker daemon logs to: ${DAEMON_LOG_EXPORT}"
}

assert_log_contains_any() {
    local description="$1"
    shift

    export_plugin_logs
    local logs
    logs="$(cat "${PLUGIN_LOG_EXPORT}" "${DAEMON_LOG_EXPORT}" 2>/dev/null || true)"

    for expected in "$@"; do
        if echo "${logs}" | grep -Fq "${expected}"; then
            success "${description}: found '${expected}'"
            return
        fi
    done

    die "${description}: expected one of [$*]. See exported logs in ${LOG_EXPORT_DIR}"
}

cleanup() {
    EXIT_CODE=$?
    set +e
    echo -e "${RED}Running OpenBao JWT smoke test cleanup...${DEF}"
    export_plugin_logs
    remove_stack "${STACK_NAME}"
    docker secret rm "${SECRET_NAME}" 2>/dev/null || true
    docker stop "${OPENBAO_CONTAINER}" 2>/dev/null || true
    docker rm   "${OPENBAO_CONTAINER}" 2>/dev/null || true
    rm -rf "${JWT_WORKDIR}"
    remove_plugin
    exit "${EXIT_CODE}"
}
trap cleanup EXIT

prepare_plugin_log_path

info "Starting OpenBao dev container..."
docker run -d \
    --name "${OPENBAO_CONTAINER}" \
    -p 8200:8200 \
    -e "BAO_DEV_ROOT_TOKEN_ID=${OPENBAO_ROOT_TOKEN}" \
    quay.io/openbao/openbao:latest server -dev

info "Waiting for OpenBao to be ready..."
elapsed=0
until docker exec "${OPENBAO_CONTAINER}" bao status -address="${OPENBAO_ADDR}" >/dev/null 2>&1; do
    sleep 2
    elapsed=$((elapsed + 2))
    [[ "${elapsed}" -lt 30 ]] || die "OpenBao did not become ready within 30s."
done
success "OpenBao is ready."

info "Applying policy to OpenBao..."
copy_jwt_smoke_policy "${OPENBAO_CONTAINER}" "${POLICY_FILE}"
docker exec "${OPENBAO_CONTAINER}" \
    env BAO_ADDR="${OPENBAO_ADDR}" BAO_TOKEN="${OPENBAO_ROOT_TOKEN}" \
    bao policy write smoke-policy /tmp/admin.hcl
success "Policy applied."

info "Writing test secret to OpenBao..."
docker exec "${OPENBAO_CONTAINER}" \
    env BAO_ADDR="${OPENBAO_ADDR}" BAO_TOKEN="${OPENBAO_ROOT_TOKEN}" \
    bao kv put \
    "secret/${SECRET_PATH}" \
    "${SECRET_FIELD}=${SECRET_VALUE}"
success "Secret written."

info "Generating local JWT signing keys and signed JWT..."
generate_local_jwt
docker cp "${JWT_WORKDIR}/jwt-public.pem" "${OPENBAO_CONTAINER}:/tmp/jwt-public.pem"

info "Configuring OpenBao JWT auth..."
docker exec "${OPENBAO_CONTAINER}" \
    env BAO_ADDR="${OPENBAO_ADDR}" BAO_TOKEN="${OPENBAO_ROOT_TOKEN}" \
    bao auth enable jwt
docker exec "${OPENBAO_CONTAINER}" \
    env BAO_ADDR="${OPENBAO_ADDR}" BAO_TOKEN="${OPENBAO_ROOT_TOKEN}" \
    bao write auth/jwt/config \
        jwt_validation_pubkeys=@/tmp/jwt-public.pem \
        bound_issuer="swarm-external-secrets-local"
docker exec "${OPENBAO_CONTAINER}" \
    env BAO_ADDR="${OPENBAO_ADDR}" BAO_TOKEN="${OPENBAO_ROOT_TOKEN}" \
    bao write "auth/jwt/role/${JWT_ROLE}" \
        role_type="jwt" \
        user_claim="sub" \
        bound_audiences="vault" \
        bound_subject="swarm-external-secrets" \
        policies="smoke-policy" \
        ttl="${JWT_TOKEN_TTL}" \
        max_ttl="${JWT_TOKEN_MAX_TTL}"
success "OpenBao JWT auth configured."

WORKLOAD_JWT="$(tr -d '\n' < "${JWT_WORKDIR}/workload.jwt")"

info "Building plugin and configuring JWT auth..."
build_plugin

docker plugin set "${PLUGIN_NAME}" \
    SECRETS_PROVIDER="openbao" \
    OPENBAO_ADDR="${OPENBAO_ADDR}" \
    OPENBAO_AUTH_METHOD="jwt" \
    OPENBAO_JWT_ROLE="${JWT_ROLE}" \
    OPENBAO_JWT="${WORKLOAD_JWT}" \
    OPENBAO_JWT_AUTH_PATH="jwt" \
    OPENBAO_MOUNT_PATH="secret" \
    ENABLE_ROTATION="false" \
    ENABLE_MONITORING="false" \
    LOG_LEVEL="debug" \
    PLUGIN_LOG_PATH="${PLUGIN_LOG_PATH}"
success "Plugin configured with OpenBao JWT auth."

info "Enabling plugin..."
enable_plugin

info "Deploying swarm stack..."
deploy_stack "${COMPOSE_FILE}" "${STACK_NAME}" 60

info "Verifying secret value matches expected password..."
verify_secret "${STACK_NAME}" "app" "${SECRET_NAME}" "${SECRET_VALUE}" 60

info "Waiting ${RENEWAL_WAIT_SECONDS}s for JWT token renewal and max-TTL re-auth paths..."
sleep "${RENEWAL_WAIT_SECONDS}"
export_plugin_logs

assert_log_contains_any \
    "JWT renewal path" \
    "Successfully renewed openbao token"

assert_log_contains_any \
    "JWT re-auth fallback path" \
    "Renewing openbao token failed, attempting re-authentication" \
    "Successfully re-authenticated with openbao"

info "Re-deploying stack to prove reads still work after original token max TTL..."
remove_stack "${STACK_NAME}"
docker secret rm "${SECRET_NAME}" 2>/dev/null || true
deploy_stack "${COMPOSE_FILE}" "${STACK_NAME}" 60
verify_secret "${STACK_NAME}" "app" "${SECRET_NAME}" "${SECRET_VALUE}" 60

success "OpenBao JWT smoke test PASSED"
