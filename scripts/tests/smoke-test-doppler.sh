#!/usr/bin/env bash

set -ex
SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd)"
REPO_ROOT="$(realpath -- "${SCRIPT_DIR}/../..")"

# shellcheck source=smoke-test-helper.sh
source "${SCRIPT_DIR}/smoke-test-helper.sh"

# Backend selection:
#   - If DOPPLER_SMOKE_TOKEN is set, run against real Doppler (api.doppler.com)
#     using a service token with read/write access to a dedicated smoke-tests
#     config. Secrets are seeded/rotated via the Doppler REST API.
#   - Otherwise, fall back to the local Go mock server (no account needed),
#     mirroring how the AWS smoke test skips LocalStack when it is already up.
export DOPPLER_SMOKE_TOKEN="${DOPPLER_SMOKE_TOKEN:-}"
export DOPPLER_API_URL="${DOPPLER_API_URL:-https://api.doppler.com}"
export DOPPLER_PROJECT="${DOPPLER_PROJECT:-}"
export DOPPLER_CONFIG="${DOPPLER_CONFIG:-}"
export DOPPLER_MOCK_URL="http://127.0.0.1:18080"
export DOPPLER_MOCK_TOKEN="dp.st.smoke-test"

# Common configuration
STACK_NAME="smoke-doppler"
SECRET_NAME="smoke_secret"
COMPOSE_FILE="$(mktemp -t smoke-doppler-compose.XXXXXX.yml)"

# Unique per-run key so concurrent CI runs never stomp each other's secret.
RUN_ID="$(printf '%s_%s' "${GITHUB_RUN_ID:-local}" "${GITHUB_RUN_ATTEMPT:-1}" \
    | tr -cd '[:alnum:]_' | tr '[:lower:]' '[:upper:]')"
SECRET_KEY="SMOKE_TEST_PASSWORD_${RUN_ID}"
SECRET_VALUE="doppler-smoke-pass-v1-${RUN_ID}"
SECRET_VALUE_ROTATED="doppler-smoke-pass-v2-${RUN_ID}"

MOCK_SERVER_PID=""
EXIT_CODE=0

doppler_init_backend

cleanup() {
    echo -e "${RED}Running Doppler smoke test cleanup...${DEF}"
    remove_stack "${STACK_NAME}"
    docker secret rm "${SECRET_NAME}" 2>/dev/null || true
    doppler_delete_secret "${SECRET_KEY}"
    if [[ -n "${MOCK_SERVER_PID}" ]]; then
        kill "${MOCK_SERVER_PID}" 2>/dev/null || true
        wait "${MOCK_SERVER_PID}" 2>/dev/null || true
    fi
    rm -f "${COMPOSE_FILE}"
    remove_plugin
    exit "${EXIT_CODE}"
}
trap cleanup EXIT

info "Doppler smoke test running in '${DOPPLER_MODE}' mode."

write_doppler_compose "${COMPOSE_FILE}" "${SECRET_NAME}" "${SECRET_KEY}"

if [[ "${DOPPLER_MODE}" == "mock" ]]; then
    info "Starting Doppler API mock server..."
    go run "${REPO_ROOT}/scripts/tests/mock-doppler-server" --token "${DOPPLER_MOCK_TOKEN}" &
    MOCK_SERVER_PID=$!

    elapsed=0
    until curl -fsS \
        -H "Authorization: Bearer ${DOPPLER_MOCK_TOKEN}" \
        "${DOPPLER_MOCK_URL}/v3/configs/config/secrets/download?format=json" >/dev/null; do
        sleep 1
        elapsed=$((elapsed + 1))
        [[ "${elapsed}" -lt 15 ]] || die "Doppler mock server did not become ready within 15s."
    done
    success "Doppler mock server is ready."
fi

info "Seeding secret ${SECRET_KEY}..."
doppler_seed_secret "${SECRET_KEY}" "${SECRET_VALUE}"
doppler_wait_readable "${SECRET_VALUE}" 30
success "Secret ${SECRET_KEY} is readable."

info "Building plugin and setting Doppler config..."
build_plugin

docker plugin set "${PLUGIN_NAME}" \
    SECRETS_PROVIDER="doppler" \
    DOPPLER_TOKEN="${DOPPLER_PLUGIN_TOKEN}" \
    DOPPLER_API_URL="${DOPPLER_PLUGIN_API_URL}" \
    DOPPLER_PROJECT="${DOPPLER_PROJECT}" \
    DOPPLER_CONFIG="${DOPPLER_CONFIG}" \
    DOPPLER_CACHE_TTL="5s" \
    ENABLE_ROTATION="true" \
    ROTATION_INTERVAL="10s" \
    ENABLE_MONITORING="false"
success "Plugin configured with Doppler settings."

info "Enabling plugin..."
enable_plugin

info "Deploying swarm stack..."
deploy_stack "${COMPOSE_FILE}" "${STACK_NAME}" 60

info "Logging service output..."
sleep 10
log_stack "${STACK_NAME}" "app"
assert_no_sensitive_rotation_metadata_logs

info "Verifying secret value matches expected password..."
verify_secret "${STACK_NAME}" "app" "${SECRET_NAME}" "${SECRET_VALUE}" 60

info "Rotating secret in Doppler (${DOPPLER_MODE})..."
doppler_seed_secret "${SECRET_KEY}" "${SECRET_VALUE_ROTATED}"
success "Secret rotated to: ${SECRET_VALUE_ROTATED}"

info "Waiting for plugin rotation interval (15s)..."
sleep 15

info "Logging service output after rotation..."
log_stack "${STACK_NAME}" "app"
assert_no_sensitive_rotation_metadata_logs

info "Verifying rotated secret value..."
verify_secret "${STACK_NAME}" "app" "${SECRET_NAME}" "${SECRET_VALUE_ROTATED}" 180

success "Doppler smoke test PASSED (${DOPPLER_MODE} mode)"
