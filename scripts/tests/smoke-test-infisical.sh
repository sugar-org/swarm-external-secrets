#!/usr/bin/env bash
# Infisical smoke test with a disposable local instance by default.
#
# External mode (INFISICAL_SMOKE_EXTERNAL=true) requires:
#   INFISICAL_PROJECT_ID
#   and either:
#     INFISICAL_SMOKE_TOKEN
#   or:
#     INFISICAL_SMOKE_CLIENT_ID + INFISICAL_SMOKE_CLIENT_SECRET
#
# Optional:
#   INFISICAL_ENVIRONMENT   (default: dev)
#   INFISICAL_SECRET_PATH   (default: /)
#   INFISICAL_SITE_URL      (default: https://app.infisical.com)
#
# Machine identity / token must be able to create, read, update, and delete
# secrets in the target project/environment.

set +x
set -eo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd)"
REPO_ROOT="$(realpath -- "${SCRIPT_DIR}/../..")"

# shellcheck source=smoke-test-helper.sh
source "${SCRIPT_DIR}/smoke-test-helper.sh"
source "${SCRIPT_DIR}/infisical-local.sh"

prepare_plugin_rootfs() {
    infisical_local_trust_plugin
}

export INFISICAL_SITE_URL="${INFISICAL_SITE_URL:-https://app.infisical.com}"
export INFISICAL_ENVIRONMENT="${INFISICAL_ENVIRONMENT:-dev}"
export INFISICAL_SECRET_PATH="${INFISICAL_SECRET_PATH:-/}"
export INFISICAL_PROJECT_ID="${INFISICAL_PROJECT_ID:-}"
export INFISICAL_SMOKE_TOKEN="${INFISICAL_SMOKE_TOKEN:-}"
export INFISICAL_SMOKE_CLIENT_ID="${INFISICAL_SMOKE_CLIENT_ID:-}"
export INFISICAL_SMOKE_CLIENT_SECRET="${INFISICAL_SMOKE_CLIENT_SECRET:-}"

STACK_NAME="smoke-infisical"
SECRET_NAME="smoke_secret"
# Xs must be at the end of the template (macOS mktemp); rename to .yml after.
COMPOSE_FILE="$(mktemp "${TMPDIR:-/tmp}/smoke-infisical-compose.XXXXXX").yml"
mv "${COMPOSE_FILE%.yml}" "${COMPOSE_FILE}"

RUN_ID="$(printf '%s_%s' "${GITHUB_RUN_ID:-local_$$}" "${GITHUB_RUN_ATTEMPT:-1}" \
    | tr -cd '[:alnum:]_' | tr '[:lower:]' '[:upper:]')"
SECRET_KEY="SMOKE_TEST_PASSWORD_${RUN_ID}"
SECRET_VALUE="infisical-smoke-pass-v1-${RUN_ID}"
SECRET_VALUE_ROTATED="infisical-smoke-pass-v2-${RUN_ID}"

INFISICAL_ACCESS_TOKEN=""
EXIT_CODE=0

infisical_require_creds() {
    if [[ -z "${INFISICAL_PROJECT_ID}" ]]; then
        die "INFISICAL_PROJECT_ID is required (create a free Infisical project and export it)."
    fi
    if [[ -n "${INFISICAL_SMOKE_TOKEN}" ]]; then
        return 0
    fi
    if [[ -n "${INFISICAL_SMOKE_CLIENT_ID}" && -n "${INFISICAL_SMOKE_CLIENT_SECRET}" ]]; then
        return 0
    fi
    die "Set INFISICAL_SMOKE_TOKEN, or INFISICAL_SMOKE_CLIENT_ID + INFISICAL_SMOKE_CLIENT_SECRET (free Infisical account)."
}

infisical_login() {
    if [[ -n "${INFISICAL_SMOKE_TOKEN}" ]]; then
        INFISICAL_ACCESS_TOKEN="${INFISICAL_SMOKE_TOKEN}"
        return 0
    fi

    local resp
    resp="$(curl --max-time 30 -fsS -X POST "${INFISICAL_SITE_URL}/api/v1/auth/universal-auth/login" \
        -H "Content-Type: application/json" \
        -H "Accept: application/json" \
        -d "{\"clientId\":\"${INFISICAL_SMOKE_CLIENT_ID}\",\"clientSecret\":\"${INFISICAL_SMOKE_CLIENT_SECRET}\"}")"

    INFISICAL_ACCESS_TOKEN="$(printf '%s' "${resp}" | jq -er '.accessToken')"
    if [[ "${GITHUB_ACTIONS:-}" == true ]]; then
        printf '::add-mask::%s\n' "${INFISICAL_ACCESS_TOKEN}"
    fi
    [[ -n "${INFISICAL_ACCESS_TOKEN}" ]] || die "Failed to obtain Infisical access token."
}

infisical_api() {
    local method="$1"
    local path="$2"
    local body="${3:-}"
    if [[ -n "${body}" ]]; then
        curl --max-time 30 -fsS -X "${method}" "${INFISICAL_SITE_URL}${path}" \
            -H "Authorization: Bearer ${INFISICAL_ACCESS_TOKEN}" \
            -H "Content-Type: application/json" \
            -H "Accept: application/json" \
            -d "${body}"
    else
        curl --max-time 30 -fsS -X "${method}" "${INFISICAL_SITE_URL}${path}" \
            -H "Authorization: Bearer ${INFISICAL_ACCESS_TOKEN}" \
            -H "Accept: application/json"
    fi
}

infisical_secret_body() {
    # Optional secretValue as $1. Smoke inputs are alphanumeric / path-safe.
    if [[ $# -ge 1 ]]; then
        printf '{"projectId":"%s","environment":"%s","secretPath":"%s","secretValue":"%s"}' \
            "${INFISICAL_PROJECT_ID}" "${INFISICAL_ENVIRONMENT}" "${INFISICAL_SECRET_PATH}" "$1"
    else
        printf '{"projectId":"%s","environment":"%s","secretPath":"%s"}' \
            "${INFISICAL_PROJECT_ID}" "${INFISICAL_ENVIRONMENT}" "${INFISICAL_SECRET_PATH}"
    fi
}

# Create or update (upsert) a secret value.
infisical_seed_secret() {
    local name="$1" value="$2"
    local body status
    body="$(infisical_secret_body "${value}")"

    status="$(curl --max-time 30 -sS -o /dev/null -w '%{http_code}' \
        -X GET "${INFISICAL_SITE_URL}/api/v4/secrets/${name}?projectId=${INFISICAL_PROJECT_ID}&environment=${INFISICAL_ENVIRONMENT}&secretPath=${INFISICAL_SECRET_PATH}&viewSecretValue=true" \
        -H "Authorization: Bearer ${INFISICAL_ACCESS_TOKEN}" \
        -H "Accept: application/json" || true)"

    if [[ "${status}" == "200" ]]; then
        infisical_api PATCH "/api/v4/secrets/${name}" "${body}" >/dev/null
    else
        # Missing or unreadable — create; if it already exists, update.
        if ! infisical_api POST "/api/v4/secrets/${name}" "${body}" >/dev/null; then
            infisical_api PATCH "/api/v4/secrets/${name}" "${body}" >/dev/null
        fi
    fi
}

infisical_delete_secret() {
    local name="$1"
    local body
    body="$(infisical_secret_body)"
    curl --max-time 30 -fsS -X DELETE "${INFISICAL_SITE_URL}/api/v4/secrets/${name}" \
        -H "Authorization: Bearer ${INFISICAL_ACCESS_TOKEN}" \
        -H "Content-Type: application/json" \
        -H "Accept: application/json" \
        -d "${body}" >/dev/null 2>&1 || true
}

# Same idea as Doppler: wait until the seeded value appears in the API response.
infisical_wait_readable() {
    local value="$1" timeout="${2:-30}" elapsed=0
    local qs="projectId=${INFISICAL_PROJECT_ID}&environment=${INFISICAL_ENVIRONMENT}&secretPath=${INFISICAL_SECRET_PATH}&viewSecretValue=true"
    until curl --max-time 30 -fsS \
        -H "Authorization: Bearer ${INFISICAL_ACCESS_TOKEN}" \
        -H "Accept: application/json" \
        "${INFISICAL_SITE_URL}/api/v4/secrets/${SECRET_KEY}?${qs}" \
        | grep -q "${value}"; do
        sleep 2
        elapsed=$((elapsed + 2))
        [[ "${elapsed}" -lt "${timeout}" ]] || die "Seeded Infisical secret did not become readable within ${timeout}s."
    done
}

write_infisical_compose() {
    local out_file="$1"
    local secret_name="$2"
    local secret_key="$3"

    cat > "${out_file}" <<EOF
version: '3.8'

services:
  app:
    image: busybox:latest
    command: >
      sh -c "
        while true; do
          echo 'Current secret:' && cat /run/secrets/${secret_name}
          sleep 5
        done
      "
    secrets:
      - ${secret_name}
    deploy:
      replicas: 1
      restart_policy:
        condition: any
    networks:
      - smoke-network

secrets:
  ${secret_name}:
    driver: swarm-external-secrets:latest
    labels:
      infisical_secret_name: "${secret_key}"

networks:
  smoke-network:
    driver: overlay
EOF
}

cleanup() {
    local ec=$?
    echo -e "${RED}Running Infisical smoke test cleanup...${DEF}"
    remove_stack "${STACK_NAME}"
    docker secret rm "${SECRET_NAME}" 2>/dev/null || true
    if [[ -n "${INFISICAL_ACCESS_TOKEN}" ]]; then
        infisical_delete_secret "${SECRET_KEY}"
    fi
    rm -f "${COMPOSE_FILE}"
    remove_plugin
    infisical_local_stop
    # Preserve the first non-zero status (e.g. die/set -e), else EXIT_CODE.
    if [[ "${EXIT_CODE}" -eq 0 && "${ec}" -ne 0 ]]; then
        EXIT_CODE="${ec}"
    fi
    exit "${EXIT_CODE}"
}
trap cleanup EXIT

if [[ "${INFISICAL_SMOKE_EXTERNAL:-false}" != true ]]; then
    infisical_local_start
fi
infisical_require_creds
infisical_login
info "Infisical smoke test against ${INFISICAL_SITE_URL} (project=${INFISICAL_PROJECT_ID}, env=${INFISICAL_ENVIRONMENT})."

write_infisical_compose "${COMPOSE_FILE}" "${SECRET_NAME}" "${SECRET_KEY}"

info "Seeding secret ${SECRET_KEY}..."
infisical_seed_secret "${SECRET_KEY}" "${SECRET_VALUE}"
infisical_wait_readable "${SECRET_VALUE}" 30
success "Secret ${SECRET_KEY} is readable."

info "Building plugin and setting Infisical config..."
build_plugin

PLUGIN_SET_ARGS=(
    SECRETS_PROVIDER="infisical"
    INFISICAL_PROJECT_ID="${INFISICAL_PROJECT_ID}"
    INFISICAL_ENVIRONMENT="${INFISICAL_ENVIRONMENT}"
    INFISICAL_SECRET_PATH="${INFISICAL_SECRET_PATH}"
    INFISICAL_SITE_URL="${INFISICAL_SITE_URL}"
    ENABLE_ROTATION="true"
    ROTATION_INTERVAL="10s"
    ENABLE_MONITORING="false"
)

if [[ -n "${INFISICAL_SMOKE_TOKEN}" ]]; then
    PLUGIN_SET_ARGS+=(INFISICAL_TOKEN="${INFISICAL_SMOKE_TOKEN}")
else
    PLUGIN_SET_ARGS+=(
        INFISICAL_CLIENT_ID="${INFISICAL_SMOKE_CLIENT_ID}"
        INFISICAL_CLIENT_SECRET="${INFISICAL_SMOKE_CLIENT_SECRET}"
    )
fi

docker plugin set "${PLUGIN_NAME}" "${PLUGIN_SET_ARGS[@]}"
success "Plugin configured with Infisical settings."

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

info "Rotating secret in Infisical..."
infisical_seed_secret "${SECRET_KEY}" "${SECRET_VALUE_ROTATED}"
success "Secret rotated to: ${SECRET_VALUE_ROTATED}"

info "Waiting for plugin rotation interval (15s)..."
sleep 15

info "Logging service output after rotation..."
log_stack "${STACK_NAME}" "app"
assert_no_sensitive_rotation_metadata_logs

info "Verifying rotated secret value..."
verify_secret "${STACK_NAME}" "app" "${SECRET_NAME}" "${SECRET_VALUE_ROTATED}" 180

success "Infisical smoke test PASSED"
EXIT_CODE=0
