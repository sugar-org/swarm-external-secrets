#!/usr/bin/env bash
# smoke-test-helper.sh
# Shared helper functions sourced by smoke-test-vault.sh and smoke-test-openbao.sh

RED='\033[0;31m'
GRN='\033[0;32m'
BLU='\033[0;34m'
DEF='\033[0m'

PLUGIN_NAME="swarm-external-secrets:latest"
WEBHOOK_TEST_DIR="${REPO_ROOT}/scripts/tests/webhook"
WEBHOOK_UI_PORT="${WEBHOOK_UI_PORT:-8765}"
WEBHOOK_PORT="${WEBHOOK_PORT:-9095}"
WEBHOOK_PATH="${WEBHOOK_PATH:-/webhook}"
WEBHOOK_SECRET="${WEBHOOK_SECRET:-smoke-webhook-secret}"

# Logging
info()    { echo -e "${BLU}[INFO]${DEF} $*"; }
success() { echo -e "${GRN}[PASS]${DEF} $*"; }
error()   { echo -e "${RED}[FAIL]${DEF} $*" >&2; }
die()     { error "$*"; exit 1; }

wait_for_http_ok() {
    local url="$1"
    local timeout="${2:-30}"
    local elapsed=0

    while [ "${elapsed}" -lt "${timeout}" ]; do
        if python3 - "${url}" <<'PY'
import sys
from urllib import request
from urllib.error import URLError

try:
    with request.urlopen(sys.argv[1], timeout=2) as response:
        raise SystemExit(0 if 200 <= response.status <= 299 else 1)
except URLError:
    raise SystemExit(1)
PY
        then
            return 0
        fi
        sleep 2
        elapsed=$((elapsed + 2))
    done

    die "Timed out waiting for ${url}"
}

start_webhook_config_ui() {
    local config_path="$1"
    local log_path="${config_path}.ui.log"

    info "Starting local HCP-style webhook UI..."
    python3 "${WEBHOOK_TEST_DIR}/mock_hcp_webhook_ui.py" \
        --host "127.0.0.1" \
        --port "${WEBHOOK_UI_PORT}" \
        --output "${config_path}" \
        >"${log_path}" 2>&1 &
    WEBHOOK_UI_PID="$!"
    export WEBHOOK_UI_PID

    wait_for_http_ok "http://127.0.0.1:${WEBHOOK_UI_PORT}/health" 30
    success "Local webhook UI is ready."
}

stop_webhook_config_ui() {
    if [ -n "${WEBHOOK_UI_PID:-}" ]; then
        kill "${WEBHOOK_UI_PID}" 2>/dev/null || true
        wait "${WEBHOOK_UI_PID}" 2>/dev/null || true
        WEBHOOK_UI_PID=""
    fi
}

create_webhook_config_with_playwright() {
    local config_path="$1"
    local webhook_url="http://127.0.0.1:${WEBHOOK_PORT}${WEBHOOK_PATH}"

    info "Creating webhook config through Playwright UI flow..."
    python3 "${WEBHOOK_TEST_DIR}/create_webhook_config.py" \
        --ui-url "http://127.0.0.1:${WEBHOOK_UI_PORT}" \
        --webhook-url "${webhook_url}" \
        --webhook-path "${WEBHOOK_PATH}" \
        --webhook-secret "${WEBHOOK_SECRET}" \
        --output "${config_path}"

    load_webhook_config "${config_path}"
    success "Webhook config created for ${WEBHOOK_URL}."
}

load_webhook_config() {
    local config_path="$1"

    eval "$(
        python3 - "${config_path}" <<'PY'
import json
import shlex
import sys
from pathlib import Path

config = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
print(f"WEBHOOK_URL={shlex.quote(config['url'])}")
print(f"WEBHOOK_PATH={shlex.quote(config['path'])}")
print(f"WEBHOOK_SECRET={shlex.quote(config['secret'])}")
PY
    )"
    export WEBHOOK_URL WEBHOOK_PATH WEBHOOK_SECRET
}

wait_for_webhook_health() {
    wait_for_http_ok "http://127.0.0.1:${WEBHOOK_PORT}${WEBHOOK_PATH}/health" 60
    success "Plugin webhook health endpoint is ready."
}

send_vault_webhook_event() {
    local config_path="$1"
    local action="$2"
    local app_name="$3"
    local secret_name="$4"
    local secret_path="$5"

    python3 "${WEBHOOK_TEST_DIR}/send_webhook_event.py" \
        --config "${config_path}" \
        --payload-format "vault" \
        --provider "vault" \
        --action "${action}" \
        --app-name "${app_name}" \
        --secret-name "${secret_name}" \
        --secret-path "${secret_path}" \
        --event-id "vault-smoke-${action}"
}

send_normalized_webhook_event() {
    local config_path="$1"
    local provider="$2"
    local action="$3"
    local secret_name="$4"
    local secret_path="$5"

    python3 "${WEBHOOK_TEST_DIR}/send_webhook_event.py" \
        --config "${config_path}" \
        --payload-format "normalized" \
        --provider "${provider}" \
        --action "${action}" \
        --secret-name "${secret_name}" \
        --secret-path "${secret_path}" \
        --event-id "${provider}-smoke-${action}"
}

docker_daemon_logs() {
    # Best-effort: plugin logs are routed through Docker daemon logs.
    # In CI, journald is usually available; fall back gracefully if not.
    if command -v journalctl >/dev/null 2>&1; then
        if command -v sudo >/dev/null 2>&1; then
            sudo journalctl -u docker.service --no-pager -n 2000 2>/dev/null || true
        else
            journalctl -u docker.service --no-pager -n 2000 2>/dev/null || true
        fi
        return 0
    fi
    return 0
}

# Assemble the JWT smoke policy on the host and pipe it into `vault`/`bao
# policy write -`. docker cp into /tmp as root leaves 0600 files the
# non-root server user cannot read.
write_jwt_smoke_policy() {
    local container="$1"
    local policy_file="$2"
    shift 2
    local tmp status=0
    tmp="$(mktemp)"
    if [[ ! -r "${policy_file}" ]] || ! cat "${policy_file}" > "${tmp}"; then
        rm -f "${tmp}"
        return 1
    fi
    cat <<'EOF' >> "${tmp}"

path "auth/token/renew-self" {
  capabilities = ["update"]
}
EOF
    docker exec -i "${container}" "$@" < "${tmp}" || status=$?
    rm -f "${tmp}"
    return "${status}"
}

# Pass a JWT into `docker plugin set` with xtrace off so `set -x` does not
# print the token in CI logs. Restore xtrace only if the caller had it on.
configure_plugin_jwt() {
    local jwt_file="$1"
    local jwt_env="$2"
    shift 2
    local jwt status=0 xtrace_was_on=0
    case "$-" in
        *x*) xtrace_was_on=1 ;;
    esac
    set +x
    jwt="$(tr -d '\n' < "${jwt_file}")"
    docker plugin set "${PLUGIN_NAME}" "$@" "${jwt_env}=${jwt}" || status=$?
    if [[ "${xtrace_was_on}" -eq 1 ]]; then
        set -x
    fi
    return "${status}"
}

assert_no_sensitive_rotation_metadata_logs() {
    # Ensure trace-only rotation metadata isn't emitted at default log levels.
    # We look for the exact strings used by the driver.
    local logs
    logs="$(docker_daemon_logs)"
    if echo "${logs}" | grep -Fq "tracking secret:"; then
        die "Sensitive rotation metadata leaked into logs (found: 'tracking secret:')"
    fi
    if echo "${logs}" | grep -Fq "Tracking secret:"; then
        die "Sensitive rotation metadata leaked into logs (found: 'Tracking secret:')"
    fi
    if echo "${logs}" | grep -Fq "Detected change in secret:"; then
        die "Sensitive rotation metadata leaked into logs (found: 'Detected change in secret:')"
    fi

    return 0
}

# Build plugin (mirrors build.sh / test.sh pattern exactly)
build_plugin() {
    echo -e "${RED}Remove existing plugin if it exists${DEF}"
    if docker plugin inspect "${PLUGIN_NAME}" &>/dev/null; then
        docker plugin disable "${PLUGIN_NAME}" --force 2>/dev/null || true
        docker plugin rm      "${PLUGIN_NAME}" --force 2>/dev/null || true
        # Verify removal succeeded
        if docker plugin inspect "${PLUGIN_NAME}" &>/dev/null; then
            die "Failed to remove existing plugin '${PLUGIN_NAME}'. Run: docker plugin rm ${PLUGIN_NAME} --force"
        fi
    fi

    echo -e "${RED}Build the plugin${DEF}"
    docker build -f "${REPO_ROOT}/Dockerfile" -t swarm-external-secrets:temp "${REPO_ROOT}"

    echo -e "${RED}Create plugin rootfs${DEF}"
    mkdir -p "${REPO_ROOT}/plugin/rootfs"

    if docker ps -a --format '{{.Names}}' | grep -q '^temp-container$'; then
        docker rm -f temp-container || true
    fi

    docker create --name temp-container swarm-external-secrets:temp
    docker export temp-container | tar -x -C "${REPO_ROOT}/plugin/rootfs"
    docker rm  temp-container
    docker rmi swarm-external-secrets:temp

    echo -e "${RED}Copy config to plugin directory${DEF}"
    cp "${REPO_ROOT}/config.json" "${REPO_ROOT}/plugin/"

    echo -e "${RED}Create the plugin${DEF}"
    docker plugin create "${PLUGIN_NAME}" "${REPO_ROOT}/plugin"

    echo -e "${RED}Clean up plugin directory${DEF}"
    rm -rf "${REPO_ROOT}/plugin"

    success "Plugin built: ${PLUGIN_NAME}"
}

# Enable plugin (mirrors test.sh pattern)
enable_plugin() {
    # config.json bind-mounts host /run/swarm-external-secrets into the plugin.
    # Docker refuses to enable if that host path does not exist.
    ensure_plugin_mount_dir

    echo -e "${RED}Set plugin permissions${DEF}"
    docker plugin set "${PLUGIN_NAME}" gid=0 uid=0

    echo -e "${RED}Enable the plugin${DEF}"
    if ! docker plugin enable "${PLUGIN_NAME}"; then
        error "Failed to enable plugin '${PLUGIN_NAME}'"
        docker plugin inspect "${PLUGIN_NAME}" 2>/dev/null || true
        docker_daemon_logs
        die "docker plugin enable failed (plugin process likely exited before creating plugin.sock)"
    fi

    echo -e "${RED}Check plugin status${DEF}"
    docker plugin ls

    success "Plugin enabled."
}

ensure_plugin_mount_dir() {
    local dir="/run/swarm-external-secrets"
    if [[ -d "${dir}" ]]; then
        return 0
    fi
    info "Creating plugin mount source ${dir}..."
    # Directory only needs to exist for the bind mount; Docker daemon is root.
    if [[ "$(id -u)" -eq 0 ]]; then
        mkdir -p "${dir}"
    elif command -v sudo >/dev/null 2>&1; then
        sudo mkdir -p "${dir}"
    else
        die "Need ${dir} for plugin bind mount (create it as root)."
    fi
}
# Remove plugin (mirrors cleanup.sh pattern)
remove_plugin() {
    docker plugin disable "${PLUGIN_NAME}" --force 2>/dev/null || true
    docker plugin rm      "${PLUGIN_NAME}" --force 2>/dev/null || true
    docker image rm swarm-external-secrets:temp --force 2>/dev/null || true
}

# Deploy swarm stack (mirrors deploy.sh pattern)
deploy_stack() {
    local compose_file="$1"
    local stack_name="$2"
    local timeout="${3:-60}"

    info "Deploying stack '${stack_name}'..."
    docker stack deploy -c "${compose_file}" "${stack_name}"

    info "Waiting for stack '${stack_name}' to be ready (timeout: ${timeout}s)..."
    local elapsed=0
    while [ "${elapsed}" -lt "${timeout}" ]; do
        local running
        running=$(docker stack ps "${stack_name}" \
            --filter "desired-state=running" \
            --format '{{.CurrentState}}' 2>/dev/null \
            | grep -c "Running" || true)
        if [ "${running}" -gt 0 ]; then
            success "Stack '${stack_name}' is running."
            return 0
        fi
        sleep 5
        elapsed=$((elapsed + 5))
    done
    die "Stack '${stack_name}' did not become ready within ${timeout}s."
}

# Log stack service output (mirrors deploy.sh: docker service logs)
log_stack() {
    local stack_name="$1"
    local service_suffix="$2"
    info "Logging output for '${stack_name}_${service_suffix}'..."
    docker service logs "${stack_name}_${service_suffix}" 2>&1 || true
}

# Compare password == logged secret 
verify_secret() {
    local stack_name="$1"
    local service_suffix="$2"
    local secret_name="$3"
    local expected_value="$4"
    local timeout="${5:-60}"

    info "Verifying secret '${secret_name}' matches expected value..."

    local elapsed=0
    while [ "${elapsed}" -lt "${timeout}" ]; do
        local task_id
        task_id=$(docker service ps "${stack_name}_${service_suffix}" \
            --filter "desired-state=running" \
            --format '{{.ID}}' 2>/dev/null | head -1)

        if [ -n "${task_id}" ]; then
            local container_id
            container_id=$(docker inspect "${task_id}" \
                --format '{{.Status.ContainerStatus.ContainerID}}' 2>/dev/null || true)

            if [ -n "${container_id}" ]; then
                local actual
                actual=$(docker exec "${container_id}" \
                    cat "/run/secrets/${secret_name}" 2>/dev/null | tr -d '[:space:]' || true)
                local expected_trimmed
                expected_trimmed=$(echo "${expected_value}" | tr -d '[:space:]')

                info "Expected: '${expected_trimmed}' | Got: '${actual}'"

                if [ "${actual}" = "${expected_trimmed}" ]; then
                    success "Secret '${secret_name}' verified: value matches expected."
                    return 0
                fi
            fi
        fi
        sleep 5
        elapsed=$((elapsed + 5))
    done

    die "Secret '${secret_name}' did not match expected value within ${timeout}s."
}

# Get the currently running container ID for a swarm service
get_running_container_id() {
    local stack_name="$1"
    local service_suffix="$2"
    local task_id
    task_id=$(docker service ps "${stack_name}_${service_suffix}" \
        --filter "desired-state=running" \
        --format '{{.ID}}' 2>/dev/null | head -1)
    if [ -n "${task_id}" ]; then
        docker inspect "${task_id}" \
            --format '{{.Status.ContainerStatus.ContainerID}}' 2>/dev/null || true
    fi
}

# Remove stack cleanly
remove_stack() {
    local stack_name="$1"
    info "Removing stack '${stack_name}'..."
    docker stack rm "${stack_name}" 2>/dev/null || true
    local elapsed=0
    while docker stack ps "${stack_name}" &>/dev/null && [ "${elapsed}" -lt 30 ]; do
        sleep 3
        elapsed=$((elapsed + 3))
    done
}
