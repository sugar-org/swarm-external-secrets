#!/usr/bin/env bash
# smoke-test-helper.sh
# Shared helper functions sourced by smoke-test-vault.sh and smoke-test-openbao.sh

RED='\033[0;31m'
GRN='\033[0;32m'
BLU='\033[0;34m'
DEF='\033[0m'

PLUGIN_NAME="swarm-external-secrets:latest"

# Logging
info()    { echo -e "${BLU}[INFO]${DEF} $*"; }
success() { echo -e "${GRN}[PASS]${DEF} $*"; }
error()   { echo -e "${RED}[FAIL]${DEF} $*" >&2; }
die()     { error "$*"; exit 1; }

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
    echo -e "${RED}Set plugin permissions${DEF}"
    docker plugin set "${PLUGIN_NAME}" gid=0 uid=0

    echo -e "${RED}Enable the plugin${DEF}"
    docker plugin enable "${PLUGIN_NAME}"

    echo -e "${RED}Check plugin status${DEF}"
    docker plugin ls

    success "Plugin enabled."
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
