#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd)"
REPO_ROOT="$(realpath -- "${SCRIPT_DIR}/../..")"

VAULT_CONTAINER="smoke-vault"
OPENBAO_CONTAINER="smoke-openbao"
VAULT_ROOT_TOKEN="smoke-root-token"
OPENBAO_ROOT_TOKEN="smoke-root-token"
VAULT_ADDR="http://127.0.0.1:8200"
OPENBAO_ADDR="http://127.0.0.1:8201"
VAULT_SECRET_VALUE="vault-multi-instance-pass"
OPENBAO_SECRET_VALUE="openbao-multi-instance-pass"
SECRET_PATH="database/mysql"
SECRET_FIELD="password"
POLICY_FILE="${REPO_ROOT}/vault_conf/admin.hcl"

VAULT_PLUGIN="vault-secret:latest"
OPENBAO_PLUGIN="openbao-secret:latest"
STACK_SINGLE="smoke-alias-single"
STACK_DUAL="smoke-alias-dual"
COMPOSE_SINGLE="${SCRIPT_DIR}/smoke-alias-single-service-compose.yml"
COMPOSE_DUAL="${SCRIPT_DIR}/smoke-alias-two-services-compose.yml"

RED='\033[0;31m'
GRN='\033[0;32m'
BLU='\033[0;34m'
DEF='\033[0m'

info()    { echo -e "${BLU}[INFO]${DEF} $*"; }
success() { echo -e "${GRN}[PASS]${DEF} $*"; }
error()   { echo -e "${RED}[FAIL]${DEF} $*" >&2; }
die()     { error "$*"; exit 1; }

cleanup() {
    info "Cleaning up test resources..."
    docker stack rm "${STACK_SINGLE}" 2>/dev/null || true
    docker stack rm "${STACK_DUAL}" 2>/dev/null || true
    sleep 5

    docker plugin disable "${VAULT_PLUGIN}" --force 2>/dev/null || true
    docker plugin disable "${OPENBAO_PLUGIN}" --force 2>/dev/null || true
    docker plugin rm "${VAULT_PLUGIN}" --force 2>/dev/null || true
    docker plugin rm "${OPENBAO_PLUGIN}" --force 2>/dev/null || true

    docker stop "${VAULT_CONTAINER}" 2>/dev/null || true
    docker stop "${OPENBAO_CONTAINER}" 2>/dev/null || true
    docker rm "${VAULT_CONTAINER}" 2>/dev/null || true
    docker rm "${OPENBAO_CONTAINER}" 2>/dev/null || true

    docker rm -f temp-container 2>/dev/null || true
    docker rmi swarm-external-secrets:temp 2>/dev/null || true
    rm -rf "${REPO_ROOT}/plugin_vault" "${REPO_ROOT}/plugin_openbao"
}
trap cleanup EXIT

wait_for_service_running() {
    local stack_name="$1"
    local service_suffix="$2"
    local timeout="${3:-120}"
    local elapsed=0

    while [ "${elapsed}" -lt "${timeout}" ]; do
        local state
        state="$(docker service ps "${stack_name}_${service_suffix}" --no-trunc --format '{{.CurrentState}}' 2>/dev/null | head -1 || true)"
        if echo "${state}" | grep -q "Running"; then
            return 0
        fi
        sleep 5
        elapsed=$((elapsed + 5))
    done
    return 1
}

get_running_container_id() {
    local stack_name="$1"
    local service_suffix="$2"
    local task_id
    task_id="$(docker service ps "${stack_name}_${service_suffix}" \
        --filter "desired-state=running" \
        --format '{{.ID}}' 2>/dev/null | head -1)"
    if [ -n "${task_id}" ]; then
        docker inspect "${task_id}" --format '{{.Status.ContainerStatus.ContainerID}}' 2>/dev/null || true
    fi
}

verify_secret() {
    local stack_name="$1"
    local service_suffix="$2"
    local secret_name="$3"
    local expected="$4"
    local timeout="${5:-120}"
    local elapsed=0

    info "Verifying ${stack_name}_${service_suffix} -> /run/secrets/${secret_name}"
    while [ "${elapsed}" -lt "${timeout}" ]; do
        local container_id
        container_id="$(get_running_container_id "${stack_name}" "${service_suffix}")"
        if [ -n "${container_id}" ]; then
            local actual
            actual="$(docker exec "${container_id}" cat "/run/secrets/${secret_name}" 2>/dev/null | tr -d '[:space:]' || true)"
            if [ "${actual}" = "${expected}" ]; then
                success "Secret ${secret_name} verified for ${stack_name}_${service_suffix}"
                return 0
            fi
        fi
        sleep 5
        elapsed=$((elapsed + 5))
    done

    die "Secret ${secret_name} verification failed for ${stack_name}_${service_suffix}"
}

info "Ensuring Docker Swarm is initialized..."
if [ "$(docker info --format '{{.Swarm.LocalNodeState}}')" != "active" ]; then
    docker swarm init --advertise-addr 127.0.0.1 >/dev/null
fi
success "Swarm is active"

info "Starting Vault and OpenBao dev containers..."
docker run -d --name "${VAULT_CONTAINER}" -p 8200:8200 \
    -e "VAULT_DEV_ROOT_TOKEN_ID=${VAULT_ROOT_TOKEN}" \
    hashicorp/vault:latest server -dev >/dev/null

docker run -d --name "${OPENBAO_CONTAINER}" -p 8201:8200 \
    -e "BAO_DEV_ROOT_TOKEN_ID=${OPENBAO_ROOT_TOKEN}" \
    quay.io/openbao/openbao:latest server -dev >/dev/null

info "Waiting for Vault and OpenBao readiness..."
for _ in $(seq 1 30); do
    if docker exec "${VAULT_CONTAINER}" vault status -address="http://127.0.0.1:8200" >/dev/null 2>&1; then
        break
    fi
    sleep 2
done

for _ in $(seq 1 30); do
    if docker exec "${OPENBAO_CONTAINER}" bao status -address="http://127.0.0.1:8200" >/dev/null 2>&1; then
        break
    fi
    sleep 2
done

info "Applying policy and writing source secrets..."
docker cp "${POLICY_FILE}" "${VAULT_CONTAINER}:/tmp/admin.hcl"
docker exec "${VAULT_CONTAINER}" env VAULT_ADDR="http://127.0.0.1:8200" VAULT_TOKEN="${VAULT_ROOT_TOKEN}" \
    vault policy write smoke-policy /tmp/admin.hcl >/dev/null
docker exec "${VAULT_CONTAINER}" env VAULT_ADDR="http://127.0.0.1:8200" VAULT_TOKEN="${VAULT_ROOT_TOKEN}" \
    vault kv put "secret/${SECRET_PATH}" "${SECRET_FIELD}=${VAULT_SECRET_VALUE}" >/dev/null
VAULT_TOKEN="$(docker exec "${VAULT_CONTAINER}" env VAULT_ADDR="http://127.0.0.1:8200" VAULT_TOKEN="${VAULT_ROOT_TOKEN}" \
    vault token create -policy="smoke-policy" -field=token)"

docker cp "${POLICY_FILE}" "${OPENBAO_CONTAINER}:/tmp/admin.hcl"
docker exec "${OPENBAO_CONTAINER}" env BAO_ADDR="http://127.0.0.1:8200" BAO_TOKEN="${OPENBAO_ROOT_TOKEN}" \
    bao policy write smoke-policy /tmp/admin.hcl >/dev/null
docker exec "${OPENBAO_CONTAINER}" env BAO_ADDR="http://127.0.0.1:8200" BAO_TOKEN="${OPENBAO_ROOT_TOKEN}" \
    bao kv put "secret/${SECRET_PATH}" "${SECRET_FIELD}=${OPENBAO_SECRET_VALUE}" >/dev/null
OPENBAO_TOKEN="$(docker exec "${OPENBAO_CONTAINER}" env BAO_ADDR="http://127.0.0.1:8200" BAO_TOKEN="${OPENBAO_ROOT_TOKEN}" \
    bao token create -policy="smoke-policy" -field=token)"

info "Building plugin rootfs once..."
docker build -f "${REPO_ROOT}/Dockerfile" -t swarm-external-secrets:temp "${REPO_ROOT}" >/dev/null
mkdir -p "${REPO_ROOT}/plugin_vault/rootfs" "${REPO_ROOT}/plugin_openbao/rootfs"
docker create --name temp-container swarm-external-secrets:temp >/dev/null
docker export temp-container | tar -x -C "${REPO_ROOT}/plugin_vault/rootfs"
docker export temp-container | tar -x -C "${REPO_ROOT}/plugin_openbao/rootfs"
docker rm temp-container >/dev/null
docker rmi swarm-external-secrets:temp >/dev/null

# Make each rootfs unique so Docker allows two local plugin objects.
mkdir -p "${REPO_ROOT}/plugin_vault/rootfs/etc" "${REPO_ROOT}/plugin_openbao/rootfs/etc"
echo "vault-instance" > "${REPO_ROOT}/plugin_vault/rootfs/etc/plugin-instance-id"
echo "openbao-instance" > "${REPO_ROOT}/plugin_openbao/rootfs/etc/plugin-instance-id"

cp "${REPO_ROOT}/config.json" "${REPO_ROOT}/plugin_vault/"
cp "${REPO_ROOT}/config.json" "${REPO_ROOT}/plugin_openbao/"

# Ensure plugin content differs so Docker accepts two local plugin objects
sed -i 's/External secrets plugin for Docker Swarm/External secrets plugin for Docker Swarm (vault instance)/' \
    "${REPO_ROOT}/plugin_vault/config.json"
sed -i 's/External secrets plugin for Docker Swarm/External secrets plugin for Docker Swarm (openbao instance)/' \
    "${REPO_ROOT}/plugin_openbao/config.json"

info "Creating two plugin instances with unique names..."
docker plugin create "${VAULT_PLUGIN}" "${REPO_ROOT}/plugin_vault" >/dev/null
docker plugin create "${OPENBAO_PLUGIN}" "${REPO_ROOT}/plugin_openbao" >/dev/null
rm -rf "${REPO_ROOT}/plugin_vault" "${REPO_ROOT}/plugin_openbao"

docker plugin set "${VAULT_PLUGIN}" gid=0 uid=0 >/dev/null
docker plugin set "${OPENBAO_PLUGIN}" gid=0 uid=0 >/dev/null

docker plugin set "${VAULT_PLUGIN}" \
    SECRETS_PROVIDER="vault" \
    VAULT_ADDR="${VAULT_ADDR}" \
    VAULT_AUTH_METHOD="token" \
    VAULT_TOKEN="${VAULT_TOKEN}" \
    VAULT_MOUNT_PATH="secret" \
    ENABLE_MONITORING="false" \
    ENABLE_ROTATION="false" >/dev/null

docker plugin set "${OPENBAO_PLUGIN}" \
    SECRETS_PROVIDER="openbao" \
    OPENBAO_ADDR="${OPENBAO_ADDR}" \
    OPENBAO_AUTH_METHOD="token" \
    OPENBAO_TOKEN="${OPENBAO_TOKEN}" \
    OPENBAO_MOUNT_PATH="secret" \
    ENABLE_MONITORING="false" \
    ENABLE_ROTATION="false" >/dev/null

docker plugin enable "${VAULT_PLUGIN}" >/dev/null
docker plugin enable "${OPENBAO_PLUGIN}" >/dev/null
success "Both plugin instances enabled"

info "Scenario 1: One microservice using both plugin instances"
docker stack deploy -c "${COMPOSE_SINGLE}" "${STACK_SINGLE}" >/dev/null
wait_for_service_running "${STACK_SINGLE}" "app" 120 || die "Scenario 1 service did not reach running"
verify_secret "${STACK_SINGLE}" "app" "vault_secret" "${VAULT_SECRET_VALUE}" 120
verify_secret "${STACK_SINGLE}" "app" "openbao_secret" "${OPENBAO_SECRET_VALUE}" 120
success "Scenario 1 passed"

info "Scenario 2: Two microservices using different plugin instances"
docker stack deploy -c "${COMPOSE_DUAL}" "${STACK_DUAL}" >/dev/null
wait_for_service_running "${STACK_DUAL}" "app_vault" 120 || die "Scenario 2 app_vault did not reach running"
wait_for_service_running "${STACK_DUAL}" "app_openbao" 120 || die "Scenario 2 app_openbao did not reach running"
verify_secret "${STACK_DUAL}" "app_vault" "vault_secret" "${VAULT_SECRET_VALUE}" 120
verify_secret "${STACK_DUAL}" "app_openbao" "openbao_secret" "${OPENBAO_SECRET_VALUE}" 120
success "Scenario 2 passed"

success "All multi-instance vault/openbao tests passed."
