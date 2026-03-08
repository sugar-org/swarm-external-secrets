#!/usr/bin/env bash

set -ex
SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd)"
REPO_ROOT="$(realpath -- "${SCRIPT_DIR}/../..")"
# shellcheck source=smoke-test-helper.sh
source "${SCRIPT_DIR}/smoke-test-helper.sh"

# GCP_PROJECT_ID and GOOGLE_APPLICATION_CREDENTIALS must be set externally
: "${GCP_PROJECT_ID:?GCP_PROJECT_ID env var must be set}"
: "${GOOGLE_APPLICATION_CREDENTIALS:?GOOGLE_APPLICATION_CREDENTIALS env var must be set}"

STACK_NAME="smoke-gcp"
SECRET_NAME="smoke_secret"
GCP_SECRET_ID="smoke-test-secret-$(date +%s)"
SECRET_FIELD="password"
SECRET_VALUE="gcp-smoke-pass-v1"
SECRET_VALUE_ROTATED="gcp-smoke-pass-v2"
COMPOSE_FILE="${SCRIPT_DIR}/smoke-gcp-compose.yml"

# Full GCP secret resource name
GCP_SECRET_NAME="projects/${GCP_PROJECT_ID}/secrets/${GCP_SECRET_ID}"
export GCP_SECRET_NAME

# Helpers
gcp_cmd() {
    gcloud "$@" --project="${GCP_PROJECT_ID}" --quiet
}

cleanup() {
    echo -e "${RED}Running GCP Secret Manager smoke test cleanup...${DEF}"
    remove_stack "${STACK_NAME}"
    docker secret rm "${SECRET_NAME}" 2>/dev/null || true

    # Delete the test secret from GCP (ignore errors if it doesn't exist)
    gcp_cmd secrets delete "${GCP_SECRET_ID}" 2>/dev/null || true

    remove_plugin
}
trap cleanup EXIT

info "Verifying GCP credentials and gcloud CLI..."

if ! command -v gcloud &>/dev/null; then
    die "gcloud CLI is not installed. Please install the Google Cloud SDK."
fi

# Activate service account if GOOGLE_APPLICATION_CREDENTIALS is set
gcloud auth activate-service-account --key-file="${GOOGLE_APPLICATION_CREDENTIALS}" 2>/dev/null || true

# Verify Secret Manager API access
if ! gcp_cmd secrets list --limit=1 &>/dev/null; then
    die "Cannot access GCP Secret Manager. Ensure the Secret Manager API is enabled and credentials are valid."
fi
success "GCP credentials verified."

# Create Test Secret
info "Creating test secret in GCP Secret Manager..."
gcp_cmd secrets create "${GCP_SECRET_ID}" --replication-policy="automatic"

info "Adding initial secret version..."
echo -n "{\"${SECRET_FIELD}\":\"${SECRET_VALUE}\"}" | \
    gcp_cmd secrets versions add "${GCP_SECRET_ID}" --data-file=-
success "Secret created: ${GCP_SECRET_ID} ${SECRET_FIELD}=${SECRET_VALUE}"

# BUILD PLUGIN
info "Building plugin and setting GCP Secret Manager config..."
build_plugin

docker plugin disable "${PLUGIN_NAME}" --force 2>/dev/null || true
docker plugin set "${PLUGIN_NAME}" \
    SECRETS_PROVIDER="gcp" \
    GCP_PROJECT_ID="${GCP_PROJECT_ID}" \
    GOOGLE_APPLICATION_CREDENTIALS="${GOOGLE_APPLICATION_CREDENTIALS}" \
    ENABLE_ROTATION="true" \
    ROTATION_INTERVAL="10s" \
    ENABLE_MONITORING="false"
success "Plugin configured with GCP Secret Manager settings."

# Enable Plugin
info "Enabling plugin..."
enable_plugin

# Deploy Stack
info "Deploying swarm stack..."
deploy_stack "${COMPOSE_FILE}" "${STACK_NAME}" 60

info "Logging service output..."
sleep 10
log_stack "${STACK_NAME}" "app"

info "Verifying secret value matches expected password..."
verify_secret "${STACK_NAME}" "app" "${SECRET_NAME}" "${SECRET_VALUE}" 60

# Rotate the SECRET
info "Rotating secret in GCP Secret Manager..."
echo -n "{\"${SECRET_FIELD}\":\"${SECRET_VALUE_ROTATED}\"}" | \
    gcp_cmd secrets versions add "${GCP_SECRET_ID}" --data-file=-
success "Secret rotated to: ${SECRET_VALUE_ROTATED}"

info "Waiting for plugin rotation interval (30s)..."
sleep 30

info "Logging service output after rotation..."
log_stack "${STACK_NAME}" "app"

info "Verifying rotated secret value..."
verify_secret "${STACK_NAME}" "app" "${SECRET_NAME}" "${SECRET_VALUE_ROTATED}" 180

success "GCP Secret Manager smoke test PASSED"
