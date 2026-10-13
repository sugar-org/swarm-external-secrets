#!/usr/bin/env bash

infisical_local_compose() {
    docker compose -p "${INFISICAL_LOCAL_PROJECT}" -f "${SCRIPT_DIR}/smoke-infisical-compose.yml" "$@"
}

infisical_local_start() {
    export INFISICAL_LOCAL_DIR
    INFISICAL_LOCAL_DIR="$(mktemp -d)"
    INFISICAL_LOCAL_PROJECT="infisical-smoke-$$"
    export INFISICAL_LOCAL_ENCRYPTION_KEY INFISICAL_LOCAL_AUTH_SECRET INFISICAL_LOCAL_DB_PASSWORD
    INFISICAL_LOCAL_ENCRYPTION_KEY="$(openssl rand -hex 16)"
    INFISICAL_LOCAL_AUTH_SECRET="$(openssl rand -hex 32)"
    INFISICAL_LOCAL_DB_PASSWORD="$(openssl rand -hex 16)"
    export INFISICAL_SITE_URL="https://localhost:${INFISICAL_LOCAL_PORT:-8443}"
    export INFISICAL_ENVIRONMENT=dev
    export INFISICAL_SECRET_PATH=/
    openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
        -keyout "${INFISICAL_LOCAL_DIR}/server.key" \
        -out "${INFISICAL_LOCAL_DIR}/server.crt" -subj /CN=localhost \
        -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1' >/dev/null 2>&1
    cat > "${INFISICAL_LOCAL_DIR}/nginx.conf" <<'EOF'
server {
    listen 443 ssl;
    ssl_certificate /etc/nginx/server.crt;
    ssl_certificate_key /etc/nginx/server.key;
    location / {
        proxy_pass http://backend:8080;
        proxy_set_header Host $http_host;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
EOF
    export CURL_CA_BUNDLE="${INFISICAL_LOCAL_DIR}/server.crt"
    infisical_local_compose up -d
    local attempt response identity_id ready=false
    for ((attempt=0; attempt<120; attempt++)); do
        if curl --max-time 5 -fsS "${INFISICAL_SITE_URL}/api/status" >/dev/null 2>&1; then
            ready=true
            break
        fi
        sleep 2
    done
    [[ "${ready}" == true ]] || die "Local Infisical did not become ready."
    response="$(curl --max-time 30 -fsS -X POST "${INFISICAL_SITE_URL}/api/v1/admin/bootstrap" \
        -H 'Content-Type: application/json' \
        -d "$(jq -n --arg password "$(openssl rand -hex 24)Aa1!" \
            '{email:"smoke@example.com", password:$password, organization:"Smoke Test"}')")"
    INFISICAL_ACCESS_TOKEN="$(printf '%s' "${response}" | jq -er '.identity.credentials.token')"
    response="$(infisical_api POST /api/v1/projects \
        '{"projectName":"Smoke Test","slug":"smoke-test","type":"secret-manager","template":"default"}')"
    export INFISICAL_PROJECT_ID
    INFISICAL_PROJECT_ID="$(printf '%s' "${response}" | jq -er '.project.id')"
    response="$(infisical_api POST "/api/v1/projects/${INFISICAL_PROJECT_ID}/identities" \
        '{"name":"Smoke Test","roles":[{"role":"admin","isTemporary":false}]}')"
    identity_id="$(printf '%s' "${response}" | jq -er '.identity.id')"
    response="$(infisical_api POST "/api/v1/auth/universal-auth/identities/${identity_id}" \
        '{"accessTokenTTL":3600,"accessTokenMaxTTL":7200}')"
    export INFISICAL_SMOKE_CLIENT_ID
    INFISICAL_SMOKE_CLIENT_ID="$(printf '%s' "${response}" | jq -er '.identityUniversalAuth.clientId')"
    response="$(infisical_api POST "/api/v1/auth/universal-auth/identities/${identity_id}/client-secrets" \
        '{"description":"Disposable smoke test","ttl":3600}')"
    export INFISICAL_SMOKE_CLIENT_SECRET
    INFISICAL_SMOKE_CLIENT_SECRET="$(printf '%s' "${response}" | jq -er '.clientSecret')"
    export INFISICAL_SMOKE_TOKEN=""
    if [[ "${GITHUB_ACTIONS:-}" == true ]]; then
        printf '::add-mask::%s\n' "${INFISICAL_ACCESS_TOKEN}" "${INFISICAL_SMOKE_CLIENT_SECRET}"
    fi
}

infisical_local_trust_plugin() {
    if [[ -n "${INFISICAL_LOCAL_DIR:-}" ]]; then
        mkdir -p "${REPO_ROOT}/plugin/rootfs/etc/ssl/certs"
        cp "${INFISICAL_LOCAL_DIR}/server.crt" "${REPO_ROOT}/plugin/rootfs/etc/ssl/certs/infisical-smoke.pem"
    fi
}

infisical_local_stop() {
    if [[ -n "${INFISICAL_LOCAL_DIR:-}" ]]; then
        infisical_local_compose down -v --remove-orphans >/dev/null 2>&1 || true
        rm -rf "${INFISICAL_LOCAL_DIR}"
        rm -f "${REPO_ROOT}/plugin/rootfs/etc/ssl/certs/infisical-smoke.pem"
    fi
}
