#!/usr/bin/env bash

set -ex  # Exit on any error
cd -- "$(dirname -- "$0")" || exit 1

RED='\033[0;31m'
BLU='\e[34m'
GRN='\e[32m'
DEF='\e[0m'

echo -e ${DEF}Remove existing plugin if it exists and stop
docker plugin disable swarm-external-secrets:latest --force 2>/dev/null || true
docker plugin rm swarm-external-secrets:latest --force 2>/dev/null || true

echo -e ${DEF}Build the plugin
docker build  -f ../Dockerfile -t swarm-external-secrets:temp ..

echo -e ${DEF}Create plugin rootfs
mkdir -p ./plugin/rootfs
docker create --name temp-container swarm-external-secrets:temp
docker export temp-container | tar -x -C ./plugin/rootfs
docker rm temp-container
docker rmi swarm-external-secrets:temp

echo -e ${DEF}Copy config to plugin directory
cp ../config.json ./plugin/

# go run plugin_installer/installer.go

echo -e ${DEF}Create the plugin
docker plugin create swarm-external-secrets:latest ./plugin

echo -e ${DEF}Clean up plugin directory
rm -rf ./plugin



# echo -e ${DEF}Set plugin configuration
# docker plugin set swarm-external-secrets:latest \
#     VAULT_ADDR="https://152.53.244.80:8200" \
#     VAULT_AUTH_METHOD="approle" \
#     VAULT_ROLE_ID="" \
#     VAULT_SECRET_ID="" \
#     VAULT_MOUNT_PATH="secret"

# docker plugin set swarm-external-secrets:latest \
#     SECRETS_PROVIDER="vault" \
#     VAULT_ADDR="https://152.53.244.80:8200" \
#     VAULT_AUTH_METHOD="token" \
#     VAULT_TOKEN="" \
#     VAULT_MOUNT_PATH="secret" \
#     VAULT_ENABLE_ROTATION="true" \
#     VAULT_ROTATION_INTERVAL="5s" \
#     ENABLE_MONITORING="true" \
#     MONITORING_PORT="8080"

# docker plugin set swarm-external-secrets:latest \
#     SECRETS_PROVIDER="openbao" \
#     OPENBAO_AUTH_METHOD="token" \
#     OPENBAO_ADDR="" \
#     OPENBAO_TOKEN="" \
#     OPENBAO_MOUNT_PATH="secret" \
#     VAULT_ENABLE_ROTATION="true"

export GOOGLE_CREDENTIALS=$(jq -c . ../graphic-transit-458312-f7-44c20b0e486c.json)
docker plugin set swarm-external-secrets:latest \
    SECRETS_PROVIDER="gcp" \
    GCP_PROJECT_ID="graphic-transit-458312-f7" \
    GCP_CREDENTIALS_JSON="$GOOGLE_CREDENTIALS" \
    ENABLE_ROTATION="true" \
    ROTATION_INTERVAL="5s" \


echo -e ${DEF}Enable the plugin
docker plugin enable swarm-external-secrets:latest


# export VAULT_ROLE_ID="8ff294a6-9d5c-c5bb-b494-bc0bfe02a97e"
# export VAULT_SECRET_ID="aedde801-0616-18a5-a62d-c6d7eb483cff"

# echo -e ${DEF}Enable the plugin compose service
# docker compose up -d  swarm-external-secrets

echo -e ${DEF}Verify the plugin is enabled
docker plugin ls

echo -e ${DEF}Create secrets in Vault first before deploying
echo "Please ensure the following secrets exist in Vault:"
echo "- secret/database/mysql (with root_password and user_password fields)"
# echo "- secret/application/api (with key field)"

docker node ls --filter role=worker -q | wc -l | grep -q 0 && snitch_role=manager || snitch_role=worker
export snitch_role
echo -e ${DEF}Deploy the stack
docker stack deploy -c ../docker-compose.yml myapp

echo -e ${DEF}Verify the deployment
docker stack services myapp

echo -e ${DEF}Check the logs of the service
sleep 5
docker service logs -f myapp_busybox
