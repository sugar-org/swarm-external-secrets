#!/usr/bin/env bash

set -ex  # Exit on any error
cd -- "$(dirname -- "$0")" || exit 1

# filepath: /home/sanjay7178/vault-swarm-plugin/test-plugin.sh

RED='\033[0;31m'
GRN='\e[32m'
DEF='\e[0m'

echo -e "${RED}Remove existing plugin if it exists${DEF}"
docker plugin rm vault-secrets-plugin:temp --force 2>/dev/null || true
docker plugin rm vault-secrets-plugin:latest --force 2>/dev/null || true

echo -e "${RED}Build the plugin${DEF}"
docker build -t vault-secrets-plugin:temp ../

echo -e "${RED}Create plugin rootfs${DEF}"
mkdir -p ./plugin/rootfs
docker create --name temp-container vault-secrets-plugin:temp
docker export temp-container | tar -x -C ./plugin/rootfs
docker rm temp-container
docker rmi vault-secrets-plugin:temp

echo -e "${RED}Copy config to plugin directory${DEF}"
cp ../config.json ./plugin/

echo -e "${RED}Create the plugin${DEF}"
docker plugin create vault-secrets-plugin:temp ./plugin

echo -e "${RED}Clean up plugin directory${DEF}"
rm -rf ./plugin

echo -e "${RED}Enable the plugin${DEF}"
docker plugin enable vault-secrets-plugin:temp

echo -e "${RED}Check plugin status${DEF}"
docker plugin ls

# Add debugging and set proper permissions
echo -e "${RED}Set plugin permissions${DEF}"
docker plugin set vault-secrets-plugin:temp gid=0 uid=0

echo -e "${RED}Set plugin configuration${DEF}"
docker plugin set vault-secrets-plugin:temp \
    VAULT_ADDR="https://152.53.244.80:8200" \
    VAULT_AUTH_METHOD="approle" \
    VAULT_ROLE_ID="8ff294a6-9d5c-c5bb-b494-bc0bfe02a97e" \
    VAULT_SECRET_ID="aedde801-0616-18a5-a62d-c6d7eb483cff" \
    VAULT_MOUNT_PATH="secret" \
    VAULT_ENABLE_ROTATION="true" \
    VAULT_ROTATION_INTERVAL="1m"

echo -e "${GRN}Plugin setup complete. Check plugin logs with:${DEF}"
echo "docker plugin inspect vault-secrets-plugin:temp"
