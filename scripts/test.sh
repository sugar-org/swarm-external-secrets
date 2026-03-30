#!/usr/bin/env bash

set -ex  # Exit on any error
cd -- "$(dirname -- "$0")" || exit 1

# filepath: /home/sanjay7178/vault-swarm-plugin/test-plugin.sh

RED='\033[0;31m'
GRN='\e[32m'
DEF='\e[0m'

echo -e "${RED}Remove existing plugin if it exists${DEF}"
docker plugin rm swarm-external-secrets:temp --force 2>/dev/null || true
docker plugin rm swarm-external-secrets:latest --force 2>/dev/null || true

echo -e "${RED}Build the plugin${DEF}"
docker build -t swarm-external-secrets:temp ../

echo -e "${RED}Create plugin rootfs${DEF}"
mkdir -p ./plugin/rootfs
docker create --name temp-container swarm-external-secrets:temp
docker export temp-container | tar -x -C ./plugin/rootfs
docker rm temp-container
docker rmi swarm-external-secrets:temp

echo -e "${RED}Copy config to plugin directory${DEF}"
cp ../config.json ./plugin/

echo -e "${RED}Create the plugin${DEF}"
docker plugin create swarm-external-secrets:temp ./plugin

echo -e "${RED}Clean up plugin directory${DEF}"
rm -rf ./plugin

echo -e "${RED}Set plugin configuration${DEF}"
docker plugin set swarm-external-secrets:temp \
    SECRETS_PROVIDER="aws" \
    AWS_REGION="us-east-1" \
    ENABLE_ROTATION="false" \
    ENABLE_MONITORING="false" \
    gid=0 \
    uid=0

echo -e "${RED}Enable the plugin${DEF}"
docker plugin enable swarm-external-secrets:temp

echo -e "${RED}Check plugin status${DEF}"
docker plugin ls

echo -e "${GRN}Plugin setup complete. Check plugin logs with:${DEF}"
echo "docker plugin inspect swarm-external-secrets:temp"
