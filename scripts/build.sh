#!/usr/bin/env bash

set -ex  # Exit on any error
cd -- "$(dirname -- "$0")" || exit 1

RED='\033[0;31m'
BLU='\e[34m'
GRN='\e[32m'
DEF='\e[0m'

echo -e "${DEF}Remove existing plugin if it exists${DEF}"
docker plugin disable sanjay7178/vault-secrets-plugin:latest --force 2>/dev/null || true
docker plugin rm sanjay7178/vault-secrets-plugin:latest --force 2>/dev/null || true

echo -e "${DEF}Build the plugin${DEF}"
docker build -t vault-secrets-plugin:temp ../

echo -e "${DEF}Create plugin rootfs${DEF}"
mkdir -p ./plugin/rootfs
docker create --name temp-container vault-secrets-plugin:temp
docker export temp-container | tar -x -C ./plugin/rootfs
docker rm temp-container
docker rmi vault-secrets-plugin:temp

echo -e "${DEF}Copy config to plugin directory${DEF}"
cp ../config.json ./plugin/

echo -e "${DEF}Create the plugin${DEF}"
docker plugin create sanjay7178/vault-secrets-plugin:latest ./plugin

echo -e "${DEF}Clean up plugin directory${DEF}"
rm -rf ./plugin

# Use docker plugin push, not docker push
echo -e "${DEF}Pushing plugin to registry${DEF}"
if docker plugin push sanjay7178/vault-secrets-plugin:latest; then
    echo -e "${GRN}Successfully pushed plugin to Docker Hub${DEF}"
else
    echo -e "${DEF}Failed to push plugin. Make sure you're logged in with 'docker login'${DEF}"
    echo "Run: docker login -u sanjay7178"
    exit 1
fi

echo -e "${GRN}Plugin build, enable, and push completed successfully${DEF}"
echo -e "You can now use this plugin with: docker plugin install sanjay7178/vault-secrets-plugin:latest"


# Important: Enable the plugin before pushing
# echo -e "${DEF}Enable the plugin${DEF}"
# docker plugin enable sanjay7178/vault-secrets-plugin:latest

# # Set privileges if needed
# echo -e "${DEF}Setting plugin permissions${DEF}"
# docker plugin set sanjay7178/vault-secrets-plugin:latest gid=0 uid=0 || echo "Skipping permission setting (plugin may already be enabled)"
