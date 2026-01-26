#!/usr/bin/env bash

set -ex  # Exit on any error
cd -- "$(dirname -- "$0")" || exit 1

RED='\033[0;31m'
BLU='\e[34m'
GRN='\e[32m'
DEF='\e[0m'

# Get Docker username from argument or environment (optional; if omitted, pushing will be skipped)
DOCKER_USERNAME="${1:-${DOCKER_USERNAME:-}}"
if [ -n "$DOCKER_USERNAME" ]; then
    DOCKER_USERNAME="${DOCKER_USERNAME}/"
fi

echo -e "${DEF}Remove existing plugin if it exists${DEF}"
docker plugin disable ${DOCKER_USERNAME}swarm-external-secrets:latest --force 2>/dev/null || true
docker plugin rm ${DOCKER_USERNAME}swarm-external-secrets:latest --force 2>/dev/null || true
echo -e "${DEF}Build the plugin${DEF}"
docker build -t swarm-external-secrets:temp ../

echo -e "${DEF}Create plugin rootfs${DEF}"
# Check if any previous plugin image exists and remove it
mkdir -p ./plugin/rootfs
echo -e "${DEF}Create plugin rootfs${DEF}"
# Remove any existing temporary container that could conflict with the name we want to use
if docker ps -a --format '{{.Names}}' | grep -q '^temp-container$'; then
    echo -e "${DEF}Removing existing temp-container${DEF}"
    docker rm -f temp-container || true
fi

mkdir -p ./plugin/rootfs
docker create --name temp-container swarm-external-secrets:temp
docker export temp-container | tar -x -C ./plugin/rootfs
docker rm temp-container
docker rmi swarm-external-secrets:temp

echo -e "${DEF}Copy config to plugin directory${DEF}"
cp ../config.json ./plugin/

echo -e "${DEF}Create the plugin${DEF}"
docker plugin create ${DOCKER_USERNAME}swarm-external-secrets:latest ./plugin

echo -e "${DEF}Clean up plugin directory${DEF}"
rm -rf ./plugin

# If docker_username is not set, do not attempt to push
if [ -z "$DOCKER_USERNAME" ]; then
    echo -e "${RED}Docker username not provided. Skipping push to registry.${DEF}"
    echo -e "${GRN}Plugin build and enable completed successfully${DEF}"
    echo -e "You can now use this plugin with: docker plugin install ${DOCKER_USERNAME}swarm-external-secrets:latest"
    exit 0
else
    # Use docker plugin push, not docker push
    echo -e "${DEF}Pushing plugin to registry${DEF}"
    if docker plugin push ${DOCKER_USERNAME}swarm-external-secrets:latest; then
        echo -e "${GRN}Successfully pushed plugin to Docker Hub${DEF}"
        echo -e "${GRN}Plugin build, enable, and push completed successfully${DEF}"
        echo -e "You can now use this plugin with: docker plugin install ${DOCKER_USERNAME}swarm-external-secrets:latest"
    else
        echo -e "${DEF}Failed to push plugin. Make sure you're logged in with 'docker login'${DEF}"
        echo "Run: docker login -u ${DOCKER_USERNAME}"
        exit 1
    fi
fi

# Important: Enable the plugin before pushing
# echo -e "${DEF}Enable the plugin${DEF}"
# docker plugin enable sanjay7178/swarm-external-secrets:latest

# # Set privileges if needed
# echo -e "${DEF}Setting plugin permissions${DEF}"
# docker plugin set sanjay7178/swarm-external-secrets:latest gid=0 uid=0 || echo "Skipping permission setting (plugin may already be enabled)"
