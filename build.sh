#!/usr/bin/env bash

set -ex

# Color codes
RED='\033[0;31m'
BLU='\e[34m'
GRN='\e[32m'
DEF='\e[0m'

# Get Docker username from argument or environment
DOCKER_USERNAME="${1:-${DOCKER_USERNAME:-}}"

if [ -z "$DOCKER_USERNAME" ]; then
    echo -e "${RED}Error: Docker username is required${DEF}"
    echo "Usage: ./build.sh <docker-username>"
    echo "   or: DOCKER_USERNAME=<username> ./build.sh"
    exit 1
fi

PLUGIN_NAME="${DOCKER_USERNAME}/vault-secrets-plugin:latest"
TEMP_IMAGE="vault-secrets-plugin:temp"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo -e "${BLU}Building plugin for: ${PLUGIN_NAME}${DEF}"

# Remove existing plugin if it exists
echo -e "${DEF}Removing existing plugin if it exists${DEF}"
docker plugin disable "$PLUGIN_NAME" --force 2>/dev/null || true
docker plugin rm "$PLUGIN_NAME" --force 2>/dev/null || true

# Build Docker image
echo -e "${DEF}Building Docker image${DEF}"
docker build -t "$TEMP_IMAGE" "$SCRIPT_DIR"

# Create plugin rootfs
echo -e "${DEF}Creating plugin rootfs${DEF}"
mkdir -p "$SCRIPT_DIR/plugin/rootfs"
docker create --name temp-container "$TEMP_IMAGE"
docker export temp-container | tar -x -C "$SCRIPT_DIR/plugin/rootfs"
docker rm temp-container
docker rmi "$TEMP_IMAGE"

# Copy config to plugin directory
echo -e "${DEF}Copying config.json to plugin directory${DEF}"
cp "$SCRIPT_DIR/config.json" "$SCRIPT_DIR/plugin/"

# Create the plugin
echo -e "${DEF}Creating Docker plugin${DEF}"
docker plugin create "$PLUGIN_NAME" "$SCRIPT_DIR/plugin"

# Clean up
echo -e "${DEF}Cleaning up temporary files${DEF}"
rm -rf "$SCRIPT_DIR/plugin"

# Push to registry
echo -e "${DEF}Pushing plugin to Docker registry${DEF}"
if docker plugin push "$PLUGIN_NAME"; then
    echo -e "${GRN}Successfully pushed plugin to Docker Hub${DEF}"
    echo -e "${GRN}Plugin is ready: $PLUGIN_NAME${DEF}"
    echo -e "${DEF}To use this plugin run: docker plugin install $PLUGIN_NAME${DEF}"
else
    echo -e "${RED}Failed to push plugin${DEF}"
    echo -e "${DEF}Make sure you're logged in with: docker login${DEF}"
    exit 1
fi

echo -e "${GRN}Build completed successfully!${DEF}"
