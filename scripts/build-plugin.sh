#!/usr/bin/env bash

set -euo pipefail

IMAGE_NAME="${1:-swarm-external-secrets:test}"
PLUGIN_NAME="${2:-test-org/swarm-external-secrets:test}"

docker build -t "${IMAGE_NAME}" .
mkdir -p ./plugin/rootfs
docker create --name plugin-rootfs "${IMAGE_NAME}"
docker export plugin-rootfs | tar -x -C ./plugin/rootfs
docker rm plugin-rootfs
cp config.json ./plugin/
docker plugin create "${PLUGIN_NAME}" ./plugin
docker plugin inspect "${PLUGIN_NAME}"
