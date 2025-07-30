#!/usr/bin/env bash

set -ex  # Exit on any error
cd -- "$(dirname -- "$0")" || exit 1

# Check if service ID is provided
if [ $# -eq 0 ]; then
  echo "Please provide the service ID as argument"
  echo "Usage: $0 <service-id>"
  exit 1
fi

SERVICE_ID=$1

# Check if service exists
if ! docker service inspect "$SERVICE_ID" &>/dev/null; then
  echo "Service $SERVICE_ID not found"
  exit 1
fi

echo "=== Service Details ==="
docker service inspect --pretty "$SERVICE_ID"

echo -e "\n=== Service Tasks ==="
docker service ps "$SERVICE_ID"

echo -e "\n=== Plugin Status ==="
PLUGIN_NAME=$(docker service inspect -f '{{index .Spec.TaskTemplate.PluginSpec "Name"}}' "$SERVICE_ID")
echo "Plugin Name: $PLUGIN_NAME"

# If the plugin is actually installed locally, show its status
if docker plugin inspect "$PLUGIN_NAME" &>/dev/null; then
  echo -e "\n=== Local Plugin Details ==="
  docker plugin inspect "$PLUGIN_NAME" | grep -E 'Name|Enabled|Config'
fi

echo -e "\n=== Node Status ==="
# Check for nodes running the service
docker node ls

echo -e "\nNOTE: The 'docker service logs' command doesn't work with plugin services."
echo "Use these commands for troubleshooting:"
echo "  - docker service inspect $SERVICE_ID"
echo "  - docker service ps $SERVICE_ID"
echo "  - docker node ls"
