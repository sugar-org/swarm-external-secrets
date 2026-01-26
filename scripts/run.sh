#!/usr/bin/env bash

set -ex  # Exit on any error
cd -- "$(dirname -- "$0")" || exit 1

./plugin_installer/plugin_installer
until [[ "$(docker plugin inspect sanjay7178/swarm-external-secrets:latest --format '{{.Enabled}}' 2>/dev/null)" == "true" ]]
do
    echo "waiting for plugin to be installed"
    sleep 1
done

docker node ls --filter role=worker -q | wc -l | grep -q 0 && snitch_role=manager || snitch_role=worker
