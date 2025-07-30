#!/usr/bin/env bash

set -ex  # Exit on any error
cd -- "$(dirname -- "$0")" || exit 1

# Cleanup script for the Vault Secrets Plugin
docker plugin disable vault-secrets-plugin:latest --force 2>/dev/null || true
docker plugin disable sanjay7178/vault-secrets-plugin:latest --force 2>/dev/null || true
docker plugin rm vault-secrets-plugin:latest --force 2>/dev/null || true    
docker image rm vault-secrets-plugin:temp --force 2>/dev/null || true
docker swarm leave --force 2>/dev/null || true
docker swarm init --advertise-addr 127.0.0.1
