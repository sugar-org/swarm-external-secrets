#!/bin/bash

WEBHOOK_URL="http://localhost:9095/webhook"

echo "Testing webhook with simulated Vault secret update event..."

# Simulate a secret update event (matching HCP Vault Secrets format)
curl -X POST "$WEBHOOK_URL" \
  -H "Content-Type: application/json" \
  -d '{
    "resource_id": "test-secret-123",
    "resource_name": "secrets/project/test-project/app/test-app",
    "event_id": "secrets.event:TEST123",
    "event_action": "update",
    "event_description": "Update an existing KV secret",
    "event_source": "hashicorp.secrets.secret",
    "event_version": "1",
    "event_payload": {
      "app_name": "test-app",
      "name": "database",
      "organization_id": "00000000-0000-0000-0000-000000000001",
      "principal_id": "00000000-0000-0000-0000-000000000003",
      "project_id": "00000000-0000-0000-0000-000000000002",
      "timestamp": "2026-03-04T18:53:23Z",
      "type": "static",
      "version": 2
    }
  }'

echo -e "\n\n  Testing webhook with simulated secret rotation event..."

curl -X POST "$WEBHOOK_URL" \
  -H "Content-Type: application/json" \
  -d '{
    "resource_id": "test-secret-456",
    "resource_name": "secrets/project/test-project/app/test-app",
    "event_id": "secrets.event:TEST456",
    "event_action": "rotate",
    "event_description": "Rotate a secret",
    "event_source": "hashicorp.secrets.secret",
    "event_version": "1",
    "event_payload": {
      "app_name": "test-app",
      "name": "api-key",
      "organization_id": "00000000-0000-0000-0000-000000000001",
      "principal_id": "00000000-0000-0000-0000-000000000003",
      "project_id": "00000000-0000-0000-0000-000000000002",
      "provider": "mongodb-atlas",
      "timestamp": "2026-03-04T18:54:00Z",
      "type": "rotating",
      "version": 3
    }
  }'

echo -e "\n\n est webhooks sent!"
