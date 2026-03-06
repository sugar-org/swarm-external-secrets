#!/bin/bash
set -e

RED='\033[0;31m'
GRN='\033[0;32m'
BLU='\033[0;34m'
DEF='\033[0m'

echo -e "${BLU}=== Testing Webhook Feature ===${DEF}"

#Build the plugin
echo -e "${BLU}Step 1: Building plugin...${DEF}"
cd scripts
bash build.sh

# 2. Configure plugin with webhook enabled
echo -e "${BLU}Step 2: Configuring plugin with webhook mode...${DEF}"
docker plugin set swarm-external-secrets:latest \
    SECRETS_PROVIDER="vault" \
    VAULT_ADDR="http://host.docker.internal:8200" \
    VAULT_TOKEN="root-token" \
    VAULT_MOUNT_PATH="secret" \
    USE_WEBHOOK="true" \
    WEBHOOK_PORT="9095" \
    WEBHOOK_SECRET="" \
    ENABLE_ROTATION="true" \
    ROTATION_INTERVAL="10s" \
    ENABLE_MONITORING="false"

echo -e "${GRN}Plugin configured with webhook mode${DEF}"

# 3. Enable plugin
echo -e "${BLU}Step 3: Enabling plugin...${DEF}"
docker plugin enable swarm-external-secrets:latest

# 4. Wait for plugin to start
sleep 5

# 5. Check plugin logs for webhook startup message
echo -e "${BLU}Step 4: Checking plugin logs for webhook mode...${DEF}"
docker plugin inspect swarm-external-secrets:latest --format '{{.ID}}' > /tmp/plugin_id.txt
PLUGIN_ID=$(cat /tmp/plugin_id.txt)

echo -e "${BLU}Looking for webhook startup in logs...${DEF}"
timeout 10 bash -c "
    while true; do
        if sudo journalctl -u docker.service --since '1 minute ago' | grep -q 'WEBHOOK mode'; then
            echo -e '${GRN}✅ Found webhook mode startup message${DEF}'
            break
        fi
        sleep 1
    done
" || echo -e "${RED}⚠️  Timeout waiting for webhook message${DEF}"

# Show relevant logs
echo -e "${BLU}Recent plugin logs:${DEF}"
sudo journalctl -u docker.service --since '1 minute ago' | grep -i webhook || true

echo -e "${GRN}=== Test completed ===${DEF}"
echo -e "${BLU}To send a test webhook:${DEF}"
echo "curl -X POST http://localhost:9095/webhook -H 'Content-Type: application/json' -d '{
  \"event_action\": \"update\",
  \"event_payload\": {
    \"name\": \"test-secret\",
    \"app_name\": \"test-app\"
  }
}'"

echo -e "\n${BLU}To disable webhook mode and use ticker:${DEF}"
echo "docker plugin disable swarm-external-secrets:latest"
echo "docker plugin set swarm-external-secrets:latest USE_WEBHOOK=false"
echo "docker plugin enable swarm-external-secrets:latest"
