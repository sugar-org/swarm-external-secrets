#!/usr/bin/env bash
set -ex  # Exit on any error
cd -- "$(dirname -- "$0")" || exit 1
# Vault Secret Rotation Demo Script
# This script demonstrates the automatic secret rotation feature
set -e
RED='\033[0;31m'
GRN='\033[0;32m'
BLU='\033[0;34m'
DEF='\033[0m'
echo -e "${BLU}=== Vault Secret Rotation Demo ===${DEF}"
echo
# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}
# Check prerequisites
echo -e "${BLU}Checking prerequisites...${DEF}"
if ! command_exists docker; then
    echo -e "${RED}Error: Docker is not installed${DEF}"
    exit 1
fi
if ! command_exists vault; then
    echo -e "${RED}Warning: Vault CLI is not installed. Some demo steps may be skipped.${DEF}"
fi
echo -e "${GRN}Prerequisites check passed${DEF}"
echo
# Build the plugin
echo -e "${BLU}Building the plugin with rotation feature...${DEF}"
./build.sh
echo -e "${BLU}Setting up plugin configuration with rotation enabled...${DEF}"
docker plugin set swarm-external-secrets:latest \
    VAULT_ADDR="https://your-vault-address:8200" \
    VAULT_AUTH_METHOD="token" \
    VAULT_TOKEN="your-vault-token" \
    VAULT_MOUNT_PATH="secret" \
    VAULT_ENABLE_ROTATION="true" \
    VAULT_ROTATION_INTERVAL="30s" || echo "Plugin configuration may already be set"
echo -e "${GRN}Plugin configured with 30-second rotation interval${DEF}"
echo
# Create a simple demo stack
echo -e "${BLU}Creating demo docker-compose.yml with automatic rotation...${DEF}"
cat > demo-compose.yml << 'EOF'
version: '3.8'
services:
  demo-app:
    image: busybox:latest
    command: >
      sh -c "
        echo 'Demo App Started - Monitoring secret changes...'
        while true; do
          echo 'Current secret value:' && cat /run/secrets/demo_secret || echo 'Secret not available'
          sleep 10
        done
      "
    secrets:
      - demo_secret
    deploy:
      replicas: 1
      restart_policy:
        condition: any
    networks:
      - demo-network
secrets:
  demo_secret:
    driver: swarm-external-secrets:latest
    labels:
      vault_path: "demo/app"
      vault_field: "password"
networks:
  demo-network:
    driver: overlay
EOF
echo -e "${GRN}Demo compose file created${DEF}"
echo
# Display the rotation configuration
echo -e "${BLU}Current rotation configuration:${DEF}"
echo "- Rotation enabled: true"
echo "- Check interval: 30 seconds"
echo "- Vault path: demo/app"
echo "- Secret field: password"
echo
echo -e "${BLU}=== Demo Instructions ===${DEF}"
echo
echo "1. Deploy the demo stack:"
echo "   docker stack deploy -c demo-compose.yml demo"
echo
echo "2. Monitor the demo app logs:"
echo "   docker service logs -f demo_demo-app"
echo
echo "3. In another terminal, update the secret in Vault:"
echo "   vault kv put secret/demo/app password=new_password_$(date +%s)"
echo
echo "4. Watch the logs - within 30 seconds you should see:"
echo "   - Plugin detecting the secret change"
echo "   - Docker secret being updated"
echo "   - Service being redeployed"
echo "   - Demo app showing the new secret value"
echo
echo "5. Clean up when done:"
echo "   docker stack rm demo"
echo "   rm demo-compose.yml"
echo
echo -e "${BLU}=== Rotation Feature Summary ===${DEF}"
echo
echo "The implemented rotation feature provides:"
echo "✓ Automatic secret change detection via SHA256 hashing"
echo "✓ Background monitoring with configurable intervals"
echo "✓ Seamless Docker secret updates without downtime"
echo "✓ Automatic service redeployment to pick up new secrets"
echo "✓ Comprehensive logging for audit trails"
echo "✓ Graceful cleanup of old secret versions"
echo
echo -e "${GRN}Demo setup complete! Follow the instructions above to see rotation in action.${DEF}"