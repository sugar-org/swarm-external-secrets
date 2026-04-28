#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd)"

bash "${SCRIPT_DIR}/smoke-test-vault.sh"
bash "${SCRIPT_DIR}/smoke-test-openbao.sh"
bash "${SCRIPT_DIR}/smoke-test-awssm.sh"
