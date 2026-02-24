#!/bin/bash
#
# This script provides a one-click setup for the project's Git hooks.
# It installs all necessary Go tools and configures Lefthook.
#
# Usage: ./setup-hooks.sh
#

set -e # Exit immediately if a command exits with a non-zero status.

# --- Helper functions for colored output ---
info() {
    echo -e "\033[34m[INFO]\033[0m $1"
}

success() {
    echo -e "\033[32m[SUCCESS]\033[0m $1"
}

error() {
    echo -e "\033[31m[ERROR]\033[0m $1" >&2
    exit 1
}

# --- 1. Check for prerequisites ---
info "Checking for Go installation..."
if ! command -v go &> /dev/null; then
    error "Go is not installed. Please install Go (https://go.dev/doc/install) and ensure it's in your PATH."
fi
success "Go is installed."

# --- 2. Install required Go tools ---
info "Installing required Go development tools..."
go install github.com/evilmartians/lefthook/v2@latest
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
go install github.com/securego/gosec/v2/cmd/gosec@latest
go install github.com/fzipp/gocyclo/cmd/gocyclo@latest
go install golang.org/x/tools/cmd/goimports@latest
success "All required Go tools are installed."

# --- 3. Activate Lefthook hooks ---
info "Activating Lefthook Git hooks..."

BIN_DIR=$(go env GOBIN)
if [ -z "$BIN_DIR" ]; then
  BIN_DIR="$(go env GOPATH)/bin"   # falls back to $HOME/go/bin when GOPATH is unset
fi

# Add it to PATH if it isn't there already
case ":$PATH:" in
  *":$BIN_DIR:"*) ;;                     # already present → do nothing
  *) export PATH="$BIN_DIR:$PATH" ;;     # prepend so your own tools win
esac
# -----

lefthook install

success "Lefthook pre-commit hooks are now installed and active!"
info "On your next 'git commit', the checks will run automatically."
