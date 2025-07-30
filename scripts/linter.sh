#!/usr/bin/env bash

set -ex  # Exit on any error
cd -- "$(dirname -- "$0")" || exit 1

BIN_DIR=$(go env GOBIN)
if [ -z "$BIN_DIR" ]; then
  BIN_DIR="$(go env GOPATH)/bin"   # falls back to $HOME/go/bin when GOPATH is unset
fi

# Add it to PATH if it isn't there already
case ":$PATH:" in
  *":$BIN_DIR:"*) ;;                     # already present → do nothing
  *) export PATH="$BIN_DIR:$PATH" ;;     # prepend so your own tools win
esac

lefthook run pre-commit --verbose --all-files
