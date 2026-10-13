#!/usr/bin/env bash
# Preview or create a GitHub release from conventional commits on origin/main.
# Version bump uses semantic-release commit-analyzer (Angular preset):
#   feat: → minor, fix:/perf: → patch, BREAKING CHANGE / feat!: → major
#   ci:/chore:/docs:/test:/refactor: → no release
# This does not run in CI. Creating a GitHub Release triggers Publish Docker Plugin.

set -euo pipefail

cd -- "$(dirname -- "$0")/.." || exit 1

DRY_RUN=false
if [[ "${1:-}" == "--dry-run" ]]; then
  DRY_RUN=true
elif [[ -n "${1:-}" ]]; then
  echo "Usage: $0 [--dry-run]" >&2
  exit 2
fi

ROOT="$(pwd)"
WORKDIR=""

cleanup() {
  if [[ -n "${WORKDIR}" && -d "${WORKDIR}" ]]; then
    rm -rf "${WORKDIR}"
  fi
  git -C "${ROOT}" branch -D makim-release-preview >/dev/null 2>&1 || true
}
trap cleanup EXIT

semantic_release() {
  if command -v bunx >/dev/null 2>&1; then
    bunx semantic-release "$@"
  elif command -v npx >/dev/null 2>&1; then
    npx --yes semantic-release "$@"
  else
    echo "bunx or npx is required to run semantic-release" >&2
    exit 1
  fi
}

if [[ -z "${GITHUB_TOKEN:-${GH_TOKEN:-}}" ]] && command -v gh >/dev/null 2>&1; then
  token="$(gh auth token 2>/dev/null || true)"
  if [[ -n "${token}" ]]; then
    export GITHUB_TOKEN="${token}"
  fi
fi

git fetch origin main --tags

# semantic-release only accepts release branches that exist on the remote
# (git ls-remote). A local preview branch is invisible to that check, and a
# second worktree cannot check out main while this repo already has it.
ORIGIN_URL="$(git remote get-url origin)"
WORKDIR="$(mktemp -d)"
git clone --quiet --local "${ROOT}" "${WORKDIR}"
cd "${WORKDIR}"
git remote set-url origin "${ORIGIN_URL}"
git fetch origin main --tags
git checkout -q -B main origin/main

echo "Analyzing origin/main at $(git rev-parse --short HEAD) (latest tag: $(git describe --tags --abbrev=0))"

log="$(
  semantic_release \
    --dry-run \
    --no-ci \
    --branches main \
    --plugins @semantic-release/commit-analyzer \
    --verify-conditions "" \
    2>&1 | tee /dev/stderr
)" || {
  echo "semantic-release failed. Ensure bunx/npx can run, git can fetch origin, and you have push access to the repo." >&2
  exit 1
}

if grep -q "There are no relevant changes, so no new version is released" <<<"${log}"; then
  echo "No release-worthy commits on origin/main since $(git describe --tags --abbrev=0)."
  exit 0
fi

VERSION="$(sed -nE 's/.*The next release version is ([0-9]+\.[0-9]+\.[0-9]+).*/\1/p' <<<"${log}" | tail -1)"
if [[ -z "${VERSION}" ]]; then
  echo "Could not parse the next version from semantic-release output." >&2
  exit 1
fi

TAG="v${VERSION}"
SHA="$(git rev-parse origin/main)"

if ${DRY_RUN}; then
  echo "Dry-run: would create GitHub release ${TAG} at ${SHA}"
  echo "Cut with: makim release.cut"
  exit 0
fi

if ! command -v gh >/dev/null 2>&1; then
  echo "gh is required to create a GitHub release" >&2
  exit 1
fi

if git rev-parse -q --verify "refs/tags/${TAG}" >/dev/null; then
  echo "Tag ${TAG} already exists" >&2
  exit 1
fi

echo "Creating GitHub release ${TAG} at ${SHA}"
gh release create "${TAG}" \
  --title "${TAG}" \
  --target "${SHA}" \
  --generate-notes

echo "Created ${TAG}. Publish Docker Plugin runs on the published release."
