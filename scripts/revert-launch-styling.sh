#!/usr/bin/env bash
set -euo pipefail

# OBSX Security Protocol - Launch Styling Auto-Revert Script
# Restores baseline README and purges temporary launch celebration artifacts

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

echo "[OBSX Revert] Restoring baseline README..."
if [ -f "README.baseline.md" ]; then
  cp README.baseline.md README.md
  echo "[OBSX Revert] README.md restored from README.baseline.md."
else
  echo "[OBSX Revert] Error: README.baseline.md not found!" >&2
  exit 1
fi

echo "[OBSX Revert] Staging changes..."
git add README.md

if git diff --staged --quiet; then
  echo "[OBSX Revert] No changes to commit; README.md is already identical to baseline."
else
  git commit -m "chore: conclude launch week styling & revert to minimalist baseline"
  echo "[OBSX Revert] Committed revert."
  git push origin main
  echo "[OBSX Revert] Pushed revert commit to origin/main successfully."
fi

echo "[OBSX Revert] Auto-revert complete."
