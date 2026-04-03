#!/usr/bin/env bash

set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 <stage-number>" >&2
  exit 1
fi

X="$1"

if [[ ! "$X" =~ ^[0-9]+$ ]]; then
  echo "Error: stage number must be numeric." >&2
  exit 1
fi

STAGE_BRANCH="stage${X}"
ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

REPOS=(
  "$ROOT_DIR"
  "$ROOT_DIR/spartan-whir-export"
  "$ROOT_DIR/sol-spartan-whir"
)

for repo in "${REPOS[@]}"; do
  echo "Checking out ${STAGE_BRANCH} in ${repo}"
  git -C "$repo" checkout "$STAGE_BRANCH"
done

echo "Done."
