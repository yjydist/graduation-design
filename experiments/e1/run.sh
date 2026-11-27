#!/usr/bin/env bash
set -euo pipefail

experiment=$(cd "$(dirname "$0")" && pwd)
repo=$(git -C "$experiment" rev-parse --show-toplevel)
cd "$repo"

exec mise run experiment:run -- --experiment E1 "$@"
