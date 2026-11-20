#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 3 ]; then
    printf 'Usage: %s <revision> <new-instance-directory> <base-port>\n' "$0" >&2
    exit 2
fi

experiment=$(cd "$(dirname "$0")" && pwd)
repo=$(git -C "$experiment" rev-parse --show-toplevel)
cd "$repo"

exec mise exec -- go run ./experiments/runner run \
    --experiment E1 \
    --revision "$1" \
    --instance "$2" \
    --port "$3"
