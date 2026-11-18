#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 3 ]; then
    printf 'Usage: %s <revision> <new-instance-directory> <base-port>\n' "$0" >&2
    exit 2
fi

experiment=$(cd "$(dirname "$0")" && pwd)
repo=$(git -C "$experiment" rev-parse --show-toplevel)
cd "$repo"
source experiments/llm.env
: "${LLM_PROVIDER:?Set LLM_PROVIDER in experiments/llm.env}"
: "${LLM_BASE_URL:?Set LLM_BASE_URL in experiments/llm.env}"
: "${LLM_MODEL:?Set LLM_MODEL in experiments/llm.env}"
: "${LLM_API_KEY:?Export LLM_API_KEY before running E1}"

revision=$(git rev-parse --verify "$1^{commit}")
case "$2" in
    /*) instance=$2 ;;
    *) instance="$repo/$2" ;;
esac
if [ -e "$instance" ]; then
    printf 'E1 requires a new Fabric instance directory: %s\n' "$instance" >&2
    exit 2
fi

run_id="run-$(openssl rand -hex 8)"
out="$experiment/runs/$run_id"
mkdir "$out"
printf '%s\n' "$out"
stage=build
mkdir -p "$repo/.local"
work=$(mktemp -d "$repo/.local/e1-build.XXXXXX")

finish() {
    status=$?
    if [ ! -e "$out/summary.json" ]; then
        printf '{"runId":"%s","status":"FAIL","stage":"%s","exitCode":%s}\n' "$run_id" "$stage" "$status" > "$out/summary.json"
    fi
    if [ -f "$instance/network.env" ]; then
        FABRIC_INSTANCE="$instance" sh "$work/infra/fabric/network.sh" down > "$out/network-down.log" 2>&1 || true
    fi
}
trap finish EXIT

git archive "$revision" | tar -xf - -C "$work"
mkdir -p "$work/experiments/e1-procurement/driver" "$work/.local"
cp "$experiment"/driver/*.go "$work/experiments/e1-procurement/driver/"
tar -czf "$out/driver-source.tar.gz" -C "$work" experiments/e1-procurement/driver
if [ -d "$repo/.local/fabric-tools" ]; then
    ln -s "$repo/.local/fabric-tools" "$work/.local/fabric-tools"
fi

cd "$work"
mise exec -- go build -o "$work/ledgerctl" ./cmd/ledgerctl > "$out/build.log" 2>&1
mise exec -- go build -o "$work/e1-driver" ./experiments/e1-procurement/driver >> "$out/build.log" 2>&1

stage=network
sh infra/fabric/network.sh rebuild "$instance" "$3" > "$out/network-up.log" 2>&1
stage=experiment
"$work/e1-driver" -revision "$revision" -ledgerctl "$work/ledgerctl" -dir "$instance" -out "$out"
