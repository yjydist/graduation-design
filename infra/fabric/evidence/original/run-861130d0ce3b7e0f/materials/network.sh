#!/bin/sh
set -eu
umask 077
cd "$(dirname "$0")/../.."
repo=$PWD
case "$(uname -s)" in Darwin) platform=darwin-arm64 ;; Linux) platform=linux-arm64 ;; *) exit 1 ;; esac
tools="$repo/.local/fabric-tools/3.1.5-$platform"
export FABRIC_INSTANCE=${FABRIC_INSTANCE:-"$repo/.local/fabric-d0"}
channel=procurement
action=${1:-}
[ "$#" -eq 0 ] || shift

if [ "$action" = rebuild ]; then
    [ "$#" -ge 1 ] || { echo 'rebuild requires a new instance directory [base-port]' >&2; exit 2; }
    export FABRIC_INSTANCE=$1
    [ ! -e "$FABRIC_INSTANCE" ] || { echo 'rebuild target already exists' >&2; exit 2; }
    export FABRIC_PORT=${2:-17100}
    action=up
    set --
fi

init() {
    sh infra/fabric/tools.sh
    if [ -f "$FABRIC_INSTANCE/network.env" ]; then
        return
    fi
    [ ! -e "$FABRIC_INSTANCE" ] || { echo 'instance directory exists without a completed initialization' >&2; exit 1; }
    base=${FABRIC_PORT:-17000}
    case "$base" in ''|*[!0-9]*) exit 2 ;; esac
    [ "$base" -ge 1024 ] && [ "$base" -le 65526 ] || exit 2
    mkdir -p "$(dirname "$FABRIC_INSTANCE")"
    mkdir "$FABRIC_INSTANCE"
    sh infra/fabric/channel.sh crypto > "$FABRIC_INSTANCE/cryptogen.yaml"
    sh infra/fabric/channel.sh config > "$FABRIC_INSTANCE/configtx.yaml"
    "$tools/bin/cryptogen" generate --config="$FABRIC_INSTANCE/cryptogen.yaml" --output="$FABRIC_INSTANCE/crypto"
    FABRIC_CFG_PATH="$FABRIC_INSTANCE" "$tools/bin/configtxgen" -profile Procurement -channelID "$channel" -outputBlock "$FABRIC_INSTANCE/genesis.pb"
    openssl rand -hex 24 > "$FABRIC_INSTANCE/view-password"
    cat > "$FABRIC_INSTANCE/network.env" <<ENV
COMPOSE_PROJECT_NAME=grad-fabric-$(openssl rand -hex 6)
FABRIC_PEER_A=$base
FABRIC_PEER_B=$((base+1))
FABRIC_PEER_C=$((base+2))
FABRIC_ORDERER_A=$((base+3))
FABRIC_ADMIN_A=$((base+4))
FABRIC_ADMIN_B=$((base+5))
FABRIC_ADMIN_C=$((base+6))
FABRIC_ADMIN_D=$((base+7))
FABRIC_ADMIN_X=$((base+8))
FABRIC_DB=$((base+9))
ENV
}

compose() {
    docker compose --env-file "$FABRIC_INSTANCE/network.env" -f "$repo/infra/fabric/compose.yaml" "$@"
}

peer_cli() {
    org=$1
    user=$2
    shift 2
    case "$org" in a) port=$FABRIC_PEER_A ;; b) port=$FABRIC_PEER_B ;; c) port=$FABRIC_PEER_C ;; *) return 2 ;; esac
    home_org="$FABRIC_INSTANCE/crypto/peerOrganizations/$org.local"
    FABRIC_CFG_PATH="$tools/config" \
        CORE_PEER_ADDRESS="127.0.0.1:$port" \
        CORE_PEER_LOCALMSPID="$(printf '%s' "$org" | tr '[:lower:]' '[:upper:]')Msp" \
        CORE_PEER_MSPCONFIGPATH="$home_org/users/$user@$org.local/msp" \
        CORE_PEER_TLS_ENABLED=true \
        CORE_PEER_TLS_ROOTCERT_FILE="$home_org/peers/peer-$org.$org.local/tls/ca.crt" \
        CORE_PEER_CLIENT_CONNTIMEOUT=3s "$tools/bin/peer" "$@"
}

orderer_admin() {
    org=$1
    shift
    case "$org" in
        a) port=$FABRIC_ADMIN_A ;; b) port=$FABRIC_ADMIN_B ;; c) port=$FABRIC_ADMIN_C ;;
        d) port=$FABRIC_ADMIN_D ;; x) port=$FABRIC_ADMIN_X ;; *) return 2 ;;
    esac
    tls="$FABRIC_INSTANCE/crypto/ordererOrganizations/o$org.local/users/Admin@o$org.local/tls"
    "$tools/bin/osnadmin" channel "$@" -o "127.0.0.1:$port" --ca-file "$tls/ca.crt" \
        --client-cert "$tls/client.crt" --client-key "$tls/client.key"
}

join() {
    for org in a b c d; do
        i=0
        until orderer_admin "$org" list --channelID "$channel" > "$FABRIC_INSTANCE/orderer-$org.json" 2>&1 &&
                grep -q '"consensusRelation": "consenter"' "$FABRIC_INSTANCE/orderer-$org.json"; do
            orderer_admin "$org" join --channelID "$channel" --config-block "$FABRIC_INSTANCE/genesis.pb" > "$FABRIC_INSTANCE/orderer-$org.join.log" 2>&1 || true
            i=$((i+1))
            if [ "$i" -ge 20 ]; then
                cat "$FABRIC_INSTANCE/orderer-$org.join.log" >&2
                return 1
            fi
            sleep 1
        done
    done
    for org in a b c; do
        i=0
        until peer_cli "$org" Admin channel getinfo -c "$channel" > "$FABRIC_INSTANCE/peer-$org.join.log" 2>&1; do
            peer_cli "$org" Admin channel join -b "$FABRIC_INSTANCE/genesis.pb" >> "$FABRIC_INSTANCE/peer-$org.join.log" 2>&1 || true
            i=$((i+1))
            if [ "$i" -ge 20 ]; then
                cat "$FABRIC_INSTANCE/peer-$org.join.log" >&2
                return 1
            fi
            sleep 1
        done
    done
}

case "$action" in init|config|up) init ;; esac
FABRIC_INSTANCE=$(cd "$FABRIC_INSTANCE" && pwd)
export FABRIC_INSTANCE
set -a
. "$FABRIC_INSTANCE/network.env"
set +a

case "$action" in
    init) ;;
    config) compose --profile '*' config --quiet ;;
    up)
        compose up -d --wait --wait-timeout 45
        join
        if [ -f "$FABRIC_INSTANCE/registry/deployment.json" ]; then
            compose --profile registry up -d --wait --wait-timeout 30 cc-a cc-b cc-c
        fi
        ;;
    down) compose --profile '*' down ;;
    ps|logs|start|stop) compose "$action" "$@" ;;
    compose) compose "$@" ;;
    peer) peer_cli "$@" ;;
    orderer) orderer_admin "$@" ;;
    *) echo 'usage: network.sh {init|config|up|down|rebuild|ps|logs|start|stop|compose|peer|orderer}' >&2; exit 2 ;;
esac
