#!/bin/sh
# Generate public channel policy and cryptogen inputs. Invoked by network.sh.
set -eu
business_admins="AND('AMsp.admin','BMsp.admin','CMsp.admin')"
endorsement="OutOf(2,'AMsp.peer','BMsp.peer','CMsp.peer')"
clients="OR('AMsp.client','AMsp.admin','BMsp.client','BMsp.admin','CMsp.client','CMsp.admin','TMsp.client')"
readers="OR('AMsp.member','BMsp.member','CMsp.member','TMsp.client','OrdererAMsp.orderer','OrdererBMsp.orderer','OrdererCMsp.orderer','OrdererDMsp.orderer')"
case "$1" in
crypto)
    echo 'OrdererOrgs:'
    for x in a b c d x; do
        n=$x
        [ "$x" != x ] || n=rogue
        cat <<YAML
  - Name: orderer-$n
    Domain: o$x.local
    EnableNodeOUs: true
    Specs:
      - Hostname: orderer-$n
        SANS: [orderer-$n, 127.0.0.1]
YAML
    done
    echo 'PeerOrgs:'
    for x in a b c t x; do
        cat <<YAML
  - Name: org-$x
    Domain: $x.local
    EnableNodeOUs: true
YAML
        case "$x" in
            a|b|c)
                cat <<YAML
    Specs:
      - Hostname: peer-$x
        SANS: [peer-$x, 127.0.0.1]
    Users: {Count: 9}
YAML
                ;;
            t|x) echo '    Users: {Count: 1}' ;;
        esac
    done
    ;;
config)
    echo 'Organizations:'
    for x in a b c t; do
        name=$(printf '%s' "$x" | tr '[:lower:]' '[:upper:]')Msp
        if [ "$x" = t ]; then
            cat <<YAML
  - &$name
    Name: $name
    ID: $name
    MSPDir: crypto/peerOrganizations/$x.local/msp
    Policies:
      Readers: {Type: Signature, Rule: "OR('TMsp.client')"}
      Writers: {Type: Signature, Rule: "OR('TMsp.client')"}
      Admins: {Type: Signature, Rule: "$business_admins"}
YAML
        else
            cat <<YAML
  - &$name
    Name: $name
    ID: $name
    MSPDir: crypto/peerOrganizations/$x.local/msp
    AnchorPeers: [{Host: peer-$x, Port: 7051}]
    Policies:
      Readers: {Type: Signature, Rule: "OR('$name.member')"}
      Writers: {Type: Signature, Rule: "OR('$name.client','$name.admin')"}
      Admins: {Type: Signature, Rule: "OR('$name.admin')"}
      Endorsement: {Type: Signature, Rule: "OR('$name.peer')"}
YAML
        fi
    done
    for x in a b c d; do
        name=Orderer$(printf '%s' "$x" | tr '[:lower:]' '[:upper:]')Msp
        cat <<YAML
  - &$name
    Name: $name
    ID: $name
    MSPDir: crypto/ordererOrganizations/o$x.local/msp
    OrdererEndpoints: [orderer-$x:7050]
    Policies:
      Readers: {Type: Signature, Rule: "OR('$name.member')"}
      Writers: {Type: Signature, Rule: "OR('$name.orderer','$name.admin')"}
      Admins: {Type: Signature, Rule: "OR('$name.admin')"}
YAML
    done
    cat <<YAML
Profiles:
  Procurement:
    Capabilities: {V3_0: true}
    Policies:
      Readers: {Type: Signature, Rule: "$readers"}
      Writers: {Type: Signature, Rule: "$clients"}
      Admins: {Type: Signature, Rule: "$business_admins"}
    Orderer:
      OrdererType: BFT
      BatchTimeout: 200ms
      BatchSize: {MaxMessageCount: 100, AbsoluteMaxBytes: 10 MB, PreferredMaxBytes: 512 KB}
      Capabilities: {V2_0: true}
      SmartBFT:
        RequestBatchMaxCount: 100
        RequestBatchMaxInterval: 200ms
        RequestForwardTimeout: 2s
        RequestComplainTimeout: 5s
        RequestAutoRemoveTimeout: 40s
        ViewChangeResendInterval: 2s
        ViewChangeTimeout: 10s
        LeaderHeartbeatTimeout: 5s
        LeaderHeartbeatCount: 10
        CollectTimeout: 1s
        IncomingMessageBufferSize: 200
        RequestPoolSize: 10000
      Organizations: [*OrdererAMsp, *OrdererBMsp, *OrdererCMsp, *OrdererDMsp]
      Policies:
        Readers: {Type: ImplicitMeta, Rule: "ANY Readers"}
        Writers: {Type: ImplicitMeta, Rule: "ANY Writers"}
        Admins: {Type: ImplicitMeta, Rule: "MAJORITY Admins"}
        BlockValidation: {Type: ImplicitMeta, Rule: "ANY Writers"}
      ConsenterMapping:
YAML
    i=0
    for x in a b c d; do
        i=$((i+1))
        name=Orderer$(printf '%s' "$x" | tr '[:lower:]' '[:upper:]')Msp
        path=crypto/ordererOrganizations/o$x.local/orderers/orderer-$x.o$x.local
        cat <<YAML
        - ID: $i
          Host: orderer-$x
          Port: 7050
          MSPID: $name
          Identity: $path/msp/signcerts/orderer-$x.o$x.local-cert.pem
          ClientTLSCert: $path/tls/server.crt
          ServerTLSCert: $path/tls/server.crt
YAML
    done
    cat <<YAML
    Application:
      Organizations: [*AMsp, *BMsp, *CMsp, *TMsp]
      Capabilities: {V2_5: true}
      Policies:
        Readers: {Type: Signature, Rule: "$readers"}
        Writers: {Type: Signature, Rule: "$clients"}
        Admins: {Type: Signature, Rule: "$business_admins"}
        LifecycleEndorsement: {Type: Signature, Rule: "AND('AMsp.peer','BMsp.peer','CMsp.peer')"}
        Endorsement: {Type: Signature, Rule: "$endorsement"}
YAML
    ;;
*) exit 2 ;;
esac
