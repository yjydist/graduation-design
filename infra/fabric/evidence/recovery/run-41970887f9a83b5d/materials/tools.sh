#!/bin/sh
set -eu
cd "$(dirname "$0")/../.."
version=3.1.5
case "$(uname -sm)" in
    'Darwin arm64') platform=darwin-arm64; digest=d67a5c3366746a984f8ee9ae0ebf5c8b357c9d33dd589fa0b7668d739472cef0 ;;
    'Linux aarch64') platform=linux-arm64; digest=4a42cad740a7e0373eda6bf1e27c86e9b06132f9bb751daf7f0f7dc1d1bbfed9 ;;
    *) echo 'Fabric D0 requires an arm64 host' >&2; exit 1 ;;
esac
dest=".local/fabric-tools/$version-$platform"
archive="hyperledger-fabric-$platform-$version.tar.gz"
if [ -f "$dest/archive.sha256" ] && [ "$(cat "$dest/archive.sha256")" = "$digest" ]; then
    exit 0
fi
mkdir -p .local/fabric-tools
stage=$(mktemp -d .local/fabric-tools/download.XXXXXX)
trap 'rm -rf "$stage"' EXIT
curl -fsSL --retry 2 --max-time 180 "https://github.com/hyperledger/fabric/releases/download/v$version/$archive" -o "$stage/$archive"
actual=$(shasum -a 256 "$stage/$archive" | cut -d ' ' -f 1)
[ "$actual" = "$digest" ] || { echo "Fabric archive digest mismatch" >&2; exit 1; }
tar -xzf "$stage/$archive" -C "$stage" bin config
mkdir -p "$dest"
cp -R "$stage/bin" "$stage/config" "$dest/"
printf '%s\n' "$digest" > "$dest/archive.sha256"
