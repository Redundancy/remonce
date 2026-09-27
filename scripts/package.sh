#!/usr/bin/env bash
# Package a release build of remonce for one target.
#
#   scripts/package.sh <version> <target>
#
# Expects `cargo build --release --bin remonce --target <target>` to have
# run. Writes dist/remonce-v<version>-<target>.{tar.gz|zip} and a .sha256
# next to it. The UI is compiled into the binary; the archive adds what a
# host owner edits (a sample config.toml and policy/), the local identity
# provider used by GETTING_STARTED.md, and the docs.
set -euo pipefail
cd "$(dirname "$0")/.."

version=${1:?usage: package.sh <version> <target>}
target=${2:?usage: package.sh <version> <target>}
name="remonce-v${version}-${target}"

case "$target" in
    *windows*) exe=remonce.exe ;;
    *) exe=remonce ;;
esac
binary="target/${target}/release/${exe}"
[ -f "$binary" ] || { echo "error: $binary not found; build it first" >&2; exit 1; }

stage="dist/${name}"
rm -rf "$stage"
mkdir -p "$stage"

cp "$binary" "$stage/"
cp -r policy "$stage/"
cp config.toml "$stage/config.toml"
# The local identity provider, so the tutorial works from a release too.
cp start_services.sh start_services.bat configure_local.ps1 vault_setup.tf "$stage/"
cp readme.md GETTING_STARTED.md CONFIGURATION.md ARCHITECTURE.md SECURITY.md USECASES.md \
    PRODUCTION_READINESS.md alternatives.md "$stage/"
mkdir -p "$stage/docs"
cp -r docs/idp docs/images "$stage/docs/"
[ -f LICENSE ] && cp LICENSE "$stage/"

cd dist
case "$target" in
    *windows*)
        archive="${name}.zip"
        rm -f "$archive"
        powershell -NoProfile -Command "Compress-Archive -Path '${name}' -DestinationPath '${archive}'"
        ;;
    *)
        archive="${name}.tar.gz"
        tar -czf "$archive" "$name"
        ;;
esac
sha256sum "$archive" > "${archive}.sha256"
echo "dist/${archive}"
