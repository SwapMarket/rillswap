#!/usr/bin/env bash
# Offline checks of a built provider image through compose.yaml: the bundled
# tools start, the native library loads, and the documented setup flow
# (core-credential, maker init, provision-store) works under the compose
# hardening and refuses to overwrite. Used by CI before publishing; run it
# locally with: rill-provider/docker/smoke-test.sh rill-provider:test
set -euo pipefail

image=${1:?usage: smoke-test.sh IMAGE}
here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d)
project=rill-smoke-$$
trap 'docker compose -p "$project" --project-directory "$work" --profile "*" down -v >/dev/null 2>&1 || true; rm -rf "$work"' EXIT

run() { docker run --rm --read-only --cap-drop ALL "$image" "$@"; }
run rill-provider --help >/dev/null
run rill --help >/dev/null
run tor --version
run python -c 'import ctypes; ctypes.CDLL("/opt/rill/native/librill_crypto.so")'

cp "$here/compose.yaml" "$work/"
# Rootless Docker maps container root to the invoking user; rootful Docker
# needs the invoking uid so the provider owns the files it creates.
if docker info -f '{{.SecurityOptions}}' | grep -q rootless; then uid=0 gid=0; else uid=$(id -u) gid=$(id -g); fi
cat >"$work/.env" <<EOF
COMPOSE_PROFILES=btc-to-ln
RILL_PROVIDER_IMAGE=$image
RILL_UID=$uid
RILL_GID=$gid
EOF
install -d -m 0700 "$work/makers" "$work/stores" "$work/credentials"
compose() { docker compose -p "$project" --project-directory "$work" "$@"; }
compose config --quiet

compose run --rm setup rill-provider-init core-credential | grep -q '^rpcauth=__cookie__:'
grep -q '^__cookie__:' "$work/credentials/core.cookie"
compose run --rm setup rill-provider-init maker --profile btc-to-ln --network signet \
    --destination-script "0014$(printf '11%.0s' {1..20})" --affirm-store-authority
compose run --rm setup rill-provider-init maker --profile ln-to-erc20 --network signet \
    --affirm-store-authority
compose run --rm --no-deps btc-to-ln \
    rill-provider provision-store --config /rill/config/provider.json
test -s "$work/stores/btc-to-ln/live.sqlite"

status=0
compose run --rm setup rill-provider-init maker --profile btc-to-ln --network signet \
    --destination-script "0014$(printf '11%.0s' {1..20})" --affirm-store-authority || status=$?
test "$status" -eq 2
status=0
compose run --rm --no-deps ln-to-erc20 \
    rill-provider provision-store --config /rill/config/provider.json || status=$?
test "$status" -eq 2
echo "smoke test passed: $image"
