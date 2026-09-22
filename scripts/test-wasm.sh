#!/bin/sh
set -eu

image='emscripten/emsdk@sha256:e077d54e2b8970575ebc4f185ac1de0b95c05f2b266134d4ba27449af7aebf65'
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

docker run --rm \
  --volume "$root:/src:Z" \
  --workdir /src \
  "$image" \
  emcmake cmake -S . -B tmp/wasm -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=OFF

docker run --rm \
  --volume "$root:/src:Z" \
  --workdir /src \
  "$image" \
  cmake --build tmp/wasm --target rill_crypto_wasm --parallel

docker run --rm \
  --volume "$root:/src:Z" \
  --workdir /src \
  "$image" \
  node tests/ffi/wasm_smoke.mjs
