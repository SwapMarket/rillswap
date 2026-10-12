#!/usr/bin/env bash
# Reproduce the pinned ERC-4337 / EIP-7702 artifacts under artifacts/:
#   entry-point-v0.7.json            eth-infinitism/account-abstraction v0.7.0 (published npm artifact)
#   execution-install-delegate.json  alchemyplatform/modular-account v1.1.0 (built here, optimized-build profile)
#   sma7702.json                     alchemyplatform/modular-account v1.1.0 SemiModularAccount7702 (built here)
# Needs docker, curl, jq, git, tar. Fails if the rebuilt SMA7702 initcode hash differs from the
# one recorded in the upstream deployment record, so the committed artifact is provably canonical.
set -euo pipefail
cd "$(dirname "$0")"
MA_COMMIT=7e2105743e286cf696ecb2b8a484d2e97c27e153
MA_VERSION=v1.1.0
IMAGE=ghcr.io/foundry-rs/foundry:v1.8.4
EP=0x0000000071727De22E5E9d8BAf0edAc6f37da032
DELEGATE=0x0000000000008e6a39E03C7156e46b238C9E2036
SMA_INITCODE_HASH=0x9474e750bda053a876e8bd08f17a47e7cf057f046015c1a2d3f5cd88f551f02b
WORK=${WORK:-../tmp/account-abstraction-build}
mkdir -p "$WORK" artifacts

if [ ! -d "$WORK/modular-account/.git" ]; then
  git clone https://github.com/alchemyplatform/modular-account.git "$WORK/modular-account"
fi
( cd "$WORK/modular-account" && git checkout --detach "$MA_COMMIT" && git submodule update --init --recursive )
dep() {
  mkdir -p "$WORK/modular-account/node_modules/$1"
  curl -fsSL "https://codeload.github.com/$2/tar.gz/$3" | tar -xz --strip-components=1 -C "$WORK/modular-account/node_modules/$1"
}
# Locked revisions from the repository's pnpm-lock.yaml at $MA_COMMIT.
dep account-abstraction eth-infinitism/account-abstraction d99245ddb2d7bde4d2132757c4394818f1d11da0
dep @erc6900/reference-implementation erc6900/reference-implementation c9b256cfd963a655179fa3cd9ea3f92c73cbfcdd
dep solady Vectorized/solady eb227ea1c5eaa56296e7dd713eb165d5d75891dd
# Container root maps to the invoking user under rootless Docker; the image default user cannot write the mount.
docker run --rm --user 0:0 -e HOME=/tmp -v "$(cd "$WORK/modular-account" && pwd):/work:z" -w /work -e FOUNDRY_PROFILE=optimized-build --entrypoint forge "$IMAGE" build

curl -fsSL https://unpkg.com/@account-abstraction/contracts@0.7.0/artifacts/EntryPoint.json -o "$WORK/EntryPoint.json"
cast() { docker run --rm --entrypoint cast "$IMAGE" "$@"; }
OUT="$WORK/modular-account/out-optimized"
S_INIT=$(jq -r .bytecode.object "$OUT/SemiModularAccount7702.sol/SemiModularAccount7702.json")
ARGS=$(cast abi-encode 'constructor(address,address)' "$EP" "$DELEGATE")
HASH=$(cast keccak "${S_INIT}${ARGS#0x}")
if [ "$HASH" != "$SMA_INITCODE_HASH" ]; then
  echo "SemiModularAccount7702 initcode hash $HASH does not match the upstream record $SMA_INITCODE_HASH" >&2
  exit 1
fi

jq -c '{
  name: "EntryPoint", version: "0.7.0", license: "GPL-3.0",
  source: "https://github.com/eth-infinitism/account-abstraction/tree/v0.7.0",
  artifact: "https://unpkg.com/@account-abstraction/contracts@0.7.0/artifacts/EntryPoint.json",
  create2: { factory: "0x4e59b44847b379578588920ca78fbf26c0b4956c", salt: "0x90d8084deab30c2a37c45e8d47f49f2f7965183cb6990a98943ef94940681de3", address: "0x0000000071727de22e5e9d8baf0edac6f37da032" },
  constructorArgs: [], abi: .abi, bytecode: .bytecode
}' "$WORK/EntryPoint.json" > artifacts/entry-point-v0.7.json
jq -c --arg commit "$MA_COMMIT" --arg version "$MA_VERSION" '{
  name: "ExecutionInstallDelegate", version: $version, license: "GPL-3.0-or-later",
  source: ("https://github.com/alchemyplatform/modular-account/tree/" + $commit), profile: "optimized-build",
  create2: { factory: "0x4e59b44847b379578588920ca78fbf26c0b4956c", salt: "0x0000000000000000000000000000000000000000f025c5072701275be9e38d72", address: "0x0000000000008e6a39e03c7156e46b238c9e2036" },
  constructorArgs: [], abi: .abi, bytecode: .bytecode.object
}' "$OUT/ExecutionInstallDelegate.sol/ExecutionInstallDelegate.json" > artifacts/execution-install-delegate.json
jq -c --arg commit "$MA_COMMIT" --arg version "$MA_VERSION" --arg ep "$EP" --arg delegate "$DELEGATE" --arg hash "$SMA_INITCODE_HASH" '{
  name: "SemiModularAccount7702", version: $version, license: "GPL-3.0-or-later",
  source: ("https://github.com/alchemyplatform/modular-account/tree/" + $commit), profile: "optimized-build",
  create2: { factory: "0x4e59b44847b379578588920ca78fbf26c0b4956c", salt: "0x000000000000000000000000000000000000000000cb62bc96787a01bccd3750", address: "0x77021100bd87b7008e5e1989d0eb38555d0d0000", initcodeHash: $hash },
  constructorArgs: [($ep | ascii_downcase), ($delegate | ascii_downcase)], abi: .abi, bytecode: .bytecode.object
}' "$OUT/SemiModularAccount7702.sol/SemiModularAccount7702.json" > artifacts/sma7702.json
ls -la artifacts
