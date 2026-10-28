# rill-crypto

Native and WebAssembly bindings for the libsecp256k1 operations RillSwap
uses. The API exposes opaque validated keys and one-shot MuSig2 attempt
handles; secret MuSig nonces can never be serialized.

## Build and install

CMake 3.25 or newer and a C compiler. From `rill-crypto/`:

```sh
cmake -S . -B tmp/build -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=ON
cmake --build tmp/build --parallel 2
uv venv --python 3.14 .venv
uv pip install --python .venv/bin/python -e ./python
```

The Python package needs Python 3.13 or newer. CMake downloads libsecp256k1
v0.8.0, pinned to SHA-256
`dd685546f9e717b9adde329acd5a4cd8083d40f710fdb0a603ee5a83f908132b`.

## Usage

Python consumers load the native library explicitly or through
`RILL_CRYPTO_LIBRARY`:

```python
from rill_crypto import Context

with Context(library_path="tmp/build/librill_crypto.so") as context:
    ...
```

`./scripts/test-wasm.sh` (requires Docker) builds the WASM module into
`tmp/wasm/rill_crypto_wasm.mjs` and `tmp/wasm/rill_crypto_wasm.wasm` and runs
a smoke test:

```javascript
import createRillCrypto from "./tmp/wasm/rill_crypto_wasm.mjs";

const wasm = await createRillCrypto();
```

The native library also recovers and verifies compact ECDSA signatures
(`Context.ecdsa_recover`, `Context.ecdsa_verify`) for authenticating BOLT 11
invoice payees in Python. The WASM module does not export them; the browser
decodes invoices with `@noble/curves`.

`wasm/schnorr_verify.ts` provides `createSchnorrVerifier(wasm)` for BIP340
verification; call `destroy()` when finished. Consumers are responsible for
loading the artifacts and verifying their integrity.

## Tests

From `rill-crypto/`:

```sh
ctest --test-dir tmp/build --output-on-failure
uv pip install --python .venv/bin/python -r requirements-dev.txt
RILL_CRYPTO_LIBRARY="$PWD/tmp/build/librill_crypto.so" \
  .venv/bin/python -m pytest -q tests/python
./scripts/test-wasm.sh
bun install --frozen-lockfile --ignore-scripts
bun run typecheck
bun run test:wasm-verify
```

Python cannot reliably erase secrets from memory. Shared native and WASM
test vectors check parity; they are not a cryptographic audit.
