# rill-crypto

Minimal native and WebAssembly boundary to official `libsecp256k1` operations
needed by RillSwap. The API uses opaque validated keys and one-shot MuSig2
attempt handles. Secret nonce serialization is intentionally impossible.

Status: feasibility work only, unaudited, and not suitable for real funds.

`wasm/schnorr_verify.ts` is a narrowly scoped, read-only BIP340 verification
facade. Its caller must supply and authenticate a version-pinned Emscripten
module and its corresponding `.wasm` bytes. The facade checks ABI v1, copies
caller inputs (including WASM heap views and Node Buffers), randomizes its
context, maps invalid public keys and signatures to `false`, and wipes owned
temporary buffers on return or failure. Call `destroy()` when finished. It
does not load artifacts, verify contracts, authenticate application envelopes,
sign, manage MuSig nonces, or persist any state. This is **not** a browser SDK
or a release artifact: browser/worker loading, packaging, integrity pinning,
cross-platform tests, independent review, and audit remain open.

To run the focused parity tests after building native and WASM artifacts:

```sh
./scripts/test-wasm.sh
bun install --frozen-lockfile
bun run typecheck
bun run test:wasm-verify
RILL_CRYPTO_LIBRARY="$PWD/tmp/build/librill_crypto.so" .venv/bin/pytest -q
```

Both native and WASM tests use the same pinned official BIP340 rows in
`tests/fixtures/bip340-verify-vectors.json`; shared fixtures check interface
parity but do not constitute an independent cryptographic audit.
