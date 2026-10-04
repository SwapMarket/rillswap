# rill-crypto

Minimal native and WebAssembly boundary to official `libsecp256k1` operations
needed by RillSwap. The API uses opaque validated keys and one-shot MuSig2
attempt handles. Secret nonce serialization is intentionally impossible.

Status: feasibility work only, unaudited, and not suitable for real funds.

Python MuSig attempt construction establishes one idempotent native owner
before allocation. Construction failures, failed input wipes, counter charging,
nonce conversion, explicit close, and garbage collection share that owner, so
retained exception tracebacks cannot keep an allocated nonce usable or cause
double destruction. Pointer state is authoritative and invalidated on release;
forked finalizers never mutate parent-owned state. Both input wipes are attempted
even when one raises. This does not guarantee erasure if a wipe fails before
writing, reliable erasure of immutable Python secrets, or protection against
arbitrary interruption of cleanup itself. The native ABI and successful Python
API are unchanged; no persisted state or automatic upgrade work is introduced.

`rill_nip44_shared_x`/`Context.nip44_shared_x` is a narrow, **optional ABI-v1**
constant-time ECDH primitive for a future NIP-44 v2 receive boundary. It
validates a private scalar and an even-Y-lifted x-only peer point, then returns
the **unhashed** 32-byte shared x coordinate. It does **not** implement NIP-44
HKDF, authenticated encryption, signed NIP-01 events, NIP-59 decryption,
mailbox key custody, replay protection, or any swap transport. It must not be
used as a stand-alone encryption scheme. Native outputs are cleared on errors;
Python `bytes` and caller-provided secrets cannot be reliably erased from
process memory. The three C buffers must not overlap. The same ABI and SONAME
remain usable by previous callers; an existing native library missing only
this new symbol continues to support all previous operations, and requesting
the optional primitive gives a specific unsupported-library error without
rebuilding or migrating anything. The Python tests compare HKDF-extract of
the shared x to pinned official NIP-44 conversation-key vectors, from
`nip44.vectors.json` SHA-256
`269ed0f69e4c192512cc779e78c555090cebc7c785b609e338a62afc3ce25040`.
They do not yet test a NIP-44 ciphertext or constitute an external audit.

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
