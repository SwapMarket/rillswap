/**
 * Emscripten factory for the vendored rill-crypto WASM build. The .mjs and
 * .wasm bytes are produced by rill-crypto/scripts/test-wasm.sh (digest-pinned
 * emsdk image); CI rebuilds them and requires byte equality (SHA256SUMS).
 */
import type { RillCryptoWasm } from "../../swap/musig";

export default function createRillCrypto(options?: { locateFile?: (path: string) => string }): Promise<RillCryptoWasm>;
