/**
 * Load the vendored rill-crypto WASM in the browser. The bytes are pinned:
 * CI rebuilds them with the digest-pinned emsdk image and compares hashes.
 */
import createRillCrypto from "../vendor/rill-crypto/rill_crypto_wasm.mjs";
import wasmUrl from "../vendor/rill-crypto/rill_crypto_wasm.wasm?url";
import { createMusig, type Musig } from "./musig";

export async function loadMusig(): Promise<Musig> {
  return createMusig(await createRillCrypto({ locateFile: () => wasmUrl }));
}
