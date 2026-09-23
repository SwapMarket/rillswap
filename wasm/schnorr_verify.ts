/** Read-only BIP340 verification facade for an explicitly loaded rill-crypto WASM module.
 *
 * No signer, nonce, payment, or persistent-state capability is exposed here.
 * The caller owns the version-pinned `.mjs` and `.wasm` bytes and their loading.
 */

export interface SchnorrWasm {
  readonly HEAPU8: Uint8Array;
  _malloc(length: number): number;
  _free(pointer: number): void;
  _rill_crypto_abi_version(): number;
  _rill_crypto_context_create(random32: number): number;
  _rill_crypto_context_destroy(context: number): void;
  _rill_schnorr_verify(context: number, publicKey32: number, message32: number, signature64: number): number;
}

const ABI_VERSION = 1;
const INVALID_PUBLIC_KEY = 3;
const INVALID_SIGNATURE = 5;

/** A scoped, synchronous verifier. Destroy it when finished, not while in use. */
export function createSchnorrVerifier(wasm: SchnorrWasm): {
  verify(publicKey32: Uint8Array, message32: Uint8Array, signature64: Uint8Array): boolean;
  destroy(): void;
} {
  if (wasm._rill_crypto_abi_version() !== ABI_VERSION) {
    throw new Error("Unsupported rill-crypto WASM ABI version");
  }

  function allocate(length: number): number {
    const pointer = wasm._malloc(length);
    if (!Number.isSafeInteger(pointer) || pointer <= 0 || pointer + length > wasm.HEAPU8.length) {
      if (Number.isSafeInteger(pointer) && pointer > 0) wasm._free(pointer);
      throw new Error("rill-crypto WASM allocation failed");
    }
    return pointer;
  }

  function wipeAndFree(pointer: number, length: number): void {
    wasm.HEAPU8.fill(0, pointer, pointer + length);
    wasm._free(pointer);
  }

  const random = new Uint8Array(32);
  let context = 0;
  let randomPointer = 0;
  try {
    crypto.getRandomValues(random);
    randomPointer = allocate(32);
    wasm.HEAPU8.set(random, randomPointer);
    context = wasm._rill_crypto_context_create(randomPointer);
    if (!context) throw new Error("rill-crypto WASM context creation failed");
  } finally {
    random.fill(0);
    if (randomPointer) wipeAndFree(randomPointer, 32);
  }

  return {
    verify(publicKey32, message32, signature64) {
      if (!context) throw new Error("rill-crypto verifier was destroyed");
      if (!(publicKey32 instanceof Uint8Array) || publicKey32.length !== 32 ||
        !(message32 instanceof Uint8Array) || message32.length !== 32 ||
        !(signature64 instanceof Uint8Array) || signature64.length !== 64) {
        throw new TypeError("BIP340 verification requires 32-byte key, 32-byte message and 64-byte signature");
      }
      // Inputs may be views into the WASM heap. Snapshot all three before the
      // first _malloc, since a growing memory detaches its old ArrayBuffer.
      const snapshots = [
        new Uint8Array(publicKey32),
        new Uint8Array(message32),
        new Uint8Array(signature64),
      ];
      const pointers: Array<[number, number]> = [];
      try {
        for (const bytes of snapshots) {
          const pointer = allocate(bytes.length);
          pointers.push([pointer, bytes.length]);
          wasm.HEAPU8.set(bytes, pointer);
        }
        const [key, message, signature] = pointers;
        if (!key || !message || !signature) throw new Error("Incomplete WASM verification inputs");
        const status = wasm._rill_schnorr_verify(context, key[0], message[0], signature[0]);
        if (status === 0) return true;
        if (status === INVALID_PUBLIC_KEY || status === INVALID_SIGNATURE) return false;
        throw new Error(`rill-crypto WASM verification failed (status ${status})`);
      } finally {
        try {
          for (const [pointer, length] of pointers.reverse()) wipeAndFree(pointer, length);
        } finally {
          for (const bytes of snapshots) bytes.fill(0);
        }
      }
    },
    destroy() {
      if (!context) return;
      const owned = context;
      context = 0;
      wasm._rill_crypto_context_destroy(owned);
    },
  };
}
