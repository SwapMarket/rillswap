/**
 * Two-party BIP327 MuSig2 for the cooperative key-path claim, through the
 * pinned rill-crypto WASM build (the same libsecp256k1 code the CLI and
 * provider use natively).
 *
 * Key order is always (client, provider). A secret nonce exists only inside
 * one WASM attempt handle: it is never serialized, and signing consumes the
 * handle even when it fails, so a nonce can never sign twice.
 */

export interface RillCryptoWasm {
  readonly HEAPU8: Uint8Array;
  _malloc(length: number): number;
  _free(pointer: number): void;
  _rill_crypto_abi_version(): number;
  _rill_crypto_context_create(random32: number): number;
  _rill_crypto_context_destroy(context: number): void;
  _rill_musig_begin(
    context: number,
    secret32: number,
    user33: number,
    provider33: number,
    tweak32: number,
    message32: number,
    cooperationId32: number,
    random32: number,
    handleOut: number,
    nonceOut66: number,
  ): number;
  _rill_musig_public_nonce_validate(context: number, nonce66: number): number;
  _rill_musig_partial_sign_once(context: number, handle: number, peerNonce66: number, partialOut32: number): number;
  _rill_musig_partial_verify(
    context: number,
    user33: number,
    provider33: number,
    tweak32: number,
    message32: number,
    userNonce66: number,
    providerNonce66: number,
    signerIndex: number,
    partial32: number,
  ): number;
  _rill_musig_aggregate(
    context: number,
    user33: number,
    provider33: number,
    tweak32: number,
    message32: number,
    userNonce66: number,
    providerNonce66: number,
    userPartial32: number,
    providerPartial32: number,
    signatureOut64: number,
  ): number;
  _rill_musig_attempt_destroy(handle: number): void;
}

const ABI_VERSION = 1;
const CLIENT_SIGNER_INDEX = 0;
const PROVIDER_SIGNER_INDEX = 1;

/** The public transcript both signers commit to. */
export interface MusigTranscript {
  readonly clientKey: Uint8Array; // 33-byte compressed
  readonly providerKey: Uint8Array; // 33-byte compressed
  readonly tapTweak: Uint8Array; // 32
  readonly message: Uint8Array; // 32-byte BIP341 key-path sighash
}

/** One live client signing attempt; `signOnce` consumes it on every path. */
export interface MusigAttempt {
  readonly publicNonce: Uint8Array;
  signOnce(providerNonce: Uint8Array): Uint8Array;
  destroy(): void;
}

export interface Musig {
  begin(transcript: MusigTranscript, secret: Uint8Array, cooperationId: Uint8Array): MusigAttempt;
  validateNonce(nonce: Uint8Array): boolean;
  verifyPartial(
    transcript: MusigTranscript,
    clientNonce: Uint8Array,
    providerNonce: Uint8Array,
    signer: "client" | "provider",
    partial: Uint8Array,
  ): boolean;
  /** Verifies both partials and the final BIP340 signature before returning it. */
  aggregate(
    transcript: MusigTranscript,
    clientNonce: Uint8Array,
    providerNonce: Uint8Array,
    clientPartial: Uint8Array,
    providerPartial: Uint8Array,
  ): Uint8Array;
  destroy(): void;
}

export class MusigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "MusigError";
  }
}

function sized(bytes: Uint8Array, length: number, what: string): Uint8Array {
  if (!(bytes instanceof Uint8Array) || bytes.length !== length) throw new TypeError(`${what} must be ${length} bytes`);
  return new Uint8Array(bytes); // a snapshot: a growing heap detaches old views
}

/** Bind a loaded module. Destroy the returned object only after every attempt. */
export function createMusig(wasm: RillCryptoWasm): Musig {
  if (wasm._rill_crypto_abi_version() !== ABI_VERSION) throw new MusigError("unsupported rill-crypto WASM ABI version");
  // Every call stages inputs in fresh heap buffers and wipes them afterward.
  function scoped<T>(body: (put: (bytes: Uint8Array) => number, out: (length: number) => number) => T): T {
    const local: Array<[number, number]> = [];
    const allocate = (length: number): number => {
      const pointer = wasm._malloc(length);
      if (!Number.isSafeInteger(pointer) || pointer <= 0 || pointer + length > wasm.HEAPU8.length) {
        if (Number.isSafeInteger(pointer) && pointer > 0) wasm._free(pointer);
        throw new MusigError("rill-crypto WASM allocation failed");
      }
      local.push([pointer, length]);
      wasm.HEAPU8.fill(0, pointer, pointer + length);
      return pointer;
    };
    const put = (bytes: Uint8Array): number => {
      const pointer = allocate(bytes.length);
      wasm.HEAPU8.set(bytes, pointer);
      return pointer;
    };
    try {
      return body(put, allocate);
    } finally {
      for (const [pointer, length] of local.reverse()) {
        wasm.HEAPU8.fill(0, pointer, pointer + length);
        wasm._free(pointer);
      }
    }
  }

  const read = (pointer: number, length: number): Uint8Array => wasm.HEAPU8.slice(pointer, pointer + length);
  const fresh = (): Uint8Array => crypto.getRandomValues(new Uint8Array(32));

  let context = scoped((put) => {
    const random = fresh();
    try {
      return wasm._rill_crypto_context_create(put(random));
    } finally {
      random.fill(0);
    }
  });
  if (!context) throw new MusigError("rill-crypto WASM context creation failed");
  const live = (): number => {
    if (!context) throw new MusigError("rill-crypto MuSig2 was destroyed");
    return context;
  };

  function transcriptPointers(t: MusigTranscript, put: (bytes: Uint8Array) => number): [number, number, number, number] {
    return [
      put(sized(t.clientKey, 33, "client key")),
      put(sized(t.providerKey, 33, "provider key")),
      put(sized(t.tapTweak, 32, "tap tweak")),
      put(sized(t.message, 32, "message")),
    ];
  }

  return {
    begin(transcript, secret, cooperationId) {
      const ctx = live();
      const { handle, publicNonce } = scoped((put, out) => {
        const [user, provider, tweak, message] = transcriptPointers(transcript, put);
        const secretPointer = put(sized(secret, 32, "contract secret"));
        const random = fresh(); // fresh per attempt, as rill_musig_begin requires
        const randomPointer = put(random);
        random.fill(0);
        const handleOut = out(4);
        const nonceOut = out(66);
        const status = wasm._rill_musig_begin(
          ctx, secretPointer, user, provider, tweak, message,
          put(sized(cooperationId, 32, "cooperation id")), randomPointer, handleOut, nonceOut,
        );
        const view = new DataView(wasm.HEAPU8.buffer, handleOut, 4);
        const pointer = view.getUint32(0, true);
        if (status !== 0 || pointer === 0) throw new MusigError(`MuSig2 attempt refused (status ${status})`);
        return { handle: pointer, publicNonce: read(nonceOut, 66) };
      });
      let attempt = handle;
      const destroy = (): void => {
        if (!attempt) return;
        const ownedHandle = attempt;
        attempt = 0;
        wasm._rill_musig_attempt_destroy(ownedHandle);
      };
      return {
        publicNonce,
        signOnce(providerNonce) {
          if (!attempt) throw new MusigError("MuSig2 attempt already consumed");
          const ctxNow = live();
          const peer = sized(providerNonce, 66, "provider nonce");
          try {
            return scoped((put, out) => {
              const partialOut = out(32);
              const status = wasm._rill_musig_partial_sign_once(ctxNow, attempt, put(peer), partialOut);
              if (status !== 0) throw new MusigError(`MuSig2 partial signing refused (status ${status})`);
              return read(partialOut, 32);
            });
          } finally {
            destroy(); // consumed either way; wipe the secret nonce now
          }
        },
        destroy,
      };
    },
    validateNonce(nonce) {
      const ctx = live();
      return scoped((put) => wasm._rill_musig_public_nonce_validate(ctx, put(sized(nonce, 66, "nonce"))) === 0);
    },
    verifyPartial(transcript, clientNonce, providerNonce, signer, partial) {
      const ctx = live();
      return scoped((put) => {
        const [user, provider, tweak, message] = transcriptPointers(transcript, put);
        return (
          wasm._rill_musig_partial_verify(
            ctx, user, provider, tweak, message,
            put(sized(clientNonce, 66, "client nonce")), put(sized(providerNonce, 66, "provider nonce")),
            signer === "client" ? CLIENT_SIGNER_INDEX : PROVIDER_SIGNER_INDEX,
            put(sized(partial, 32, "partial signature")),
          ) === 0
        );
      });
    },
    aggregate(transcript, clientNonce, providerNonce, clientPartial, providerPartial) {
      const ctx = live();
      return scoped((put, out) => {
        const [user, provider, tweak, message] = transcriptPointers(transcript, put);
        const signatureOut = out(64);
        const status = wasm._rill_musig_aggregate(
          ctx, user, provider, tweak, message,
          put(sized(clientNonce, 66, "client nonce")), put(sized(providerNonce, 66, "provider nonce")),
          put(sized(clientPartial, 32, "client partial")), put(sized(providerPartial, 32, "provider partial")),
          signatureOut,
        );
        if (status !== 0) throw new MusigError(`MuSig2 aggregation refused (status ${status})`);
        return read(signatureOut, 64);
      });
    },
    destroy() {
      if (!context) return;
      const ownedContext = context;
      context = 0;
      wasm._rill_crypto_context_destroy(ownedContext);
    },
  };
}
