import createRillCrypto from "../../tmp/wasm/rill_crypto_wasm.mjs";

const crypto = await createRillCrypto();
if (crypto._rill_crypto_abi_version() !== 1) {
  throw new Error("unexpected rill-crypto WASM ABI version");
}

const allocations = [];
function allocate(length, fill = 0) {
  const pointer = crypto._malloc(length);
  if (pointer === 0) {
    throw new Error("WASM allocation failed");
  }
  allocations.push({ pointer, length });
  crypto.HEAPU8.fill(fill, pointer, pointer + length);
  return pointer;
}

const contextRandom = allocate(32, 0xa1);
const secretKey = allocate(32);
crypto.HEAPU8[secretKey + 31] = 1;
const publicKey = allocate(33);
const providerSecretKey = allocate(32);
crypto.HEAPU8[providerSecretKey + 31] = 2;
const providerPublicKey = allocate(33);
const internalKey = allocate(32);
const internalParity = allocate(4, 0xff);
const context = crypto._rill_crypto_context_create(contextRandom);
if (context === 0) {
  throw new Error("WASM context creation failed");
}
if (crypto._rill_public_key_create(context, secretKey, publicKey) !== 0) {
  throw new Error("WASM public key creation failed");
}
if (![2, 3].includes(crypto.HEAPU8[publicKey])) {
  throw new Error("WASM returned an invalid compressed key");
}
if (crypto._rill_public_key_create(context, providerSecretKey, providerPublicKey) !== 0) {
  throw new Error("WASM provider public key creation failed");
}
if (typeof crypto._rill_musig_internal_key !== "function") {
  throw new Error("WASM internal-key export is missing");
}
if (
  crypto._rill_musig_internal_key(
    context,
    publicKey,
    providerPublicKey,
    internalKey,
    internalParity,
  ) !== 0
) {
  throw new Error("WASM internal-key aggregation failed");
}
const expectedInternalKey =
  "3b46d262d2f610e9038b44beabdfe97ab5a0feb89870acc2264edfb7f63ec2ec";
const actualInternalKey = Array.from(crypto.HEAPU8.slice(internalKey, internalKey + 32))
  .map((value) => value.toString(16).padStart(2, "0"))
  .join("");
if (actualInternalKey !== expectedInternalKey) {
  throw new Error("WASM returned the wrong ordered aggregate key");
}
if (crypto.HEAPU8.slice(internalParity, internalParity + 4).some((value) => value !== 0)) {
  throw new Error("WASM returned the wrong internal-key parity");
}

// A complete BIP327 tweaked, two-party key-path signature, not merely KeyAgg.
// This tests raw ABI availability and one-shot behavior, NOT an application
// signing policy or a browser signer. Production burns an attempt durably
// before allocating the native nonce handle and authorizes the exact sighash.
const tweak = allocate(32);
crypto.HEAPU8[tweak + 31] = 3;
const message = allocate(32, 0x44);
const cooperationId = allocate(32, 0x55);
const userRandom = allocate(32, 0x66);
const providerRandom = allocate(32, 0x77);
const userHandle = allocate(4);
const providerHandle = allocate(4);
const userNonce = allocate(66);
const providerNonce = allocate(66);
const userPartial = allocate(32);
const providerPartial = allocate(32);
const signature = allocate(64);
const outputKey = allocate(32);
const outputParity = allocate(4);
const readHandle = (pointer) => new DataView(crypto.HEAPU8.buffer).getUint32(pointer, true);
const check = (result, operation) => {
  if (result !== 0) throw new Error(`${operation} failed with status ${result}`);
};
check(crypto._rill_musig_output_key(context, publicKey, providerPublicKey, tweak,
  outputKey, outputParity), "output key");
check(crypto._rill_musig_begin(context, secretKey, publicKey, providerPublicKey,
  tweak, message, cooperationId, userRandom, userHandle, userNonce), "user begin");
check(crypto._rill_musig_begin(context, providerSecretKey, publicKey, providerPublicKey,
  tweak, message, cooperationId, providerRandom, providerHandle, providerNonce), "provider begin");
try {
  check(crypto._rill_musig_public_nonce_validate(context, userNonce), "user public nonce");
  check(crypto._rill_musig_public_nonce_validate(context, providerNonce), "provider public nonce");
  check(crypto._rill_musig_partial_sign_once(context, readHandle(userHandle), providerNonce,
    userPartial), "user partial");
  if (crypto._rill_musig_partial_sign_once(context, readHandle(userHandle), providerNonce,
    userPartial) !== 7) {
    throw new Error("consumed user attempt signed a second time");
  }
  check(crypto._rill_musig_partial_sign_once(context, readHandle(providerHandle), userNonce,
    providerPartial), "provider partial");
  for (const [signer, partial] of [[0, userPartial], [1, providerPartial]]) {
    check(crypto._rill_musig_partial_verify(context, publicKey, providerPublicKey, tweak,
      message, userNonce, providerNonce, signer, partial), `partial verify ${signer}`);
  }
  check(crypto._rill_musig_aggregate(context, publicKey, providerPublicKey, tweak, message,
    userNonce, providerNonce, userPartial, providerPartial, signature), "aggregate");
  check(crypto._rill_schnorr_verify(context, outputKey, message, signature), "final BIP340 signature");
  const corruptedPartial = crypto.HEAPU8[providerPartial];
  crypto.HEAPU8[providerPartial] ^= 1;
  if (crypto._rill_musig_aggregate(context, publicKey, providerPublicKey, tweak, message,
    userNonce, providerNonce, userPartial, providerPartial, signature) === 0) {
    throw new Error("tampered peer partial was accepted");
  }
  crypto.HEAPU8[providerPartial] = corruptedPartial;
} finally {
  crypto._rill_musig_attempt_destroy(readHandle(userHandle));
  crypto._rill_musig_attempt_destroy(readHandle(providerHandle));
}

// Even a failed partial-sign invocation burns its one-shot handle. No peer
// nonce or secret nonce ever enters the recovery file or persistent JS state.
const failedHandle = allocate(4);
const failedNonce = allocate(66);
const invalidNonce = allocate(66);
crypto.HEAPU8[cooperationId] = 0x56;
crypto.HEAPU8[userRandom] = 0x88;
check(crypto._rill_musig_begin(context, secretKey, publicKey, providerPublicKey,
  tweak, message, cooperationId, userRandom, failedHandle, failedNonce), "failed attempt begin");
try {
  if (crypto._rill_musig_partial_sign_once(context, readHandle(failedHandle), invalidNonce,
    userPartial) !== 6) {
    throw new Error("invalid peer nonce did not consume the attempt");
  }
  if (crypto._rill_musig_partial_sign_once(context, readHandle(failedHandle), providerNonce,
    userPartial) !== 7) {
    throw new Error("failed attempt could sign after invalid peer nonce");
  }
} finally {
  crypto._rill_musig_attempt_destroy(readHandle(failedHandle));
}

crypto._rill_crypto_context_destroy(context);
for (const { pointer, length } of allocations.reverse()) {
  crypto.HEAPU8.fill(0, pointer, pointer + length);
  crypto._free(pointer);
}
