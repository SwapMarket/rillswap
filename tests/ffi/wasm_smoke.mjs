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

crypto._rill_crypto_context_destroy(context);
for (const { pointer, length } of allocations.reverse()) {
  crypto.HEAPU8.fill(0, pointer, pointer + length);
  crypto._free(pointer);
}
