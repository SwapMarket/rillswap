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

crypto._rill_crypto_context_destroy(context);
for (const { pointer, length } of allocations.reverse()) {
  crypto.HEAPU8.fill(0, pointer, pointer + length);
  crypto._free(pointer);
}
