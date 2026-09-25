import { expect, spyOn, test } from "bun:test";
import createRillCrypto from "../../tmp/wasm/rill_crypto_wasm.mjs";
import { createSchnorrVerifier, type SchnorrWasm } from "../../wasm/schnorr_verify";
import vectors from "../fixtures/bip340-verify-vectors.json";

const bytes = (hex: string): Uint8Array => Uint8Array.fromHex(hex);

test("pinned BIP340 valid and invalid vectors agree with native verification", async () => {
  const wasm = await createRillCrypto() as SchnorrWasm;
  const verifier = createSchnorrVerifier(wasm);
  try {
    for (const vector of vectors.cases) {
      const key = bytes(vector.key);
      const message = bytes(vector.message);
      const signature = bytes(vector.signature);
      expect(verifier.verify(key, message, signature)).toBe(vector.expected);
      expect(key).toEqual(bytes(vector.key));
      expect(message).toEqual(bytes(vector.message));
      expect(signature).toEqual(bytes(vector.signature));
      expect(verifier.verify(key, message, signature)).toBe(vector.expected);
    }
    expect(() => verifier.verify(bytes("00"), bytes(vectors.cases[0]!.message), bytes(vectors.cases[0]!.signature)))
      .toThrow(TypeError);
  } finally {
    verifier.destroy();
    verifier.destroy();
  }
  expect(() => verifier.verify(bytes(vectors.cases[0]!.key), bytes(vectors.cases[0]!.message), bytes(vectors.cases[0]!.signature)))
    .toThrow(/destroyed/);
});

test("ABI mismatch is refused before context creation", async () => {
  const wasm = await createRillCrypto() as SchnorrWasm;
  const incompatible = Object.create(wasm) as SchnorrWasm;
  incompatible._rill_crypto_abi_version = () => 2;
  expect(() => createSchnorrVerifier(incompatible)).toThrow(/ABI version/);
});

test("unexpected native status wipes and releases every verification buffer", async () => {
  const wasm = await createRillCrypto() as SchnorrWasm;
  const instrumented = Object.create(wasm) as SchnorrWasm;
  const allocated: Array<[number, number]> = [];
  const freed: number[] = [];
  const wiped: boolean[] = [];
  instrumented._malloc = (length) => {
    const pointer = wasm._malloc(length);
    allocated.push([pointer, length]);
    return pointer;
  };
  instrumented._free = (pointer) => {
    const size = allocated.filter(([address]) => address === pointer).at(-1)?.[1];
    wiped.push(size !== undefined && wasm.HEAPU8.slice(pointer, pointer + size)
      .every((value) => value === 0));
    freed.push(pointer);
    wasm._free(pointer);
  };
  instrumented._rill_schnorr_verify = () => 9;
  const verifier = createSchnorrVerifier(instrumented);
  try {
    const vector = vectors.cases[0]!;
    expect(() => verifier.verify(bytes(vector.key), bytes(vector.message), bytes(vector.signature)))
      .toThrow(/status 9/);
    expect(freed.sort()).toEqual(allocated.map(([pointer]) => pointer).sort());
    expect(wiped.every(Boolean)).toBe(true);
  } finally {
    verifier.destroy();
  }
});

test("partial allocation failure still wipes and frees earlier buffers", async () => {
  const wasm = await createRillCrypto() as SchnorrWasm;
  const instrumented = Object.create(wasm) as SchnorrWasm;
  const allocated: Array<[number, number]> = [];
  const freed: number[] = [];
  const wiped: boolean[] = [];
  instrumented._malloc = (length) => {
    if (allocated.length === 2) return 0; // random and key succeeded; message fails.
    const pointer = wasm._malloc(length);
    allocated.push([pointer, length]);
    return pointer;
  };
  instrumented._free = (pointer) => {
    const size = allocated.filter(([address]) => address === pointer).at(-1)?.[1];
    wiped.push(size !== undefined && wasm.HEAPU8.slice(pointer, pointer + size)
      .every((value) => value === 0));
    freed.push(pointer);
    wasm._free(pointer);
  };
  const verifier = createSchnorrVerifier(instrumented);
  try {
    const vector = vectors.cases[0]!;
    expect(() => verifier.verify(bytes(vector.key), bytes(vector.message), bytes(vector.signature)))
      .toThrow(/allocation failed/);
    expect(freed.sort()).toEqual(allocated.map(([pointer]) => pointer).sort());
    expect(wiped.every(Boolean)).toBe(true);
  } finally {
    verifier.destroy();
  }
});

test("heap-backed inputs survive WebAssembly memory growth while allocating", () => {
  const memory = new WebAssembly.Memory({ initial: 1 });
  const view = () => new Uint8Array(memory.buffer);
  const vector = vectors.cases[0]!;
  const key = bytes(vector.key), message = bytes(vector.message), signature = bytes(vector.signature);
  view().set(key, 16);
  view().set(message, 64);
  view().set(signature, 128);
  let cursor = 1024;
  let allocations = 0;
  let checked = false;
  const wasm: SchnorrWasm = {
    get HEAPU8() { return view(); },
    _malloc(length) {
      if (++allocations === 2) memory.grow(1); // First verification allocation.
      const pointer = cursor;
      cursor += length;
      return pointer;
    },
    _free() {},
    _rill_crypto_abi_version: () => 1,
    _rill_crypto_context_create: () => 1,
    _rill_crypto_context_destroy: () => {},
    _rill_schnorr_verify(_context, publicKey, digest, sig) {
      checked = view().slice(publicKey, publicKey + 32).toHex() === key.toHex() &&
        view().slice(digest, digest + 32).toHex() === message.toHex() &&
        view().slice(sig, sig + 64).toHex() === signature.toHex();
      return checked ? 0 : 5;
    },
  };
  const verifier = createSchnorrVerifier(wasm);
  try {
    expect(verifier.verify(new Uint8Array(memory.buffer, 16, 32),
      new Uint8Array(memory.buffer, 64, 32), new Uint8Array(memory.buffer, 128, 64)))
      .toBe(true);
    expect(checked).toBe(true);
  } finally {
    verifier.destroy();
  }
});

test("Buffer inputs stay owned by the caller after snapshot cleanup", async () => {
  const wasm = await createRillCrypto() as SchnorrWasm;
  const verifier = createSchnorrVerifier(wasm);
  const vector = vectors.cases[0]!;
  const key = Buffer.from(vector.key, "hex");
  const message = Buffer.from(vector.message, "hex");
  const signature = Buffer.from(vector.signature, "hex");
  try {
    expect(verifier.verify(key, message, signature)).toBe(true);
    expect(key.toString("hex").toUpperCase()).toBe(vector.key);
    expect(message.toString("hex").toUpperCase()).toBe(vector.message);
    expect(signature.toString("hex").toUpperCase()).toBe(vector.signature);
    expect(verifier.verify(key, message, signature)).toBe(true);
  } finally {
    verifier.destroy();
  }
});

test("initial allocation failure wipes the context randomization seed", async () => {
  const base = await createRillCrypto() as SchnorrWasm;
  const wasm = Object.create(base) as SchnorrWasm;
  let created = false;
  let captured: Uint8Array | undefined;
  wasm._malloc = () => 0;
  wasm._rill_crypto_context_create = () => { created = true; return 1; };
  const actual = crypto.getRandomValues.bind(crypto);
  const randomSpy = spyOn(crypto, "getRandomValues").mockImplementation((array: Uint8Array) => {
    captured = array as Uint8Array;
    return actual(array);
  });
  try {
    expect(() => createSchnorrVerifier(wasm)).toThrow(/allocation failed/);
    expect(created).toBe(false);
    expect(captured).toBeDefined();
    expect(captured!.every((value) => value === 0)).toBe(true);
  } finally {
    randomSpy.mockRestore();
  }
});
