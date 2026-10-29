import { expect, test } from "bun:test";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { hexToBytes } from "@noble/hashes/utils.js";
import { bech32 } from "@scure/base";
import { decodeBolt11, invoiceBinding, invoiceMetadataBinding } from "../src/bolt11";
import { receiver, testInvoice } from "./helpers";

const encoder = new TextEncoder();
const tag = (type: number, words: number[]) => [type, Math.floor(words.length / 32), words.length % 32, ...words];
const metadataTag = (metadata: string) => tag(23, bech32.toWords(sha256(encoder.encode(metadata))));

// Genuine signed payloads, with explicit payee pin so signature corruption
// cannot merely recover a different signer. The key is a public test fixture.
function invoice(tags: number[][], corruptSignature = false, prepend = false): string {
  const base = bech32.decode(testInvoice("metadata") as `${string}1${string}`, 2048);
  const original = base.words.slice(7, -104), retained: number[] = [];
  for (let i = 0; i < original.length;) {
    const type = original[i]!, length = original[i + 1]! * 32 + original[i + 2]!;
    if (type !== 13) retained.push(...original.slice(i, i + 3 + length));
    i += 3 + length;
  }
  const data = [...base.words.slice(0, 7), ...(prepend ? tags.flat() : []), ...retained, ...tag(19, bech32.toWords(hexToBytes(receiver))), ...(prepend ? [] : tags.flat())];
  const bitLength = data.length * 5, byteLength = Math.ceil(bitLength / 8);
  const packed = data.reduce((bits, word) => (bits << 5n) | BigInt(word), 0n) << BigInt(byteLength * 8 - bitLength);
  const digest = sha256(new Uint8Array([...encoder.encode(base.prefix), ...hexToBytes(packed.toString(16).padStart(byteLength * 2, "0"))]));
  const secret = new Uint8Array(32); secret[31] = 1;
  const signed = secp256k1.sign(digest, secret, { prehash: false, format: "recovered" });
  const signature = new Uint8Array([...signed.slice(1), signed[0]!]);
  if (corruptSignature) signature.fill(0);
  return bech32.encode(base.prefix, [...data, ...bech32.toWords(signature)], 2048);
}

test("strict metadata mode authenticates exact UTF-8 and preserves all seven binding fields", () => {
  const metadata = '[["text/plain","Receipt \u00e9"]]', signed = invoice([metadataTag(metadata)]);
  expect(invoiceMetadataBinding(signed, "regtest", metadata)).toEqual(invoiceBinding(signed, "regtest"));
  expect(Object.keys(invoiceMetadataBinding(signed, "regtest", metadata))).toEqual([
    "bolt11_sha256", "payment_hash", "amount_msat", "payee_compressed_pubkey", "created_at", "expires_at", "min_final_cltv_delta",
  ]);
  expect(Object.keys(decodeBolt11(signed))).not.toContain("metadataHash");
  for (const changed of [metadata + " ", metadata.replace("\u00e9", "e\u0301"), JSON.stringify(JSON.parse(metadata), null, 2)]) {
    expect(() => invoiceMetadataBinding(signed, "regtest", changed)).toThrow("hash differs");
  }
});

test("wrong network and explicit-payee invalid signature still follow existing admission", () => {
  const metadata = "exact";
  expect(() => invoiceMetadataBinding(invoice([metadataTag(metadata)]), "mainnet", metadata)).toThrow("selected network");
  expect(() => invoiceMetadataBinding(invoice([metadataTag(metadata)], true), "regtest", metadata)).toThrow("signature invalid");
  const unknownFeature = invoice([metadataTag(metadata), tag(5, [1, 0, 16, 8, 0])]);
  expect(() => invoiceMetadataBinding(unknownFeature, "regtest", metadata)).toThrow("feature");
  expect(() => invoiceBinding(unknownFeature, "regtest")).toThrow("feature");
});

test("ambiguous, missing and noncanonical description tags refuse only metadata mode", () => {
  const metadata = "exact", valid = metadataTag(metadata), padding = bech32.toWords(sha256(encoder.encode(metadata)));
  padding[51] = padding[51]! | 1;
  const unsupported = [[], [tag(13, [])], [valid, tag(13, [])], [valid, valid], [tag(23, padding)]];
  for (const tags of unsupported) {
    const signed = invoice(tags), ordinary = invoiceBinding(signed, "regtest");
    expect(ordinary.payee_compressed_pubkey).toBe(receiver);
    expect(() => invoiceMetadataBinding(signed, "regtest", metadata)).toThrow("description tags");
    expect(invoiceBinding(signed, "regtest")).toEqual(ordinary);
  }
});

test("every signed wrong-length p/h/s/n occurrence is refused before or after valid fields", () => {
  const metadata = "exact", valid = metadataTag(metadata);
  for (const type of [1, 23, 16, 19]) {
    const length = type === 19 ? 53 : 52;
    for (const words of [new Array<number>(length - 1).fill(0), new Array<number>(length + 1).fill(0), []]) {
      for (const prepend of [true, false]) {
        const signed = invoice([tag(type, words), valid], false, prepend);
        expect(() => decodeBolt11(signed)).toThrow("Invoice refused");
        expect(() => invoiceBinding(signed, "regtest")).toThrow("Invoice refused");
        expect(() => invoiceMetadataBinding(signed, "regtest", metadata)).toThrow("Invoice refused");
      }
    }
  }
});

test("unknown invoice tags remain benign under the explicit metadata profile", () => {
  const metadata = "exact", signed = invoice([tag(31, [1, 2]), metadataTag(metadata)]);
  expect(invoiceMetadataBinding(signed, "regtest", metadata)).toEqual(invoiceBinding(signed, "regtest"));
});

test("metadata byte bounds, lone surrogates, BOM and exact empty hash are explicit", () => {
  for (const metadata of ["", "a".repeat(16384), "\u00e9".repeat(8192), "\ufeffexact", "\ud834\udd1e".repeat(4096)]) {
    const signed = invoice([metadataTag(metadata)]);
    expect(invoiceMetadataBinding(signed, "regtest", metadata)).toEqual(invoiceBinding(signed, "regtest"));
  }
  for (const metadata of ["a".repeat(16385), "\u00e9".repeat(8193), "\ud800", "\udc00", "a\ud800b", null as unknown as string]) {
    expect(() => invoiceMetadataBinding(invoice([metadataTag("exact")]), "regtest", metadata)).toThrow("metadata");
  }
});

test("ordinary modern unhashed invoice acceptance remains unchanged", () => {
  const signed = testInvoice("modern-lnurl");
  expect(invoiceBinding(signed, "regtest").payee_compressed_pubkey).toBe(receiver);
  expect(() => invoiceMetadataBinding(signed, "regtest", "metadata")).toThrow("description tags");
});

// lightning/bolts#1357 (stacker.news/items/1576513): one signed invoice must
// not let different components pick different payment hashes.
test("multiple or malformed payment hashes are refused by every reader", () => {
  const other = tag(1, bech32.toWords(new Uint8Array(32).fill(7)));
  for (const tags of [[other], [tag(1, [1])], [tag(1, bech32.toWords(new Uint8Array(33)))]]) {
    const signed = invoice(tags);
    expect(() => decodeBolt11(signed)).toThrow("Invoice refused");
    expect(() => invoiceBinding(signed, "regtest")).toThrow("Invoice refused");
    expect(() => invoiceMetadataBinding(signed, "regtest", "exact")).toThrow("Invoice refused");
  }
  expect(() => decodeBolt11(invoice([other]))).toThrow("multiple payment hashes");
  // Wrong-length payment secret or payee is also refused instead of skipped.
  expect(() => decodeBolt11(invoice([tag(16, [1])]))).toThrow("fixed-length");
  expect(() => decodeBolt11(invoice([tag(19, [1])]))).toThrow("fixed-length");
  // Repeated binding fields (secret, expiry, payee, CLTV) are
  // resolved differently by readers (LND keeps the first), so they are refused.
  // The fixture already carries s, x and n once; c is added twice.
  for (const repeated of [[tag(16, bech32.toWords(new Uint8Array(32).fill(9)))], [tag(6, [1, 0])],
    [tag(19, bech32.toWords(hexToBytes(receiver)))], [tag(24, [9]), tag(24, [9])]]) {
    expect(() => decodeBolt11(invoice(repeated))).toThrow("duplicate binding field");
  }
  expect(decodeBolt11(invoice([tag(24, [9])])).minFinalCltvDelta).toBe(9);
  expect(invoiceBinding(invoice([]), "regtest").payee_compressed_pubkey).toBe(receiver);
});

// A batch of invoices in one string must never pass as one of them (or all).
test("batched, wrapped or padded invoice strings are one refusal", () => {
  const first = invoice([]), second = testInvoice("modern-lnurl");
  expect(invoiceBinding(first, "regtest").payee_compressed_pubkey).toBe(receiver);
  for (const batched of [first + second, `${first} ${second}`, `${first},${second}`, `${first}\n${second}`,
    `lightning:${first}`, `${first} `, ` ${first}`, `${first}q`]) {
    expect(() => decodeBolt11(batched)).toThrow("Invoice refused");
    expect(() => invoiceBinding(batched, "regtest")).toThrow("Invoice refused");
  }
});
