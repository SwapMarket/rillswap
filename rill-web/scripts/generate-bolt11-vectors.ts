/**
 * Shared BOLT11 decoder vectors: the browser decoder (rill-payments/src/bolt11.ts)
 * produces the expectations, and rill-core's Python decoder must agree exactly.
 * Synthetic invoices are signed deterministically (RFC 6979) with public
 * test-only keys. `--check` fails when the committed file is stale.
 */
import { readFileSync, writeFileSync } from "node:fs";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { bech32 } from "@scure/base";

import { decodeBolt11, invoiceBinding, InvoiceRejectedError } from "../src/swap/bolt11";
import spec from "../unit/fixtures/bolt11-spec-examples.json";

const NETWORKS = ["mainnet", "testnet4", "signet", "regtest"] as const;
const ORDER = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const KEY = hexToBytes("00".repeat(31) + "01"), OTHER = hexToBytes("00".repeat(31) + "02");
const PAYEE = secp256k1.getPublicKey(KEY, true), OTHER_PAYEE = secp256k1.getPublicKey(OTHER, true);
const utf8 = (text: string): Uint8Array => new TextEncoder().encode(text);
const HASH = sha256(utf8("rillswap bolt11 vector")), SECRET = sha256(HASH);

const integer = (value: number): number[] => {
  const out: number[] = [];
  do { out.unshift(value % 32); value = Math.floor(value / 32); } while (value);
  return out;
};
const tag = (type: number, words: readonly number[]): number[] => [type, Math.floor(words.length / 32), words.length % 32, ...words];
const bytesTag = (type: number, bytes: Uint8Array): number[] => tag(type, bech32.toWords(bytes));
const features = (...bits: number[]): number[] => {
  const words = new Array<number>(Math.floor(Math.max(...bits) / 5) + 1).fill(0);
  for (const bit of bits) words[words.length - 1 - Math.floor(bit / 5)]! |= 1 << (bit % 5);
  return tag(5, words);
};
const p = bytesTag(1, HASH), s = bytesTag(16, SECRET), d = bytesTag(13, utf8("RillSwap vector"));
const x = tag(6, integer(7200)), c = tag(24, integer(80)), lnd = features(8, 14, 17);
const standard = [p, s, d, x, c, lnd];

function pack(words: readonly number[]): Uint8Array {
  const out: number[] = [];
  let accumulator = 0, bits = 0;
  for (const word of words) {
    accumulator = (accumulator << 5) | word; bits += 5;
    while (bits >= 8) { bits -= 8; out.push((accumulator >> bits) & 255); }
    accumulator &= (1 << bits) - 1;
  }
  if (bits) out.push((accumulator << (8 - bits)) & 255);
  return Uint8Array.from(out);
}

interface Build {
  readonly hrp?: string;
  readonly timestamp?: number;
  readonly tags?: readonly (readonly number[])[];
  readonly highS?: boolean;
  readonly recovery?: (actual: number) => number;
  readonly zeroSignature?: boolean;
  readonly trailing?: readonly number[];
}
function build(options: Build): string {
  const hrp = options.hrp ?? "lnbcrt500u";
  const timestamp = integer(options.timestamp ?? 1_700_000_000);
  while (timestamp.length < 7) timestamp.unshift(0);
  const data = [...timestamp, ...(options.tags ?? standard).flat(), ...(options.trailing ?? [])];
  const digest = sha256(new Uint8Array([...utf8(hrp), ...pack(data)]));
  const signed = secp256k1.sign(digest, KEY, { prehash: false, format: "recovered" });
  let compact = signed.slice(1), recovery = signed[0]!;
  if (options.highS) {
    // n - s, with the other recovery parity: the same signer, in high-S form.
    const high = ORDER - BigInt("0x" + bytesToHex(compact.slice(32)));
    compact = new Uint8Array([...compact.slice(0, 32), ...hexToBytes(high.toString(16).padStart(64, "0"))]);
    recovery ^= 1;
  }
  if (options.recovery) recovery = options.recovery(recovery);
  if (options.zeroSignature) compact.fill(0);
  return bech32.encode(hrp, [...data, ...bech32.toWords(new Uint8Array([...compact, recovery]))], false);
}

/** The invoice whose length is exactly `target` characters, padded with ignored unknown fields. */
function sized(target: number): string {
  const filler: number[][] = [];
  let remaining = target - build({}).length;
  while (remaining > 0) {
    // A field carries at most 1023 words after its 3-word header.
    const words = remaining > 1026 ? (remaining - 1026 < 3 ? 1000 : 1023) : remaining - 3;
    filler.push(tag(2, new Array<number>(words).fill(0)));
    remaining -= words + 3;
  }
  return build({ tags: [...standard, ...filler] });
}

const synthetic: readonly (readonly [string, string])[] = [
  ["regtest hold invoice", build({})],
  ["signet hold invoice", build({ hrp: "lntbs500u" })],
  ["testnet hold invoice", build({ hrp: "lntb500u" })],
  ["mainnet hold invoice", build({ hrp: "lnbc500u" })],
  ["amount in pico-bitcoin", build({ hrp: "lnbcrt500000000p" })],
  ["amount of 100 millisatoshi", build({ hrp: "lnbcrt1n" })],
  ["amount of one whole bitcoin", build({ hrp: "lnbcrt1" })],
  ["amount with a leading zero", build({ hrp: "lnbcrt0500u" })],
  ["amount with an unknown multiplier", build({ hrp: "lnbcrt500x" })],
  ["amount missing", build({ hrp: "lnbcrt" })],
  ["unknown currency", build({ hrp: "lnxy500u" })],
  ["prefix without ln", build({ hrp: "bcrt500u", timestamp: 1_700_000_001 })],
  ["explicit payee with a low-S signature", build({ tags: [...standard, bytesTag(19, PAYEE)] })],
  ["explicit payee with a high-S signature", build({ tags: [...standard, bytesTag(19, PAYEE)], highS: true })],
  ["recovered payee with a high-S signature", build({ highS: true })],
  ["explicit payee of another key", build({ tags: [...standard, bytesTag(19, OTHER_PAYEE)] })],
  ["explicit payee of 52 words", build({ tags: [...standard, tag(19, bech32.toWords(PAYEE).slice(0, 52))] })],
  ["duplicate explicit payee", build({ tags: [...standard, bytesTag(19, PAYEE), bytesTag(19, PAYEE)] })],
  ["other recovery parity", build({ recovery: (actual) => actual ^ 1 })],
  ["recovery id 4", build({ recovery: () => 4 })],
  ["zeroed signature", build({ zeroSignature: true })],
  ["optional feature pairs with AMP", build({ tags: [p, s, d, x, c, features(9, 15, 25)] })],
  ["features 8 and 9 together", build({ tags: [p, s, d, x, c, features(8, 9, 14)] })],
  ["feature 14 missing", build({ tags: [p, s, d, x, c, features(8)] })],
  ["unknown odd feature 51", build({ tags: [p, s, d, x, c, features(8, 14, 51)] })],
  ["no feature field", build({ tags: [p, s, d, x, c] })],
  ["repeated feature field, last wins", build({ tags: [p, s, d, x, c, features(8, 14, 100), lnd] })],
  ["duplicate payment secret", build({ tags: [...standard, s] })],
  ["duplicate expiry", build({ tags: [...standard, x] })],
  ["duplicate final CLTV", build({ tags: [...standard, c] })],
  ["two payment hashes", build({ tags: [...standard, bytesTag(1, SECRET)] })],
  ["payment hash missing", build({ tags: [s, d, x, c, lnd] })],
  ["payment secret missing", build({ tags: [p, d, x, c, lnd] })],
  ["payment hash of 51 words", build({ tags: [tag(1, bech32.toWords(HASH).slice(0, 51)), s, d, x, c, lnd] })],
  ["payment secret of 53 words", build({ tags: [p, tag(16, [...bech32.toWords(SECRET), 0]), d, x, c, lnd] })],
  ["description hash of 51 words", build({ tags: [p, s, tag(23, bech32.toWords(HASH).slice(0, 51)), x, c, lnd] })],
  ["description hash instead of description", build({ tags: [p, s, bytesTag(23, HASH), x, c, lnd] })],
  ["blinded path field", build({ tags: [...standard, tag(20, [1, 2, 3])] })],
  ["default expiry and final CLTV", build({ tags: [p, s, d, lnd] })],
  ["zero expiry", build({ tags: [p, s, d, tag(6, [0]), c, lnd] })],
  ["zero final CLTV", build({ tags: [p, s, d, x, tag(24, [0]), lnd] })],
  ["empty expiry field", build({ tags: [p, s, d, tag(6, []), c, lnd] })],
  ["expiry of ten words", build({ tags: [p, s, d, tag(6, [1, 0, 0, 0, 0, 0, 0, 0, 0, 0]), c, lnd] })],
  ["final CLTV of eleven words", build({ tags: [p, s, d, x, tag(24, [0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 16]), lnd] })],
  ["unknown tags are ignored", build({ tags: [...standard, tag(2, [1, 2, 3]), tag(31, [])] })],
  ["fallback address and route hint are ignored", build({ tags: [...standard, tag(9, [0, ...bech32.toWords(new Uint8Array(20))]), tag(3, bech32.toWords(new Uint8Array(51)))] })],
  ["truncated tagged field header", build({ trailing: [7, 0] })],
  ["truncated tagged field value", build({ trailing: [7, 1, 0, 1, 2] })],
  ["latest 35-bit timestamp", build({ timestamp: 2 ** 35 - 1 })],
  ["exactly 2048 characters", sized(2048)],
  ["2049 characters", sized(2049)],
  ["upper case", build({}).toUpperCase()],
  ["mixed case", "LNBCRT" + build({}).slice(6)],
  ["non-ASCII character", build({}).slice(0, -1) + "\u00e9"],
  ["too short", bech32.encode("lnbcrt500u", new Array<number>(110).fill(0), false)],
  ["empty string", ""],
];

type Outcome<T> = T | { readonly error: string };
function outcome<T>(run: () => T): Outcome<T> {
  try { return run(); } catch (error) {
    if (!(error instanceof InvoiceRejectedError)) throw error;
    return { error: error.message };
  }
}

function vector(name: string, invoice: string) {
  const decoded = outcome(() => {
    const value = decodeBolt11(invoice);
    return {
      currency: value.currency,
      amount_msat: value.amountMsat === null ? null : value.amountMsat.toString(),
      timestamp: value.timestamp,
      payment_hash: value.paymentHash,
      payment_secret: value.paymentSecret,
      payee: value.payee,
      expiry_seconds: value.expirySeconds,
      min_final_cltv_delta: value.minFinalCltvDelta,
      features: [...value.features].sort((a, b) => a - b),
      blinded_paths: value.blindedPaths,
    };
  });
  const bindings = Object.fromEntries(NETWORKS.map((network) => [network, outcome(() => ({ ...invoiceBinding(invoice, network) }))]));
  return { name, invoice, decoded, bindings };
}

const cases = [
  ...[...spec.valid, ...spec.invalid].map((example) => vector(`spec: ${example.title}`, example.invoice)),
  ...synthetic.map(([name, invoice]) => vector(name, invoice)),
];
const names = new Set(cases.map((item) => item.name));
if (names.size !== cases.length) throw new Error("vector names must be unique");
const generated = JSON.stringify({
  description: "BOLT11 reader and InvoiceBinding admission cases shared by rill-payments/src/bolt11.ts and rill-core's rill_core.wire.bolt11. " +
    "decoded and each binding hold either the result or {error}. testnet3 shares testnet4's currency.",
  source: `${spec.source}; synthetic cases from rill-web/scripts/generate-bolt11-vectors.ts, signed with the public test keys 1 and 2`,
  networks: NETWORKS,
  cases,
}, null, 2) + "\n";

const path = new URL("../../rill-docs/vectors/bolt11/cases-v1.json", import.meta.url);
if (process.argv.includes("--check")) {
  if (readFileSync(path, "utf8") !== generated) throw new Error("BOLT11 vectors are stale; run bun run generate:bolt11-vectors");
} else {
  writeFileSync(path, generated);
}
