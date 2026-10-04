import { secp256k1 } from "@noble/curves/secp256k1.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { bech32 } from "@scure/base";

const secret = new Uint8Array(32); secret[31] = 1; // Public test-only fixture key.
export const receiver = bytesToHex(secp256k1.getPublicKey(secret, true));
export function testInvoice(operationId: string, amountMsat = "1000000", createdAt = 1000, expiresAt = 2000, currency = "bcrt"): string {
  const words = (n: number): number[] => { const out: number[] = []; do { out.unshift(n % 32); n = Math.floor(n / 32); } while (n); return out; };
  const tag = (type: number, values: number[]): number[] => [type, Math.floor(values.length / 32), values.length % 32, ...values];
  const timestamp = words(createdAt); while (timestamp.length < 7) timestamp.unshift(0);
  const hash = sha256(new TextEncoder().encode("test hash " + operationId));
  const data = [...timestamp, ...tag(1, bech32.toWords(hash)), ...tag(16, bech32.toWords(sha256(hash))),
    ...tag(13, bech32.toWords(new TextEncoder().encode("Public checkout fixture"))), ...tag(6, words(expiresAt - createdAt)), ...tag(5, [16, 8, 0])];
  let bits = 0, accumulator = 0; const packed: number[] = [];
  for (const word of data) { accumulator = (accumulator << 5) | word; bits += 5; while (bits >= 8) { bits -= 8; packed.push((accumulator >> bits) & 255); } accumulator &= (1 << bits) - 1; }
  if (bits) packed.push(accumulator << (8 - bits));
  const hrp = `ln${currency}${BigInt(amountMsat) * 10n}p`;
  const digest = sha256(new Uint8Array([...new TextEncoder().encode(hrp), ...packed]));
  const signed = secp256k1.sign(digest, secret, { prehash: false, format: "recovered" });
  const signature = new Uint8Array([...signed.slice(1), signed[0]!]);
  return bech32.encode(hrp, [...data, ...bech32.toWords(signature)], 2048);
}
