/**
 * RS-006 transport proof of work (NIP-13) on provider-bound gift wraps.
 *
 * A provider advertising `rillswap/transport-pow` requires work on every
 * kind-1059 outer event sent to it. Work is the number of leading zero bits of
 * the event ID, capped by the target committed in exactly one
 * `["nonce", counter, target]` tag. Mining varies only the counter, so the
 * randomized NIP-59 `created_at` is kept. Work raises the cost of floods; it is
 * not authentication or principal protection.
 */
import { sha256 } from "@noble/hashes/sha2.js";
import { hexToBytes } from "@noble/hashes/utils.js";

export const TRANSPORT_POW_EXTENSION = "rillswap/transport-pow";
/**
 * About a million hashes on average. Every attempt rehashes the whole outer
 * ciphertext (the counter precedes `content` in the NIP-01 serialization), so
 * cost grows with message size: for a 3 KB wrap, desktop Chromium measured
 * about 7 us per WebCrypto hash and 49 us per fallback hash.
 */
export const MAX_WORK_BITS = 20;
const TARGET = /^(0|[1-9][0-9]{0,2})$/;
const BATCH = 512;
const PLACEHOLDER = "\u0000"; // JSON always escapes it; no NIP-59 field contains it
const encoder = new TextEncoder();

export class TransportWorkError extends Error {
  constructor() {
    super("Transport proof of work refused");
    this.name = "TransportWorkError";
  }
}

/** Return the work signed extensions require (0: none); a malformed requirement throws. */
export function transportWorkRequirement(extensions: Readonly<Record<string, unknown>>): number {
  if (!Object.hasOwn(extensions, TRANSPORT_POW_EXTENSION)) return 0;
  const value = extensions[TRANSPORT_POW_EXTENSION];
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new TransportWorkError();
  const keys = Object.keys(value);
  const bits = (value as Record<string, unknown>).bits;
  if (keys.length !== 1 || keys[0] !== "bits" || typeof bits !== "number" ||
      !Number.isInteger(bits) || bits < 1 || bits > MAX_WORK_BITS) {
    throw new TransportWorkError();
  }
  return bits;
}

export function leadingZeroBits(digest: Uint8Array): number {
  let bits = 0;
  for (const byte of digest) {
    if (byte !== 0) return bits + Math.clz32(byte) - 24;
    bits += 8;
  }
  return bits;
}

/** The work an event with this (already recomputed) ID proves under its tags. */
export function committedWork(eventId: string, tags: readonly (readonly string[])[]): number {
  const nonces = tags.filter((tag) => tag[0] === "nonce");
  const target = nonces[0]?.[2];
  if (nonces.length !== 1 || nonces[0]!.length !== 3 || target === undefined || !TARGET.test(target)) return 0;
  return Math.min(leadingZeroBits(hexToBytes(eventId)), Number(target));
}

function attempt(prefix: Uint8Array, counter: number, tail: Uint8Array): Uint8Array<ArrayBuffer> {
  const digits = encoder.encode(String(counter));
  const message = new Uint8Array(prefix.length + digits.length + tail.length);
  message.set(prefix);
  message.set(digits, prefix.length);
  message.set(tail, prefix.length + digits.length);
  return message;
}

async function batch(
  subtle: SubtleCrypto | null, prefix: Uint8Array, tail: Uint8Array, base: number, bits: number,
): Promise<number | null> {
  if (subtle !== null) {
    // Native hashing in parallel; awaiting it lets the page render between batches.
    const digests = await Promise.all(
      Array.from({ length: BATCH }, (_, i) => subtle.digest("SHA-256", attempt(prefix, base + i, tail))),
    );
    const hit = digests.findIndex((digest) => leadingZeroBits(new Uint8Array(digest)) >= bits);
    return hit < 0 ? null : base + hit;
  }
  const head = sha256.create().update(prefix); // the fixed prefix is hashed once per batch
  for (let counter = base; counter < base + BATCH; counter += 1) {
    const digest = head.clone().update(encoder.encode(String(counter))).update(tail).digest();
    if (leadingZeroBits(digest) >= bits) return counter;
  }
  await new Promise((resolve) => setTimeout(resolve, 0)); // keep the page responsive
  return null;
}

/**
 * Return `tags` plus a nonce tag giving the NIP-01 event `bits` leading zero
 * bits. WebCrypto is used when the page has it (secure contexts); otherwise a
 * slower synchronous hash runs in yielding batches.
 */
export async function mineNonceTag(
  pubkey: string,
  createdAt: number,
  kind: number,
  tags: readonly (readonly string[])[],
  content: string,
  bits: number,
  subtle: SubtleCrypto | null = globalThis.crypto?.subtle ?? null,
): Promise<string[][]> {
  if (!Number.isInteger(bits) || bits < 1 || bits > MAX_WORK_BITS) throw new TransportWorkError();
  const template = [...tags.map((tag) => [...tag]), ["nonce", PLACEHOLDER, String(bits)]];
  // nostr-tools hashes exactly this JSON.stringify serialization (NIP-01).
  const serialized = JSON.stringify([0, pubkey, createdAt, kind, template, content]);
  const marker = JSON.stringify(PLACEHOLDER);
  const at = serialized.indexOf(marker);
  if (at < 0 || serialized.indexOf(marker, at + 1) >= 0) throw new TransportWorkError();
  const prefix = encoder.encode(`${serialized.slice(0, at)}"`);
  const tail = encoder.encode(`"${serialized.slice(at + marker.length)}`);
  // Failing this bound has probability e**-65536.
  for (let base = 0; base < 2 ** (bits + 16); base += BATCH) {
    const found = await batch(subtle, prefix, tail, base, bits);
    if (found !== null) return [...tags.map((tag) => [...tag]), ["nonce", String(found), String(bits)]];
  }
  throw new TransportWorkError();
}
