import { ed25519 } from "@noble/curves/ed25519.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";

/**
 * Local Monero regtest receipt contract. Regtest uses mainnet address formats,
 * so the profile (affirmed `fakechain` daemon, pinned block-1 anchor) is part of
 * the signed terms. Nothing here is a mainnet payment claim.
 */
export interface MoneroRegtestProfile {
  readonly version: "monero-regtest/1";
  readonly namespace: string;
  /** Required confirmations; at least the 10-block spendable age. */
  readonly confirmations: number;
  /** Hash of block 1 when the ledger was provisioned (detects a reset chain). */
  readonly anchorHash: string;
}
export interface MoneroRegtestTerms {
  readonly version: "monero-regtest-checkout/1";
  readonly merchantOrigin: string;
  readonly intentId: string;
  readonly network: MoneroRegtestProfile;
  readonly address: string;
  readonly subaddressIndex: number;
  readonly amountAtomic: string;
  readonly createdAt: number;
  readonly expiresAt: number;
}
/** One confirmed incoming (txid, subaddress) entry, as recorded by the ledger. */
export interface MoneroReceipt {
  readonly key: string;
  readonly txid: string;
  readonly amountAtomic: string;
  readonly height: number;
  readonly timestamp: number;
  readonly timing: "timely" | "late";
}
export interface MoneroRegtestEvent {
  readonly version: "monero-regtest-event/1";
  readonly type: "regtest.receipt_recorded";
  readonly scope: "local_regtest_only";
  readonly id: string;
  readonly terms: MoneroRegtestTerms;
  readonly receipts: readonly MoneroReceipt[];
  readonly recordedAt: number;
}
export interface SignedMoneroRegtestReceipt {
  readonly algorithm: "Ed25519";
  readonly publicKey: string;
  readonly event: MoneroRegtestEvent;
  readonly signature: string;
}
export type MoneroReconciliationReason = "late" | "overpaid" | "underpaid";
export interface MoneroRegtestView {
  readonly version: "monero-regtest-view/1";
  readonly terms: MoneroRegtestTerms;
  readonly status: "awaiting_funds" | "expired" | "regtest_receipt_recorded" | "regtest_reconciliation" | "regtest_evidence_impaired";
  readonly reconciliation: MoneroReconciliationReason | null;
  /** Unpersisted latest observation for display; never evidence of payment. */
  readonly progress: { readonly seenAtomic: string; readonly confirmedAtomic: string; readonly observedAt: number } | null;
  readonly receipts: readonly MoneroReceipt[];
  readonly event: SignedMoneroRegtestReceipt | null;
}

const BASE58 = "[1-9A-HJ-NP-Za-km-z]";
export const PRIMARY_ADDRESS = new RegExp(`^4${BASE58}{94}$`);
export const SUBADDRESS = new RegExp(`^8${BASE58}{94}$`);
export const ATOMIC = /^[1-9][0-9]{0,19}$/;
const id = (value: unknown): boolean => typeof value === "string" && /^[A-Za-z0-9_-]{16,128}$/.test(value);
const hex64 = (value: unknown): boolean => typeof value === "string" && /^[0-9a-f]{64}$/.test(value);
const time = (value: unknown): boolean => typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
const fields = (input: unknown, expected: string): boolean => !!input && typeof input === "object" && !Array.isArray(input) && Object.keys(input).sort().join(",") === expected;
const amount = (value: unknown): boolean => typeof value === "string" && ATOMIC.test(value) && BigInt(value) < 1n << 64n;

/** Ledger deduplication key of one (txid, subaddress) receipt. */
export const moneroReceiptKey = (network: MoneroRegtestProfile, subaddressIndex: number, txid: string): string =>
  `monero-regtest:${network.namespace}:${network.anchorHash}:0/${subaddressIndex}:${txid}`;

export function parseMoneroRegtestProfile(input: unknown): MoneroRegtestProfile {
  const profile = input as MoneroRegtestProfile;
  if (!fields(input, "anchorHash,confirmations,namespace,version") || profile.version !== "monero-regtest/1" || typeof profile.namespace !== "string" ||
      !/^[a-z0-9-]{1,64}$/.test(profile.namespace) || !Number.isSafeInteger(profile.confirmations) || profile.confirmations < 10 || profile.confirmations > 1000 ||
      !hex64(profile.anchorHash)) throw new Error("Invalid Monero regtest profile");
  return Object.freeze({ version: profile.version, namespace: profile.namespace, confirmations: profile.confirmations, anchorHash: profile.anchorHash });
}

export function parseMoneroRegtestTerms(input: unknown): MoneroRegtestTerms {
  if (!fields(input, "address,amountAtomic,createdAt,expiresAt,intentId,merchantOrigin,network,subaddressIndex,version")) throw new Error("Invalid Monero regtest terms");
  const terms = input as MoneroRegtestTerms, network = parseMoneroRegtestProfile(terms.network);
  const origin = typeof terms.merchantOrigin === "string" ? new URL(terms.merchantOrigin) : null;
  if (terms.version !== "monero-regtest-checkout/1" || !origin || origin.origin !== terms.merchantOrigin || origin.protocol !== "https:" ||
      !id(terms.intentId) || typeof terms.address !== "string" || !SUBADDRESS.test(terms.address) || !Number.isSafeInteger(terms.subaddressIndex) || terms.subaddressIndex < 1 ||
      !amount(terms.amountAtomic) || !time(terms.createdAt) || !time(terms.expiresAt) || terms.createdAt >= terms.expiresAt) throw new Error("Invalid Monero regtest terms");
  return Object.freeze({ version: terms.version, merchantOrigin: terms.merchantOrigin, intentId: terms.intentId, network, address: terms.address,
    subaddressIndex: terms.subaddressIndex, amountAtomic: terms.amountAtomic, createdAt: terms.createdAt, expiresAt: terms.expiresAt });
}

function normalizedEvent(event: MoneroRegtestEvent): MoneroRegtestEvent {
  if (!fields(event, "id,receipts,recordedAt,scope,terms,type,version") || event.version !== "monero-regtest-event/1" || event.type !== "regtest.receipt_recorded" ||
      event.scope !== "local_regtest_only" || !id(event.id) || !time(event.recordedAt) || !Array.isArray(event.receipts) || event.receipts.length === 0) throw new Error("Invalid Monero regtest event");
  const terms = parseMoneroRegtestTerms(event.terms); let total = 0n; const keys = new Set<string>();
  const receipts = event.receipts.map((receipt) => {
    if (!fields(receipt, "amountAtomic,height,key,timestamp,timing,txid") || !hex64(receipt.txid) || !amount(receipt.amountAtomic) || !time(receipt.height) || !time(receipt.timestamp) ||
        receipt.timing !== "timely" || receipt.timestamp < terms.createdAt || receipt.timestamp >= terms.expiresAt || event.recordedAt < receipt.timestamp ||
        receipt.key !== moneroReceiptKey(terms.network, terms.subaddressIndex, receipt.txid) || keys.has(receipt.key)) throw new Error("Invalid Monero regtest event");
    keys.add(receipt.key); total += BigInt(receipt.amountAtomic);
    return { key: receipt.key, txid: receipt.txid, amountAtomic: receipt.amountAtomic, height: receipt.height, timestamp: receipt.timestamp, timing: receipt.timing };
  });
  if (total !== BigInt(terms.amountAtomic)) throw new Error("Invalid Monero regtest event");
  return { version: event.version, type: event.type, scope: event.scope, id: event.id, terms, receipts, recordedAt: event.recordedAt };
}
const eventBytes = (event: MoneroRegtestEvent): Uint8Array => new TextEncoder().encode(JSON.stringify(["rillswap-monero-regtest-receipt/1", normalizedEvent(event)]));

export function signMoneroRegtestReceipt(event: MoneroRegtestEvent, key: Uint8Array): SignedMoneroRegtestReceipt {
  const normalized = normalizedEvent(event);
  return { algorithm: "Ed25519", publicKey: bytesToHex(ed25519.getPublicKey(key)), event: normalized, signature: bytesToHex(ed25519.sign(eventBytes(normalized), key)) };
}

/** Local regtest evidence only. Pin the key and terms independently; this never proves a mainnet payment. */
export function verifyMoneroRegtestReceipt(envelope: SignedMoneroRegtestReceipt, expectedPublicKey: string, expectedTerms: MoneroRegtestTerms): boolean {
  try {
    if (!fields(envelope, "algorithm,event,publicKey,signature") || envelope.algorithm !== "Ed25519" || !hex64(expectedPublicKey) || envelope.publicKey !== expectedPublicKey ||
        typeof envelope.signature !== "string" || !/^[0-9a-f]{128}$/.test(envelope.signature)) return false;
    return JSON.stringify(parseMoneroRegtestTerms(envelope.event.terms)) === JSON.stringify(parseMoneroRegtestTerms(expectedTerms)) &&
      ed25519.verify(hexToBytes(envelope.signature), eventBytes(envelope.event), hexToBytes(expectedPublicKey));
  } catch { return false; }
}
