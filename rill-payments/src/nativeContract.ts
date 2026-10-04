import { ed25519 } from "@noble/curves/ed25519.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { validateEvmAsset, type EvmTokenAsset, type VerifiedTokenReceipt } from "./evmReceipt";

export interface NativeSandboxTerms {
  readonly version: "native-sandbox-checkout/1";
  readonly merchantOrigin: string;
  readonly intentId: string;
  readonly attemptId: string;
  readonly asset: EvmTokenAsset;
  readonly recipient: string;
  readonly amountBaseUnits: string;
  readonly createdAt: number;
  readonly expiresAt: number;
}
export interface NativeSandboxReceiptEvent {
  readonly version: "native-sandbox-event/1";
  readonly type: "sandbox.receipt_recorded";
  readonly scope: "local_sandbox_only";
  readonly id: string;
  readonly terms: NativeSandboxTerms;
  readonly receipt: VerifiedTokenReceipt;
  readonly recordedAt: number;
}
export interface SignedNativeSandboxReceipt {
  readonly algorithm: "Ed25519";
  readonly publicKey: string;
  readonly event: NativeSandboxReceiptEvent;
  readonly signature: string;
}
export interface NativeSandboxView {
  readonly version: "native-sandbox-view/1";
  readonly terms: NativeSandboxTerms;
  readonly status: "awaiting_funds" | "sandbox_receipt_recorded" | "sandbox_reconciliation" | "sandbox_evidence_impaired";
  readonly evidence: "none_recorded" | "recorded_local_confirmations" | "recorded_impairment";
  readonly receipt: VerifiedTokenReceipt | null;
  readonly event: SignedNativeSandboxReceipt | null;
}
const id = (value: unknown): boolean => typeof value === "string" && /^[A-Za-z0-9_-]{16,128}$/.test(value);
const hash = (value: unknown): boolean => typeof value === "string" && /^0x[0-9a-f]{64}$/.test(value);
const time = (value: unknown): boolean => typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
const fields = (input: unknown, expected: string): boolean => !!input && typeof input === "object" && !Array.isArray(input) && Object.keys(input).sort().join(",") === expected;

/** A distinct sandbox contract; these terms can never be parsed as Lightning checkout terms. */
export function parseNativeSandboxTerms(input: unknown): NativeSandboxTerms {
  if (!fields(input, "amountBaseUnits,asset,attemptId,createdAt,expiresAt,intentId,merchantOrigin,recipient,version")) throw new Error("Invalid sandbox terms");
  const terms = input as NativeSandboxTerms; validateEvmAsset(terms.asset);
  const origin = new URL(terms.merchantOrigin);
  if (terms.version !== "native-sandbox-checkout/1" || typeof terms.merchantOrigin !== "string" || origin.origin !== terms.merchantOrigin || origin.protocol !== "https:" || origin.username || origin.password ||
      !id(terms.intentId) || !id(terms.attemptId) || typeof terms.recipient !== "string" || !/^0x[0-9a-f]{40}$/.test(terms.recipient) ||
      typeof terms.amountBaseUnits !== "string" || !/^[1-9][0-9]{0,77}$/.test(terms.amountBaseUnits) || BigInt(terms.amountBaseUnits) >= 1n << 256n ||
      !time(terms.createdAt) || !time(terms.expiresAt) || terms.createdAt >= terms.expiresAt || terms.asset.chainId !== "31337" || terms.asset.implementation !== null ||
      !fields(terms.asset, "behavior,behaviorConformanceVerified,chainId,decimals,genesisHash,historicalStateVerified,id,implementation,localSandbox,runtimeCodeHash,token") ||
      !fields(terms.asset.localSandbox, "confirmations,namespace,version")) throw new Error("Invalid sandbox terms");
  const asset = terms.asset;
  return Object.freeze({ version: terms.version, merchantOrigin: terms.merchantOrigin, intentId: terms.intentId, attemptId: terms.attemptId,
    asset: Object.freeze({ id: asset.id, chainId: asset.chainId, genesisHash: asset.genesisHash, token: asset.token, decimals: asset.decimals, behavior: asset.behavior,
      runtimeCodeHash: asset.runtimeCodeHash, implementation: null, historicalStateVerified: asset.historicalStateVerified, behaviorConformanceVerified: asset.behaviorConformanceVerified,
      localSandbox: Object.freeze({ version: asset.localSandbox!.version, namespace: asset.localSandbox!.namespace, confirmations: asset.localSandbox!.confirmations }) }), recipient: terms.recipient, amountBaseUnits: terms.amountBaseUnits, createdAt: terms.createdAt, expiresAt: terms.expiresAt });
}
function normalizedEvent(event: NativeSandboxReceiptEvent): NativeSandboxReceiptEvent {
  if (!fields(event, "id,receipt,recordedAt,scope,terms,type,version") || event.version !== "native-sandbox-event/1" || event.type !== "sandbox.receipt_recorded" || event.scope !== "local_sandbox_only" ||
      !id(event.id) || !time(event.recordedAt)) throw new Error("Invalid sandbox receipt event");
  const terms = parseNativeSandboxTerms(event.terms), receipt = event.receipt;
  if (!fields(receipt, "assetId,blockHash,blockNumber,blockTimestamp,deduplicationKey,finality,logIndex,quantityBaseUnits,recipient,timing,transactionHash") || receipt.assetId !== terms.asset.id ||
      receipt.quantityBaseUnits !== terms.amountBaseUnits || receipt.recipient !== terms.recipient || receipt.finality !== "local_sandbox_confirmed" || receipt.timing !== "timely" ||
      !hash(receipt.transactionHash) || !hash(receipt.blockHash) || !time(receipt.blockNumber) || !time(receipt.logIndex) || !time(receipt.blockTimestamp) ||
      receipt.blockTimestamp < terms.createdAt || receipt.blockTimestamp >= terms.expiresAt || event.recordedAt < receipt.blockTimestamp ||
      receipt.deduplicationKey !== `${terms.asset.chainId}:${terms.asset.genesisHash}:sandbox:${terms.asset.localSandbox!.namespace}:${receipt.transactionHash}:${receipt.logIndex}`) throw new Error("Invalid sandbox receipt event");
  return { version: event.version, type: event.type, scope: event.scope, id: event.id, terms,
    receipt: { assetId: receipt.assetId, quantityBaseUnits: receipt.quantityBaseUnits, recipient: receipt.recipient, transactionHash: receipt.transactionHash, logIndex: receipt.logIndex,
      deduplicationKey: receipt.deduplicationKey, blockHash: receipt.blockHash, blockNumber: receipt.blockNumber, blockTimestamp: receipt.blockTimestamp, finality: receipt.finality, timing: receipt.timing }, recordedAt: event.recordedAt };
}
const eventBytes = (event: NativeSandboxReceiptEvent): Uint8Array => new TextEncoder().encode(JSON.stringify(["rillswap-native-sandbox-receipt/1", normalizedEvent(event)]));
export function signNativeSandboxReceipt(event: NativeSandboxReceiptEvent, key: Uint8Array): SignedNativeSandboxReceipt {
  const normalized = normalizedEvent(event);
  return { algorithm: "Ed25519", publicKey: bytesToHex(ed25519.getPublicKey(key)), event: normalized, signature: bytesToHex(ed25519.sign(eventBytes(normalized), key)) };
}
/** Historical sandbox evidence only. Pin the key and terms independently; signatures never authorize real fulfillment. */
export function verifyNativeSandboxReceipt(envelope: SignedNativeSandboxReceipt, expectedPublicKey: string, expectedTerms: NativeSandboxTerms): boolean {
  try {
    if (!fields(envelope, "algorithm,event,publicKey,signature") || envelope.algorithm !== "Ed25519" || envelope.publicKey !== expectedPublicKey ||
        typeof expectedPublicKey !== "string" || !/^[0-9a-f]{64}$/.test(expectedPublicKey) || typeof envelope.signature !== "string" || !/^[0-9a-f]{128}$/.test(envelope.signature)) return false;
    return JSON.stringify(parseNativeSandboxTerms(envelope.event.terms)) === JSON.stringify(parseNativeSandboxTerms(expectedTerms)) &&
      ed25519.verify(hexToBytes(envelope.signature), eventBytes(envelope.event), hexToBytes(expectedPublicKey));
  } catch { return false; }
}
