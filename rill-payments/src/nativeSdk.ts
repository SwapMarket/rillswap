import { Interface } from "ethers";
import { receiptBindingTypedData, type EvmReceiptBinding } from "./evmReceipt";
import { parseNativeSandboxTerms, verifyNativeSandboxReceipt, type NativeSandboxTerms, type NativeSandboxView } from "./nativeContract";
import type { CheckoutStore } from "./sdk";

const transfer = new Interface(["function transfer(address,uint256) returns(bool)"]);
export interface NativeSandboxCheckpoint {
  readonly version: "native-sandbox-checkpoint/1";
  readonly intentId: string;
  readonly attemptId: string;
  readonly operationId: string;
  readonly terms: NativeSandboxTerms;
  readonly stage: "reserved" | "prepared" | "dispatched" | "observing" | "ambiguous";
  readonly binding: EvmReceiptBinding | null;
  readonly transactionHash: string | null;
}
export interface NativeSandboxTransfer {
  readonly chainId: string; readonly genesisHash: string; readonly from: string; readonly to: string; readonly nonce: number;
  readonly data: string; readonly value: "0"; readonly gasLimit: string; readonly maxFeePerGasWei: string; readonly maxPriorityFeePerGasWei: string;
}
/** Trusted sandbox wallet port. Persist immutable operation/request and private signed raw BEFORE broadcast; never sign on lookup. */
export interface NativeSandboxWallet {
  readonly version: "native-sandbox-wallet/1";
  readonly durableOperationIdentity: true;
  readonly guardedFeeCaps: true;
  identity(): Promise<{ chainId: string; genesisHash: string; sourceWallet: string; sourceNonce: string }>;
  signBinding(operationId: string, binding: EvmReceiptBinding, typed: ReturnType<typeof receiptBindingTypedData>): Promise<string>;
  /** Invoke guard immediately before signing and EVERY broadcast. Reentry may use only the identical private raw/hash. */
  dispatch(operationId: string, request: NativeSandboxTransfer, guard: (phase: "sign" | "broadcast") => Promise<void>): Promise<string>;
  lookup(operationId: string): Promise<string | null>;
}
export interface NativeSandboxCheckoutOptions {
  readonly intentUrl: string;
  readonly transportOrigin?: string;
  readonly paymentCapability: string;
  readonly terms: NativeSandboxTerms;
  readonly merchantPublicKey: string;
  readonly maxTokenBaseUnits: string;
  readonly gasLimit: string;
  readonly maxFeePerGasWei: string;
  readonly maxPriorityFeePerGasWei: string;
  readonly maxGasCostWei: string;
  readonly wallet: NativeSandboxWallet;
  readonly recoveryStore: CheckoutStore<NativeSandboxCheckpoint>;
  readonly fetch?: (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>;
  readonly now?: () => number;
}
const uint = (value: string, zero = false): bigint => {
  if (typeof value !== "string" || !(zero ? /^(0|[1-9][0-9]{0,77})$/ : /^[1-9][0-9]{0,77}$/).test(value) || BigInt(value) >= 1n << 256n) throw new Error("Invalid native spending bound"); return BigInt(value);
};
const hash = (value: unknown): value is string => typeof value === "string" && /^0x[0-9a-f]{64}$/.test(value);
const same = (first: NativeSandboxTerms, second: NativeSandboxTerms): boolean => JSON.stringify(parseNativeSandboxTerms(first)) === JSON.stringify(parseNativeSandboxTerms(second));

/** Explicit sandbox funding only. open() reconciles existing identity; it never authorizes another wallet dispatch. */
export function createNativeSandboxCheckout(options: NativeSandboxCheckoutOptions) {
  const terms = parseNativeSandboxTerms(options.terms), endpoint = new URL(options.intentUrl), transportOrigin = options.transportOrigin ?? terms.merchantOrigin;
  const transport = new URL(transportOrigin), merchantPublicKey = options.merchantPublicKey, capability = options.paymentCapability;
  if (transport.origin !== transportOrigin || transport.username || transport.password || (transportOrigin !== terms.merchantOrigin && (transport.protocol !== "http:" || transport.hostname !== "127.0.0.1")) ||
      endpoint.origin !== transportOrigin || endpoint.username || endpoint.password || endpoint.search || endpoint.hash || endpoint.pathname !== "/v1/native-sandbox/intents/" + terms.intentId ||
      !/^[A-Za-z0-9_-]{32,128}$/.test(capability) || !/^[0-9a-f]{64}$/.test(merchantPublicKey)) throw new Error("Untrusted native checkout identity");
  const { wallet, recoveryStore } = options, request = options.fetch ?? fetch, now = options.now ?? (() => Math.floor(Date.now() / 1000));
  const gasLimit = options.gasLimit, fee = options.maxFeePerGasWei, priority = options.maxPriorityFeePerGasWei;
  if (wallet.version !== "native-sandbox-wallet/1" || wallet.durableOperationIdentity !== true || wallet.guardedFeeCaps !== true ||
      uint(terms.amountBaseUnits) > uint(options.maxTokenBaseUnits) || uint(gasLimit) > 10_000_000n || uint(priority, true) > uint(fee) || uint(gasLimit) * uint(fee) > uint(options.maxGasCostWei)) throw new Error("Native wallet or spend policy unavailable");
  const deadline = (): void => { const value = now(); if (!Number.isSafeInteger(value) || value < terms.createdAt || value >= terms.expiresAt) throw new Error("Native funding deadline passed"); };
  const api = async (suffix = "", body?: unknown, key?: string): Promise<unknown> => {
    const response = await request(endpoint.toString() + suffix, { method: body === undefined ? "GET" : "POST", redirect: "error", cache: "no-store",
      headers: { Authorization: "Bearer " + capability, ...(body === undefined ? {} : { "Content-Type": "application/json" }), ...(key ? { "Idempotency-Key": key } : {}) }, body: body === undefined ? undefined : JSON.stringify(body) });
    if (!response.ok) throw new Error("Native merchant request refused"); return response.json();
  };
  const view = (input: unknown): NativeSandboxView => {
    const value = input as NativeSandboxView;
    if (!value || value.version !== "native-sandbox-view/1" || !same(value.terms, terms) || !["awaiting_funds", "sandbox_receipt_recorded", "sandbox_reconciliation", "sandbox_evidence_impaired"].includes(value.status) ||
        !["none_recorded", "recorded_local_confirmations", "recorded_impairment"].includes(value.evidence)) throw new Error("Native merchant view mismatch");
    if (Object.keys(value).sort().join(",") !== "event,evidence,receipt,status,terms,version") throw new Error("Native merchant view mismatch");
    const receipt = value.receipt;
    if (value.status === "awaiting_funds") {
      if (value.evidence !== "none_recorded" || receipt !== null || value.event !== null) throw new Error("Contradictory native funding evidence");
    } else {
      if (!receipt || Object.keys(receipt).sort().join(",") !== "assetId,blockHash,blockNumber,blockTimestamp,deduplicationKey,finality,logIndex,quantityBaseUnits,recipient,timing,transactionHash" ||
          receipt.assetId !== terms.asset.id || receipt.quantityBaseUnits !== terms.amountBaseUnits || receipt.recipient !== terms.recipient || receipt.finality !== "local_sandbox_confirmed" ||
          !hash(receipt.transactionHash) || !hash(receipt.blockHash) || ![receipt.blockNumber, receipt.blockTimestamp, receipt.logIndex].every((item) => Number.isSafeInteger(item) && item >= 0) ||
          receipt.blockTimestamp < terms.createdAt || receipt.timing !== (receipt.blockTimestamp < terms.expiresAt ? "timely" : "late") ||
          receipt.deduplicationKey !== `${terms.asset.chainId}:${terms.asset.genesisHash}:sandbox:${terms.asset.localSandbox!.namespace}:${receipt.transactionHash}:${receipt.logIndex}` ||
          value.evidence !== (value.status === "sandbox_evidence_impaired" ? "recorded_impairment" : "recorded_local_confirmations")) throw new Error("Invalid native recorded evidence");
      if (value.event !== null) {
        const entries = (object: object) => Object.entries(object).sort(([a], [b]) => a.localeCompare(b));
        if (!verifyNativeSandboxReceipt(value.event, merchantPublicKey, terms) || JSON.stringify(entries(receipt)) !== JSON.stringify(entries(value.event.event.receipt))) throw new Error("Unverified sandbox receipt event");
      }
      if ((value.status === "sandbox_receipt_recorded" && (value.event === null || receipt.timing !== "timely")) ||
          (value.status === "sandbox_reconciliation" && (value.event !== null || receipt.timing !== "late"))) throw new Error("Contradictory native receipt event");
    }
    return value;
  };
  const checkBinding = (binding: EvmReceiptBinding): void => {
    if (!binding || Object.keys(binding).sort().join(",") !== "amountBaseUnits,assetId,attemptId,intentId,merchantOrigin,recipient,sourceNonce,sourceWallet,validAfter,validBefore,version" ||
        binding.version !== "evm-receipt-binding/1" || binding.intentId !== terms.intentId || binding.attemptId !== terms.attemptId || binding.merchantOrigin !== terms.merchantOrigin ||
        binding.assetId !== terms.asset.id || binding.recipient !== terms.recipient || binding.amountBaseUnits !== terms.amountBaseUnits || binding.validAfter !== terms.createdAt || binding.validBefore !== terms.expiresAt ||
        typeof binding.sourceWallet !== "string" || !/^0x[0-9a-f]{40}$/.test(binding.sourceWallet) || binding.sourceWallet === terms.recipient ||
        typeof binding.sourceNonce !== "string" || !/^(0|[1-9][0-9]{0,15})$/.test(binding.sourceNonce) || !Number.isSafeInteger(Number(binding.sourceNonce))) throw new Error("Conflicting native payer binding");
  };
  const checkRecord = (record: NativeSandboxCheckpoint): void => {
    if (!record || record.version !== "native-sandbox-checkpoint/1" || record.intentId !== terms.intentId || record.attemptId !== terms.attemptId || !same(record.terms, terms) ||
        typeof record.operationId !== "string" || !/^[A-Za-z0-9_-]{16,128}$/.test(record.operationId) || !["reserved", "prepared", "dispatched", "observing", "ambiguous"].includes(record.stage) ||
        (record.transactionHash !== null && !hash(record.transactionHash)) || (record.stage !== "reserved" && record.stage !== "ambiguous" && record.binding === null)) throw new Error("Unknown or conflicting native checkpoint");
    if (record.binding !== null) checkBinding(record.binding);
  };
  let paying = false;
  return {
    async open(): Promise<{ view: NativeSandboxView; recovery: "explicit_payment_required" | "tracking" | "intervention" }> {
      let current = view(await api()); const record = await recoveryStore.load(terms.attemptId);
      if (!record) return { view: current, recovery: current.status === "awaiting_funds" ? "explicit_payment_required" : "tracking" };
      checkRecord(record);
      if (current.status !== "awaiting_funds") return { view: current, recovery: "tracking" };
      const transactionHash = record.transactionHash ?? await wallet.lookup(record.operationId);
      if (transactionHash === null) return { view: current, recovery: "intervention" };
      if (!hash(transactionHash)) throw new Error("Invalid native recovery reference");
      // No recovery writes: a stale observer cannot erase the successful begin owner's identity or hash.
      current = view(await api("/observe", { txHash: transactionHash })); return { view: current, recovery: "tracking" };
    },
    async pay(): Promise<NativeSandboxView> {
      if (paying) throw new Error("Native payment already active"); paying = true;
      let record: NativeSandboxCheckpoint | null = null;
      let ownsReservation = false;
      try {
        if (view(await api()).status !== "awaiting_funds") throw new Error("Native order is not payable"); deadline();
        const existing = await recoveryStore.load(terms.attemptId); if (existing) { checkRecord(existing); throw new Error("Native dispatch already reserved; reconcile it"); }
        record = { version: "native-sandbox-checkpoint/1", intentId: terms.intentId, attemptId: terms.attemptId, operationId: crypto.randomUUID(), terms, stage: "reserved", binding: null, transactionHash: null };
        if (!await recoveryStore.begin(record)) { record = null; throw new Error("Native dispatch already reserved; reconcile it"); }
        ownsReservation = true;
        deadline(); const identity = await wallet.identity(); deadline();
        if (identity.chainId !== terms.asset.chainId || identity.genesisHash !== terms.asset.genesisHash) throw new Error("Wrong native wallet network");
        const binding: EvmReceiptBinding = Object.freeze({ version: "evm-receipt-binding/1", merchantOrigin: terms.merchantOrigin, intentId: terms.intentId, attemptId: terms.attemptId, assetId: terms.asset.id,
          sourceWallet: identity.sourceWallet, sourceNonce: identity.sourceNonce, recipient: terms.recipient, amountBaseUnits: terms.amountBaseUnits, validAfter: terms.createdAt, validBefore: terms.expiresAt }); checkBinding(binding);
        record = { ...record, binding }; await recoveryStore.update(record); deadline();
        const signature = await wallet.signBinding(record.operationId, binding, receiptBindingTypedData(terms.asset, binding)); deadline();
        const prepared = await api("/prepare", { binding, signature }, record.operationId) as { version: string; terms: NativeSandboxTerms; prepared: { binding: EvmReceiptBinding; signature: string; preparedAt: number; preparedBlockNumber: number; preparedBlockHash: string } };
        deadline();
        checkBinding(prepared.prepared.binding);
        if (prepared.version !== "native-sandbox-preparation/1" || !same(prepared.terms, terms) || prepared.prepared.binding.sourceWallet !== binding.sourceWallet || prepared.prepared.binding.sourceNonce !== binding.sourceNonce || prepared.prepared.signature !== signature ||
            !Number.isSafeInteger(prepared.prepared.preparedAt) || prepared.prepared.preparedAt < terms.createdAt || prepared.prepared.preparedAt >= terms.expiresAt || !Number.isSafeInteger(prepared.prepared.preparedBlockNumber) || prepared.prepared.preparedBlockNumber < 0 || !hash(prepared.prepared.preparedBlockHash)) throw new Error("Native preparation mismatch");
        record = { ...record, stage: "prepared" }; await recoveryStore.update(record); deadline();
        const guard = async (phase: "sign" | "broadcast"): Promise<void> => {
          if (phase !== "sign" && phase !== "broadcast") throw new Error("Unknown native wallet commitment phase");
          deadline(); if (view(await api()).status !== "awaiting_funds") throw new Error("Native order already has recorded evidence"); deadline();
          const current = await wallet.identity(); deadline();
          if (current.chainId !== identity.chainId || current.genesisHash !== identity.genesisHash || current.sourceWallet !== identity.sourceWallet || (phase === "sign" && current.sourceNonce !== identity.sourceNonce)) throw new Error("Native wallet commitment changed");
        };
        record = { ...record, stage: "dispatched" }; await recoveryStore.update(record); await guard("sign");
        const transferRequest = Object.freeze({ chainId: identity.chainId, genesisHash: identity.genesisHash, from: identity.sourceWallet, to: terms.asset.token, nonce: Number(identity.sourceNonce),
          data: transfer.encodeFunctionData("transfer", [terms.recipient, BigInt(terms.amountBaseUnits)]), value: "0" as const, gasLimit, maxFeePerGasWei: fee, maxPriorityFeePerGasWei: priority });
        const transactionHash = await wallet.dispatch(record.operationId, transferRequest, guard); if (!hash(transactionHash)) throw new Error("Invalid native wallet result");
        record = { ...record, stage: "observing", transactionHash }; await recoveryStore.update(record);
        return view(await api("/observe", { txHash: transactionHash }));
      } catch (error) {
        if (record && ownsReservation) await recoveryStore.update({ ...record, stage: "ambiguous" }); throw error;
      } finally { paying = false; }
    },
  };
}
