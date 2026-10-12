import { invoiceBinding } from "@rillswap/payments/bolt11";
import { evaluateNative, parseTerms, type NativePolicy } from "@rillswap/payments";
import type { CheckoutCheckpoint, CheckoutStore } from "@rillswap/payments/sdk";
import { assertFundingWindow, runSwap, type SwapHooks, type SwapOutcome, type SwapRequest } from "./swap";

export interface MerchantSwapOptions {
  readonly terms: unknown;
  readonly policy: NativePolicy & { readonly approvedRillProviders: readonly string[] };
  readonly invoice: string;
  readonly relay: Parameters<typeof runSwap>[0];
  readonly request: Omit<SwapRequest, "invoice">;
  readonly hooks: Omit<SwapHooks, "saveRecovery">;
  readonly recoveryStore: CheckoutStore;
  /** Must durably preserve the encrypted file in a payer-controlled wallet/store before returning. */
  readonly savePayerRecovery: (file: Uint8Array, stage: "terms" | "funded" | "provider_complete") => Promise<string>;
  readonly now?: () => number;
}
export interface MerchantSwapProgress {
  readonly state: "awaiting_merchant_receipt";
  readonly swapId: string;
  readonly fundingTxid: string;
  readonly recoveryRef: string;
}

/** Adapts existing regtest RillSwap, without exporting claim secrets or interpreting preimage as receipt. */
export async function executeMerchantSwap(options: MerchantSwapOptions,
  runner?: (request: SwapRequest, hooks: SwapHooks) => Promise<SwapOutcome>): Promise<MerchantSwapProgress> {
  const now = options.now ?? (() => Math.floor(Date.now() / 1000));
  const execute = runner ?? ((request: SwapRequest, hooks: SwapHooks) => runSwap(options.relay, request, hooks, undefined, () => now() * 1000));
  const terms = parseTerms(options.terms);
  const binding = invoiceBinding(options.invoice, terms.network);
  if (terms.network !== "regtest" || options.request.network.name !== terms.network ||
      !/^[0-9a-f]{64}$/.test(options.request.identity) || !options.policy.approvedRillProviders.includes(options.request.identity) ||
      binding.amount_msat !== terms.amountMsat || binding.payment_hash !== terms.paymentHash || binding.payee_compressed_pubkey !== terms.receiver ||
      binding.expires_at < terms.expiresAt || binding.created_at > now()) throw new Error("Merchant swap destination or admission mismatch");
  const limits = options.request.limits;
  const caps = [limits.maxSuccessFeeSat, limits.maxFundingFeeSat, limits.maxClaimFeeSat, limits.maxRefundFeeSat];
  if (caps.some((cap) => cap < 0n)) throw new Error("Invalid buyer fee limits");
  const maximumExtra = caps.reduce((sum, cap) => sum + cap, 0n) * 1000n;
  const eligible = (): void => {
    const result = evaluateNative({ ...terms, buyerExtraMsat: maximumExtra.toString() }, options.policy, now());
    if (!result.eligible) throw new Error(`Merchant swap unavailable: ${result.reason}`);
  };
  eligible();
  if (Math.min(terms.expiresAt, binding.expires_at) - now() < 1800) throw new Error("RillSwap requires at least 1800 seconds of invoice lifetime before quoting");
  let checkpoint: CheckoutCheckpoint = { version: "checkout-checkpoint/1", attemptId: terms.attemptId, intentId: terms.intentId,
    terms, invoice: options.invoice, stage: "dispatched", route: { adapter: "rillswap-btc-ln/1", providerId: options.request.identity } };
  if (!await options.recoveryStore.begin(checkpoint)) throw new Error("Attempt already dispatched; resume tracking or payer recovery");
  let recoveryRef: string | null = null;
  let quoteExpiry: number | null = null;
  const save = async (file: Uint8Array, stage: "terms" | "funded" | "provider_complete"): Promise<void> => {
    const ref = await options.savePayerRecovery(file, stage);
    if (!ref || ref.length > 512) throw new Error("Durable payer recovery reference required");
    recoveryRef = ref;
    checkpoint = { ...checkpoint, route: { ...checkpoint.route!, recoveryRef: ref } };
    await options.recoveryStore.update(checkpoint);
  };
  try {
    const result = await execute({ ...options.request, invoice: options.invoice, checkoutExpiresAt: terms.expiresAt }, {
      ...options.hooks, saveRecovery: save,
      async fundingSource(request) {
        eligible();
        if (!recoveryRef) throw new Error("Payer recovery must be durably saved before funding");
        return options.hooks.fundingSource(request);
      },
      async broadcast(raw, txid) {
        eligible();
        if (quoteExpiry === null || checkpoint.route?.fundingTxid !== txid) throw new Error("Funding commitment checkpoint missing");
        assertFundingWindow(quoteExpiry, binding.expires_at, now(), terms.expiresAt);
        // No asynchronous persistence between this final check and delegation.
        await options.hooks.broadcast(raw, txid);
      },
      async beforeFundingCommit(txid, termsExpiry) {
        quoteExpiry = termsExpiry;
        checkpoint = { ...checkpoint, route: { ...checkpoint.route!, fundingTxid: txid } };
        await options.recoveryStore.update(checkpoint);
        await options.hooks.beforeFundingCommit?.(txid, termsExpiry);
        eligible();
        assertFundingWindow(termsExpiry, binding.expires_at, now(), terms.expiresAt);
      },
    });
    if (!recoveryRef) throw new Error("Missing payer recovery");
    await save(result.paidRecovery, "provider_complete");
    checkpoint = { ...checkpoint, stage: "observing", route: { ...checkpoint.route!, swapId: result.sessionId, fundingTxid: result.fundingTxid } };
    await options.recoveryStore.update(checkpoint);
    return Object.freeze({ state: "awaiting_merchant_receipt", swapId: result.sessionId, fundingTxid: result.fundingTxid, recoveryRef });
  } catch (error) {
    await options.recoveryStore.update({ ...checkpoint, stage: "ambiguous" });
    throw error;
  }
}
