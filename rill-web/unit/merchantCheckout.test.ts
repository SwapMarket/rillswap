import { expect, test } from "bun:test";
import { executeMerchantSwap, type MerchantSwapOptions } from "../src/swap/merchantCheckout";
import { assertFundingWindow, type FundingRequest, type SwapHooks, type SwapOutcome } from "../src/swap/swap";
import { invoiceBinding } from "../src/swap/bolt11";
import { receiver, testInvoice } from "../../rill-payments/tests/helpers";
import type { CheckoutCheckpoint } from "@rillswap/payments/sdk";

function fixture() {
  const invoice = testInvoice("merchant_swap", "1000000", 1000, 4000); const binding = invoiceBinding(invoice, "regtest");
  let row: CheckoutCheckpoint | null = null, now = 1200, broadcasts = 0;
  const options: MerchantSwapOptions = {
    invoice, terms: { version: "checkout/0.1", policyVersion: "native-lightning/1", merchantOrigin: "https://merchant.example",
      intentId: "merchant_intent_001", attemptId: "merchant_attempt_01", network: "regtest", amountMsat: "1000000", buyerExtraMsat: "0",
      receiver, paymentHash: binding.payment_hash, expiresAt: 4000 },
    policy: { version: "native-lightning/1", merchantOrigin: "https://merchant.example", receiver, network: "regtest", maxBuyerExtraMsat: "100000", maxBuyerExtraBps: 1000, approvedRillProviders: ["4".repeat(64)] },
    relay: { publish: async () => { throw new Error("No relay in disconnected fixture"); }, subscribe: async () => {}, next: async () => null, query: async () => ({ events: [], truncated: false }) },
    request: { identity: "4".repeat(64), network: { name: "regtest" }, refundScript: "fixture", tipHeight: 100, ageRecipient: "fixture",
      limits: { maxSuccessFeeSat: 10n, maxFundingFeeSat: 10n, maxClaimFeeSat: 10n, maxRefundFeeSat: 10n, maxRefundDelayBlocks: 100 } },
    hooks: { report: () => {}, fundingSource: async () => ({ psbt: "fixture-psbt" }), broadcast: async () => { broadcasts++; },
      cosigner: { loadMusig: async () => { throw new Error("No signer in disconnected fixture"); }, reserve: async () => { throw new Error("No signer in disconnected fixture"); } } },
    recoveryStore: { load: async () => row, begin: async (record) => { if (row) return false; row = record; return true; }, update: async (record) => { row = record; } },
    savePayerRecovery: async (_file, stage) => "wallet-recovery:" + stage, now: () => now,
  };
  return { options, row: () => row, broadcasts: () => broadcasts, expire: () => { now = 4000; } };
}
const funding: FundingRequest = { contractScript: "fixture", amountSat: 1000n, maxFundingFeeSat: 10n, refundLockHeight: 200, successFeeSat: 10n };
const outcome: SwapOutcome = { sessionId: "5".repeat(64), contractHash: "6".repeat(64), fundingTxid: "7".repeat(64), preimage: "private payer preimage",
  refundLockHeight: 200, cooperation: "abandoned", claimTxid: null, paidRecovery: new Uint8Array([9]) };
const runner = async (_request: unknown, hooks: SwapHooks): Promise<SwapOutcome> => {
  await hooks.saveRecovery(new Uint8Array([1]), "terms"); await hooks.fundingSource(funding);
  await hooks.saveRecovery(new Uint8Array([2]), "funded"); await hooks.beforeFundingCommit?.(outcome.fundingTxid, 4000);
  await hooks.broadcast("fixture-raw", outcome.fundingTxid); return outcome;
};

test("merchant swap preserves payer recovery and only returns public pending receipt hints", async () => {
  const f = fixture(); const progress = await executeMerchantSwap(f.options, runner);
  expect(progress.state).toBe("awaiting_merchant_receipt"); expect(JSON.stringify(progress)).not.toContain("preimage"); expect(JSON.stringify(progress)).not.toContain("private");
  expect(f.row()?.route?.recoveryRef).toBe("wallet-recovery:provider_complete"); expect(f.row()?.route?.fundingTxid).toBe(outcome.fundingTxid); expect(f.row()?.stage).toBe("observing");
  await expect(executeMerchantSwap(f.options, runner)).rejects.toThrow("already dispatched"); expect(f.broadcasts()).toBe(1);
});
test("unapproved provider, short invoice and aggregate buyer fee caps fail before dispatch", async () => {
  for (const change of [
    (f: ReturnType<typeof fixture>): MerchantSwapOptions => ({ ...f.options, policy: { ...f.options.policy, approvedRillProviders: [] } }),
    (f: ReturnType<typeof fixture>): MerchantSwapOptions => ({ ...f.options, now: () => 3000 }),
    (f: ReturnType<typeof fixture>): MerchantSwapOptions => ({ ...f.options, policy: { ...f.options.policy, maxBuyerExtraMsat: "39000" } }),
  ]) { const f = fixture(); await expect(executeMerchantSwap(change(f), runner)).rejects.toThrow(); expect(f.row()).toBeNull(); }
});
test("wallet delay cannot broadcast expired merchant terms", async () => {
  const f = fixture(); const options = { ...f.options, hooks: { ...f.options.hooks, fundingSource: async () => { f.expire(); return { psbt: "fixture-psbt" }; } } };
  await expect(executeMerchantSwap(options, runner)).rejects.toThrow("expired"); expect(f.broadcasts()).toBe(0); expect(f.row()?.stage).toBe("ambiguous");
});
test("source funding requires durable payer recovery", async () => {
  const f = fixture(); await expect(executeMerchantSwap(f.options, async (_request, hooks) => { await hooks.fundingSource(funding); return outcome; })).rejects.toThrow("recovery"); expect(f.broadcasts()).toBe(0);
});
test("quote and invoice deadlines are checked at their exact boundary", () => {
  expect(() => assertFundingWindow(2000, 3000, 1999)).not.toThrow();
  expect(() => assertFundingWindow(2000, 3000, 2000)).toThrow("deadline");
  expect(() => assertFundingWindow(3000, 2000, 2000)).toThrow("deadline");
  expect(() => assertFundingWindow(NaN, 3000, 1000)).toThrow("deadline");
  expect(() => assertFundingWindow(3000, 4000, 2000, 2000)).toThrow("deadline");
});
