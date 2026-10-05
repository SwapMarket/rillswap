// Run in isolation so protocol mocks cannot affect other swap tests.
import { expect, mock } from "bun:test";
import { join } from "node:path";
import { readFileSync, statSync, writeFileSync } from "node:fs";
import { receiver } from "../../../rill-payments/tests/helpers";
import type { MerchantSwapOptions } from "../../src/swap/merchantCheckout";
import type { CheckoutCheckpoint } from "@rillswap/payments/sdk";
import { parseTerms } from "@rillswap/payments";

const [scenario, out] = process.argv.slice(2);
if (!out) throw new Error("Fixture output required");
const terms = { version: "checkout/0.1", policyVersion: "native-lightning/1", buyerExtraMsat: "0", merchantOrigin: "https://merchant.invalid",
  intentId: "fixture_intent_0001", attemptId: "fixture_attempt_0001", paymentHash: "1".repeat(64),
  amountMsat: "50000000", receiver, network: "regtest", expiresAt: 5000 };
writeFileSync(join(out, "network.json"), JSON.stringify({ name: "regtest" }));
writeFileSync(join(out, "cookie"), "user:PRIVATE_COOKIE_CANARY");
writeFileSync(join(out, "checkout.json"), JSON.stringify({ id: terms.intentId, status: "waiting", attempt: { terms, invoice: "fixture-invoice" } }));
mock.module("../../src/swap/address", () => ({ addressScript: () => "fixture-script", scriptAddress: () => "fixture-address" }));
mock.module("../../src/swap/relay", () => ({ RelayConnection: { open: async () => ({ close: () => writeFileSync(join(out, "closed"), "yes") }) } }));
mock.module("../../src/swap/swap", () => ({ runSwap: async () => { throw new Error("Wrong driver branch"); } }));
mock.module("../../scripts/memoryCosigner", () => ({ memoryCosigner: () => ({}) }));
mock.module("../../src/swap/merchantCheckout", () => ({ executeMerchantSwap: async (options: MerchantSwapOptions) => {
  options.hooks.report("SECRET_CANARY");
  if (scenario?.startsWith("failure")) throw new Error("SECRET_CANARY");
  expect(options.policy.approvedRillProviders).toEqual(["a".repeat(64)]);
  expect(options.policy.maxBuyerExtraMsat).toBe("17000000");
  expect(options.policy.maxBuyerExtraBps).toBe(3400);
  const record: CheckoutCheckpoint = { version: "checkout-checkpoint/1", intentId: terms.intentId,
    attemptId: terms.attemptId, terms: parseTerms(options.terms), invoice: "fixture-invoice", stage: "dispatched" };
  expect(await options.recoveryStore.begin(record)).toBe(true);
  expect(await options.recoveryStore.begin(record)).toBe(false);
  expect(await options.recoveryStore.load(terms.attemptId)).toEqual(record);
  await expect(options.recoveryStore.update({ ...record, intentId: "foreign_intent_001" })).rejects.toThrow("identity changed");
  await options.recoveryStore.update({ ...record, stage: "observing" });
  expect(JSON.parse(readFileSync(join(out!, "merchant-checkpoint.json"), "utf8")).stage).toBe("observing");
  expect(statSync(join(out!, "merchant-checkpoint.json")).mode & 0o777).toBe(0o600);
  for (const stage of ["terms", "funded", "provider_complete"] as const) {
    expect(await options.savePayerRecovery(new Uint8Array([1, 2, 3]), stage)).toBe(`web-recovery-${stage === "provider_complete" ? "paid" : stage}.age`);
  }
  await expect(options.savePayerRecovery(new Uint8Array([9]), "funded")).rejects.toThrow();
  return { state: "awaiting_merchant_receipt", swapId: "a".repeat(64), fundingTxid: "b".repeat(64), recoveryRef: "web-recovery-paid.age" };
} }));
globalThis.fetch = (async (_url: unknown, init: RequestInit) => {
  const { method } = JSON.parse(init.body as string);
  return Response.json({ result: method === "getblockcount" ? 100 : "fixture-address", error: null });
}) as typeof fetch;
process.argv = [process.execPath, "web-swap-e2e.ts", "--network", join(out, "network.json"),
  "--core-cookie", join(out, "cookie"), "--core-port", "1", "--wallet", "fixture", "--relay", "ws://127.0.0.1:1",
  "--provider", "a".repeat(64), "--invoice", "fixture-invoice", "--recipient", "fixture", "--out", out,
  "--merchant-checkout", join(out, "checkout.json")];
if (scenario === "failure_equals") process.argv.splice(-2, 2, `--merchant-checkout=${join(out, "checkout.json")}`);
await import("../../scripts/web-swap-e2e");
