// Run in its own process: mocked protocol verification must not affect other unit tests.
import { mock } from "bun:test";
import { receiver, testInvoice } from "../../../rill-payments/tests/helpers";
import type { CheckoutCheckpoint } from "@rillswap/payments/sdk";
import type { MerchantSwapOptions } from "../../src/swap/merchantCheckout";
import type { SwapRequest } from "../../src/swap/swap";

const scenario = process.argv[2]; let now = 1200, shared = 0, broadcasts = 0;
const recoveryStages: string[] = []; let checkpoint: CheckoutCheckpoint | null = null;
const messages: string[] = [];
const sessionSecrets: Uint8Array[] = [];
let recoveryBirthday = -1;
const recoveryExtensions: unknown[] = [];
const settleBudgets: number[] = [];
const terms = { terms_expiry: 5000, refund_lock_height: 200, max_funding_fee_sat: "10", funding_confirmations: 2,
  economics: { contract_amount_sat: "1040", success_fee_sat: "10" } };
class FixtureSession {
  sessionId = "5".repeat(64); key = receiver.slice(2); providerKey = "8".repeat(64);
  secret = new Uint8Array(32); constructor() { this.secret[31] = 1; sessionSecrets.push(this.secret); }
  envelope(kind: string, payload: unknown) { return { kind, payload, message_id: kind }; }
  async listen() {}
  async send(message: { kind: string }) { messages.push(message.kind); if (message.kind === "funding_binding") { shared++;
    if (scenario === "transport_after_share") throw new Error("response lost after provider received signed transaction"); } }
  async replyTo(message: { kind: string }, kind: string) {
    if (message.kind === "funding_binding" && scenario === "ack_delay") now = 3000;
    if (kind === "terms_offer") return { payload: { terms: { contract_hash: "6".repeat(64) } }, contract_hash: "6".repeat(64) };
    return { payload: { provider_identity_signature: "0".repeat(128) }, sender_session_key: this.providerKey };
  }
}
mock.module("../../src/swap/session", () => ({ Session: FixtureSession, SwapError: Error }));
mock.module("../../src/swap/discovery", () => ({ discoverProvider: async () => ({ advertisedEpochInboxKeys: ["8".repeat(64)], revision: 1 }) }));
mock.module("../../src/swap/wire", () => ({ checkHandshakeAccept: () => ({}), checkTermsOffer: () => terms, requireAnnouncedDepth: () => {}, requireShape: (_name: string, value: unknown) => value,
  COOPERATIVE_CLAIM_FEATURE: "fixture", EPOCH_SESSION_EXTENSION: "fixture", EPOCH_SESSION_FEATURE: "fixture" }));
mock.module("../../src/swap/hashes", () => ({ clientAcceptanceHash: () => new Uint8Array(32), fundingBindingHash: () => new Uint8Array(32),
  epochBoundSessionId: () => new Uint8Array(32), handshakeHash: () => new Uint8Array(32) }));
mock.module("../../src/swap/funding", () => ({ authorizeFundingPsbt: () => ({ txid: "7".repeat(64), raw: "fixture transaction" }), authorizeFunding: () => { if (scenario === "prepare_deposit_refused") throw new Error("funding fee exceeds the signed maximum"); return { txid: "7".repeat(64), raw: "fixture transaction" }; },
  fundingBinding: () => ({ funding_attempt_id: "9".repeat(64) }) }));
mock.module("../../src/swap/taproot", () => ({ reconstructTaprootContract: () => ({ script_pubkey: "5120" + "1".repeat(64) }) }));
mock.module("../../src/swap/recovery", () => ({ encryptRecovery: async (record: { birthday: number; extensions?: unknown }) => {
  recoveryExtensions.push(structuredClone(record.extensions));
  recoveryBirthday = record.birthday; return new Uint8Array([1]);
} }));
mock.module("../../src/swap/cooperative", () => ({ COOPERATIVE_RESERVATION_EXTENSION: "fixture", settle: async (context: { settleMs: number }) => (settleBudgets.push(context.settleMs), {
  cooperation: "abandoned", claimTxid: null, preimage: "private fixture preimage",
  reservation: scenario === "prepare_wallet_reserved" ? { recordedAt: now, proposal: "fixture proposal", signature_hash: "fixture hash" } : null }) }));
const { executeMerchantSwap } = await import("../../src/swap/merchantCheckout");
const { invoiceBinding } = await import("../../src/swap/bolt11");
const invoice = testInvoice("actual_runner_sequence", "1000000", 1000, 6000); const binding = invoiceBinding(invoice, "regtest");
const options: MerchantSwapOptions = {
  invoice, terms: { version: "checkout/0.1", policyVersion: "native-lightning/1", merchantOrigin: "https://merchant.example",
    intentId: "merchant_intent_001", attemptId: "merchant_attempt_01", network: "regtest", amountMsat: "1000000", buyerExtraMsat: "0",
    receiver, paymentHash: binding.payment_hash, expiresAt: 3000 },
  policy: { version: "native-lightning/1", merchantOrigin: "https://merchant.example", receiver, network: "regtest", maxBuyerExtraMsat: "100000", maxBuyerExtraBps: 1000, approvedRillProviders: ["4".repeat(64)] },
  relay: { publish: async () => false, subscribe: async () => {}, next: async () => null, query: async () => ({ events: [], truncated: false }) },
  request: { identity: "4".repeat(64), network: { name: "regtest" }, refundScript: "fixture", tipHeight: 100, ageRecipient: "fixture",
    limits: { maxSuccessFeeSat: 10n, maxFundingFeeSat: 10n, maxClaimFeeSat: 10n, maxRefundFeeSat: 10n, maxRefundDelayBlocks: 100 } },
  hooks: { report: () => {}, fundingSource: async () => { if (scenario === "wallet_delay") now = 3000;
    return scenario?.startsWith("prepare_deposit") ? { deposit: { transaction: { txid: "7".repeat(64) }, inputValues: [] } as never } : { psbt: "fixture" }; },
    broadcast: async () => { broadcasts++; }, cosigner: { loadMusig: async () => { throw new Error(); }, reserve: async () => { throw new Error(); } } },
  recoveryStore: { load: async () => checkpoint, begin: async (record) => { if (checkpoint) return false; checkpoint = record; return true; },
    update: async (record) => { checkpoint = record; if (scenario === "checkpoint_delay" && record.route?.fundingTxid) now = 3000; } },
  savePayerRecovery: async (_file, stage) => { recoveryStages.push(stage); if (scenario === "funded_recovery_delay" && stage === "funded") now = 3000; return "wallet:" + stage; },
  now: () => now,
};
if (scenario?.startsWith("prepare_")) {
  const { prepareSwap } = await import("../../src/swap/swap");
  const request: SwapRequest = { ...options.request, invoice, checkoutExpiresAt: 3000,
    ...(scenario?.startsWith("prepare_wallet") ? { refundAllocation: { version: 1, scheme: "bip84-rillswap-v1",
      identityFingerprint: "a".repeat(64), network: "regtest", index: 7, path: "m/84'/1'/2'/0/7", script: "fixture", address: "fixture" } } : {}) };
  const prepared = await prepareSwap(options.relay, request, () => {}, { clock: () => now * 1000 });
  const before = { accepted: messages.includes("terms_accept"), shared, recovery: recoveryStages.length };
  const hooks = { ...options.hooks, saveRecovery: async (_file: Uint8Array, stage: "terms" | "funded") => {
    recoveryStages.push(stage);
    if (scenario === "prepare_callback_error") throw new Error("backup failed");
  } };
  let refused = false, refusal = "", activeSignerPreserved = true;
  if (scenario === "prepare_only") prepared.dispose();
  else if (scenario === "prepare_disposed") {
    prepared.dispose(); prepared.dispose();
    try { await prepared.execute(hooks); } catch { refused = true; }
  } else if (scenario === "prepare_expired") {
    now = 3000;
    try { await prepared.execute(hooks); } catch { refused = true; }
  } else if (scenario === "prepare_concurrent") {
    const first = prepared.execute(hooks);
    prepared.dispose();
    activeSignerPreserved = sessionSecrets.at(-1)!.some((byte) => byte !== 0);
    try { await prepared.execute(hooks); } catch { refused = true; }
    await first;
  } else if (scenario === "prepare_mutation") {
    (request as { tipHeight: number }).tipHeight = 900;
    await prepared.execute(hooks);
  } else if (scenario?.startsWith("prepare_wallet")) {
    (request.refundAllocation as { index: number }).index = 999;
    await prepared.execute(hooks);
  } else {
    try { await prepared.execute(hooks); } catch (error) { refused = true; refusal = (error as Error).message; }
  }
  console.log(JSON.stringify({ before, refused, refusal, activeSignerPreserved, recoveryBirthday, recoveryExtensions,
    quoteFrozen: Object.isFrozen(prepared.quote), secretsWiped: sessionSecrets.every((secret) => secret.every((byte) => byte === 0)),
    accepted: messages.includes("terms_accept"), shared, recoveryStages, broadcasts, settleBudgets }));
} else {
let failed = false; try { await executeMerchantSwap(options); } catch { failed = true; }
now = 1200; let redispatchRefused = false;
try { await executeMerchantSwap(options); } catch (error) { redispatchRefused = (error as Error).message.includes("already dispatched"); }
console.log(JSON.stringify({ failed, shared, broadcasts, recoveryStages, checkpoint, redispatchRefused }));
}
