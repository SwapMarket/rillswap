/** Test-only quote orchestration. Real wallet, invoice validation, and tip client remain in use. */
import { BrowserRecoveryWallet } from "../../src/browserRecoveryWallet";
declare global {
  interface Window {
    uiFixture: { requests: unknown[]; executed: number; executedProviders: string[]; disposed: number;
      fundingScript?: string; fundingSource?: { psbt: string } | { depositTxid: string };
      reverseEvents?: string[]; reverseFunded?: boolean;
      wallet: typeof BrowserRecoveryWallet; releaseInfo?: () => void; infoPending: boolean };
  }
}
window.uiFixture = { requests: [], executed: 0, executedProviders: [], disposed: 0, wallet: BrowserRecoveryWallet, infoPending: false };
export const MAX_QUOTE_PROVIDERS = 8;
export const discoverMarketplace = async () => ({ providers: [{}], warnings: [] });
export const eligibleProviders = (providers: unknown[]) => providers;
export const ineligibilityReason = () => "fixture ineligible";
export const discoverDirectory = async () => ({ warnings: [], entries: [{ identity: "4".repeat(64), slot: "fixture", profiles: ["btc-to-ln/v1", "ln-to-btc/v1"],
  amountBands: [{ minimum_sat: "1000", maximum_sat: "100000000" }], indicativeFeePolicy: { base_sat: "2000", proportional_millionths: 0 },
  relayUrls: ["ws://127.0.0.1:7777/"], expiresAt: Math.floor(Date.now() / 1000) + 3600 }] });
export const indicativeFee = (policy: { base_sat: string; proportional_millionths: number }, amount: bigint) =>
  BigInt(policy.base_sat) + (amount * BigInt(policy.proportional_millionths) + 999_999n) / 1_000_000n;
export const providerLimits = (providers: unknown[]) => providers;
type FixtureEntry = { identity: string; profiles: string[]; amountBands: { minimum_sat: string; maximum_sat: string }[];
  indicativeFeePolicy: { base_sat: string; proportional_millionths: number } };
export const estimateFromDirectory = (entries: FixtureEntry[], profile: string, amount: bigint, pinned = "") => {
  const serving = entries.filter((entry) => entry.profiles.includes(profile) && (!pinned || entry.identity === pinned));
  const eligible = serving.filter((entry) => entry.amountBands.some((band) => amount >= BigInt(band.minimum_sat) && amount <= BigInt(band.maximum_sat)));
  if (eligible.length === 0) return { reason: serving.length === 0 ? "No provider announced this swap direction." : "fixture ineligible" };
  return { identity: eligible[0]!.identity, feeSat: indicativeFee(eligible[0]!.indicativeFeePolicy, amount) };
};
export const quoteProviders = async (_providers: unknown[], request: unknown) => {
  window.uiFixture.requests.push(structuredClone(request));
  return { failures: 0, reasons: [], quotes: ["4", "5"].map((id) => ({ relayUrl: "ws://127.0.0.1:7777/",
    dispose: () => { window.uiFixture.disposed++; },
    prepared: {
      quote: { providerIdentity: id.repeat(64), contractAmountSat: BigInt(1100 + Number(id)), successFeeSat: 100n,
        refundLockHeight: 300, expiresAt: Math.floor(Date.now() / 1000) + 3600 },
      execute: async (hooks: { saveRecovery: (file: Uint8Array, stage: string) => Promise<void>; fundingSource: (request: unknown) => Promise<unknown> }) => {
        window.uiFixture.executed++; window.uiFixture.executedProviders.push(id.repeat(64));
        await hooks.saveRecovery(new Uint8Array([7, 7, 7]), "terms");
        if (window.uiFixture.fundingScript) {
          // Exercise the funding prompt with the test's contract script; record what it resolved with.
          const source = await hooks.fundingSource({ contractScript: window.uiFixture.fundingScript, amountSat: 101_000n, maxFundingFeeSat: 500n,
            refundLockHeight: 300, successFeeSat: 100n, termsExpiry: Math.floor(Date.now() / 1000) + 3600 }) as { psbt?: string; deposit?: { transaction: { txid: string } } };
          window.uiFixture.fundingSource = source.psbt !== undefined ? { psbt: source.psbt } : { depositTxid: source.deposit!.transaction.txid };
          throw new Error("Fixture stopped after funding");
        }
        throw new Error("Fixture stopped before funding");
      },
      dispose: () => { window.uiFixture.disposed++; },
    },
  })) };
};
export const quoteReverseProviders = async (_providers: unknown[], request: unknown) => {
  window.uiFixture.requests.push(structuredClone(request));
  return { failures: 0, reasons: [], quotes: ["6", "7"].map((id) => ({ relayUrl: "ws://127.0.0.1:7777/",
    dispose: () => { window.uiFixture.disposed++; },
    prepared: {
      quote: { providerIdentity: id.repeat(64), payoutSat: 50_000n, holdInvoiceSat: BigInt(51_000 + Number(id)), successFeeSat: 500n,
        claimFeeReserveSat: 500n, fundingConfirmations: 2, refundDelayBlocks: 144, incomingHtlcExpiryDeltaBlocks: 288, expiresAt: Math.floor(Date.now() / 1000) + 3600 },
      // A stand-in execution: enough for the execution UI to accept, show the invoice, and receive fixture funding.
      prepareExecution: async () => {
        window.uiFixture.reverseEvents = [];
        const events = window.uiFixture.reverseEvents, record = { stage: "terms-ready" };
        const expiresAt = Math.floor(Date.now() / 1000) + 1800;
        return {
          terms: { economics: { hold_invoice_sat: String(51_000 + Number(id)), nominal_payout_sat: "50000", success_fee_sat: "500", claim_fee_reserve_sat: "500" },
            funding_confirmations: 2, refund_lock_height: 400, max_claim_fee_sat: "800", client_destination_script: "0014" + "11".repeat(20),
            invoice_binding: { expires_at: expiresAt } },
          recoveryFile: new Uint8Array([8, 8, 8]), record,
          accept: async () => { events.push("accept"); },
          exposeInvoice: async () => { events.push("expose"); record.stage = "payment-unknown"; return { bolt11: "lnbcrt510010n1fixture", expiresAt }; },
          planPayment: async () => { events.push("plan"); throw new Error("fixture has no node"); },
          receiveFunding: async () => {
            events.push("receive");
            if (!window.uiFixture.reverseFunded) { await new Promise((resolve) => setTimeout(resolve, 200)); throw new Error("no funding yet"); }
            record.stage = "funded"; return new Uint8Array([9, 9, 9]);
          },
          dispose: () => { events.push("dispose"); },
        };
      },
      dispose: () => { window.uiFixture.disposed++; },
    },
  })) };
};
