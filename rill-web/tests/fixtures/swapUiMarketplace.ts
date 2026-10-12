/** Test-only quote orchestration. Real wallet, invoice validation, and tip client remain in use. */
import { BrowserRecoveryWallet } from "../../src/browserRecoveryWallet";
declare global {
  interface Window {
    uiFixture: { requests: unknown[]; executed: number; executedProviders: string[]; disposed: number;
      wallet: typeof BrowserRecoveryWallet; releaseInfo?: () => void; infoPending: boolean };
  }
}
window.uiFixture = { requests: [], executed: 0, executedProviders: [], disposed: 0, wallet: BrowserRecoveryWallet, infoPending: false };
export const MAX_QUOTE_PROVIDERS = 8;
export const discoverMarketplace = async () => ({ providers: [{}], warnings: [] });
export const eligibleProviders = (providers: unknown[]) => providers;
export const ineligibilityReason = () => "fixture ineligible";
export const discoverDirectory = async () => ({ entries: [], warnings: [] });
export const indicativeFee = (policy: { base_sat: string; proportional_millionths: number }, amount: bigint) =>
  BigInt(policy.base_sat) + (amount * BigInt(policy.proportional_millionths) + 999_999n) / 1_000_000n;
export const quoteProviders = async (_providers: unknown[], request: unknown) => {
  window.uiFixture.requests.push(structuredClone(request));
  return { failures: 0, reasons: [], quotes: ["4", "5"].map((id) => ({ relayUrl: "ws://127.0.0.1:7777/",
    dispose: () => { window.uiFixture.disposed++; },
    prepared: {
      quote: { providerIdentity: id.repeat(64), contractAmountSat: BigInt(1100 + Number(id)), successFeeSat: 100n,
        refundLockHeight: 300, expiresAt: Math.floor(Date.now() / 1000) + 3600 },
      execute: async (hooks: { saveRecovery: (file: Uint8Array, stage: string) => Promise<void> }) => {
        window.uiFixture.executed++; window.uiFixture.executedProviders.push(id.repeat(64));
        await hooks.saveRecovery(new Uint8Array([7, 7, 7]), "terms");
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
      dispose: () => { window.uiFixture.disposed++; },
    },
  })) };
};
