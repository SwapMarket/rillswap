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
export const quoteProviders = async (_providers: unknown[], request: unknown) => {
  window.uiFixture.requests.push(structuredClone(request));
  return { failures: 0, quotes: ["4", "5"].map((id) => ({ relayUrl: "ws://127.0.0.1:7777/",
    dispose: () => { window.uiFixture.disposed++; },
    prepared: {
      quote: { providerIdentity: id.repeat(64), contractAmountSat: BigInt(1100 + Number(id)), successFeeSat: 100n,
        refundLockHeight: 300, expiresAt: Math.floor(Date.now() / 1000) + 3600 },
      execute: async () => { window.uiFixture.executed++; window.uiFixture.executedProviders.push(id.repeat(64)); throw new Error("Fixture stopped before funding"); },
      dispose: () => { window.uiFixture.disposed++; },
    },
  })) };
};
