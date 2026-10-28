// Process isolation keeps mocked nonfinancial preparation out of protocol tests.
import { mock } from "bun:test";
import type { LocatedProvider } from "../../src/swap/marketplace";
import type { PreparedSwap } from "../../src/swap/swap";

const opened: string[] = [];
const closed = new Set<string>();
const disposed = new Set<string>();
let rejectSlow: ((error: Error) => void) | undefined;
let readySlow: (() => void) | undefined;
const slowStarted = new Promise<void>((resolve) => { readySlow = resolve; });
class FakeRelay {
  constructor(readonly url: string) {}
  static async open(url: string, _timeout: number, _factory: unknown, signal: AbortSignal) {
    opened.push(url);
    const relay = new FakeRelay(url);
    signal.addEventListener("abort", () => relay.close(), { once: true });
    return relay;
  }
  close() { closed.add(this.url); if (this.url === "wss://slow/") rejectSlow?.(new Error("closed")); }
}
mock.module("../../src/swap/relay", () => ({ RelayConnection: FakeRelay }));
mock.module("../../src/swap/swap", () => ({ prepareSwap: async (relay: FakeRelay): Promise<PreparedSwap> => {
  if (relay.url === "wss://slow/") return new Promise((_resolve, reject) => { rejectSlow = reject; readySlow?.(); });
  return { quote: { providerIdentity: relay.url, providerSlot: "default", contractAmountSat: 1010n,
    successFeeSat: 10n, contractHash: "0".repeat(64), refundLockHeight: 100, expiresAt: 9999, fundingConfirmations: 1 },
    dispose: () => { disposed.add(relay.url); }, execute: async () => { throw new Error("not used"); } };
} }));
const { quoteProviders } = await import("../../src/swap/marketplace");
const provider = (identity: string, relays: string[]): LocatedProvider => ({
  announcement: { identityXOnlyKey: identity } as LocatedProvider["announcement"], rawAnnouncement: "fixture", relayUrls: relays,
});
const cancellation = new AbortController();
const operation = quoteProviders([provider("fast", ["wss://fast/"]), provider("slow", ["wss://slow/", "wss://must-not-open/"])], {
  network: { name: "regtest" }, invoice: "fixture", refundScript: "fixture", tipHeight: 10, ageRecipient: "fixture",
  limits: { maxSuccessFeeSat: 10n, maxFundingFeeSat: 10n, maxClaimFeeSat: 10n, maxRefundFeeSat: 10n, maxRefundDelayBlocks: 100 },
}, cancellation.signal);
await slowStarted;
// Let the already-resolved fast preparation register its ready handle.
await Promise.resolve();
cancellation.abort();
const result = await operation;
console.log(JSON.stringify({ opened, closed: [...closed].sort(), disposed: [...disposed], returned: result.quotes.length }));
