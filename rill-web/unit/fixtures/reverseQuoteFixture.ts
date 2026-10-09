/** Subprocess: mocked transport for prepareReverseQuote. Prints what was sent and disposed. */
import { mock } from "bun:test";
import vectors from "../../../rill-docs/vectors/wire/quote-v1.json";

const sent: { type: string; payload: unknown }[] = [];
const secrets: Uint8Array[] = [];
const offer = structuredClone((vectors as unknown as { valid: Record<string, unknown[]> }).valid.reverseQuoteOffer![0]) as Record<string, unknown>;
offer.expires_at = 2_000_000_000;
const economics = offer.economics as Record<string, string>;

class FakeSession {
  readonly secret = new Uint8Array(32).fill(7);
  providerKey = "9".repeat(64);
  constructor() { secrets.push(this.secret); }
  envelope(type: string, payload: unknown) { sent.push({ type, payload: structuredClone(payload) }); return { type }; }
  async send() {}
  async replyTo(_request: unknown, expected: string) { return { type: expected, payload: structuredClone(offer), contract_hash: null }; }
}
mock.module("../../src/swap/session", () => ({ Session: FakeSession, SwapError: Error }));
mock.module("../../src/swap/handshake", () => ({ handshake: async () => ({ transcript: "ab".repeat(32) }) }));
mock.module("../../src/nostrProviderAnnouncement", () => ({ verifyNostrProviderAnnouncement: () => ({ slot: "s" }) }));

const { prepareReverseQuote } = await import("../../src/swap/reverseSwap");
const limits = { maxSuccessFeeSat: 10_000n, minClaimFeeReserveSat: 1n, maxClaimFeeSat: 100_000n, minRefundDelayBlocks: 1, maxIncomingHtlcDelayBlocks: 1000 };
const request = { identity: "1".repeat(64), network: { name: "regtest" }, payoutSat: BigInt(economics.nominal_payout_sat!), limits };
const prepared = await prepareReverseQuote({} as never, request as never, { announcement: "{}" });
const beforeDispose = secrets.map((secret) => secret.some((byte) => byte !== 0));
prepared.dispose();
let refused = "";
try { await prepareReverseQuote({} as never, { ...request, payoutSat: 1n } as never, { announcement: "{}" }); }
catch (error) { refused = (error as Error).message; }
console.log(JSON.stringify({
  sent, hold: prepared.quote.holdInvoiceSat.toString(), keys: Object.keys(prepared.quote).sort(),
  beforeDispose, afterDispose: secrets.map((secret) => secret.some((byte) => byte !== 0)), refused,
}));
