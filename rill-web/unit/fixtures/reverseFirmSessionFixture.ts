/** Transport seam only: actual execution cryptography is covered separately. */
import { mock } from "bun:test";
import vectors from "../../../rill-docs/vectors/wire/quote-v1.json";
const offer = structuredClone((vectors as unknown as { valid: Record<string, unknown[]> }).valid.reverseQuoteOffer![0]) as Record<string, unknown>;
offer.expires_at = 2000000000;
const economics = offer.economics as Record<string, string>, sessions: FakeSession[] = [], events: string[] = [];
class FakeSession {
  readonly secret = new Uint8Array(32).fill(7);
  readonly sessionId = String(sessions.length).padStart(64, "0");
  readonly providerKey = String(sessions.length + 1).padStart(64, "0");
  constructor() { sessions.push(this); events.push("new-session"); }
  envelope(type: string, _payload: unknown) { events.push(type); return { type }; }
  async send() {}
  async replyTo() { return { payload: offer }; }
}
mock.module("../../src/swap/session", () => ({ Session: FakeSession, SwapError: Error }));
mock.module("../../src/swap/handshake", () => ({ handshake: async (session: FakeSession, provider: unknown, identity: string) => { events.push("handshake:" + session.sessionId); return { provider, identity, sessionId: session.sessionId }; } }));
mock.module("../../src/nostrProviderAnnouncement", () => ({ verifyNostrProviderAnnouncement: () => ({ slot: "s" }) }));
mock.module("../../src/swap/reverseExecution", () => ({ prepareReverseExecution: async (session: FakeSession, agreed: { sessionId: string; identity: string }, request: { payoutSat: bigint }) => {
  events.push("persist-firm-secrets"); events.push("firm-request"); return { sessionId: session.sessionId, handshakeSession: agreed.sessionId, identity: agreed.identity, payout: request.payoutSat.toString() }; } }));
const { prepareReverseQuote } = await import("../../src/swap/reverseSwap");
const original = { identity: "1".repeat(64), network: { name: "regtest" }, payoutSat: BigInt(economics.nominal_payout_sat!),
  limits: { maxSuccessFeeSat: 10000n, minClaimFeeReserveSat: 1n, maxClaimFeeSat: 100000n, minRefundDelayBlocks: 1, maxIncomingHtlcDelayBlocks: 1000 } };
const expected = original.payoutSat.toString(), prepared = await prepareReverseQuote({} as never, original as never, { announcement: "{}" }); original.payoutSat = 1n;
const result = await prepared.prepareExecution({ assertCurrent: () => {} } as never);
let refused = false; try { await prepared.prepareExecution({ assertCurrent: () => {} } as never); } catch { refused = true; }
const oldZero = sessions[0]!.secret.every((v) => v === 0); prepared.dispose();
console.log(JSON.stringify({ result, expected, refused, oldZero, allZero: sessions.every((s) => s.secret.every((v) => v === 0)), events }));
