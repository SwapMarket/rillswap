/** Isolated module mocks so lifecycle failure injection never changes another unit test's transport. */
import { mock } from "bun:test";
import { generateIdentity, identityToRecipient } from "age-encryption";
import { ASSET, CLIENT, NOW, TERMS, SECRET, signedReverse, testHoldInvoice } from "./lnErc20Cases";
import { invoiceBinding } from "../../src/swap/bolt11";
import fixture from "./initial-btc-to-ln-v1.json";
const events: string[] = [], mode = process.argv[2] ?? "";
let monotonic = 0, submitted = false;
Object.defineProperty(performance, "now", { value: () => monotonic });
let request: Record<string, unknown>;
class FakeSession {
  secret = Uint8Array.from(SECRET); key = TERMS.provider_identity_key; providerKey = TERMS.provider_identity_key; sessionId = "11".repeat(32);
  envelope(type: string, payload: Record<string, unknown>) { return { message_type: type, payload, message_id: "22".repeat(32) }; }
  async send(envelope: { message_type: string; payload: Record<string, unknown> }) {
    events.push(`send:${envelope.message_type}:${envelope.payload.mode ?? ""}`); if (envelope.payload.mode === "firm") request = envelope.payload;
  }
  async replyTo(_env: unknown, type: string) {
    if (type === "quote_offer") return { payload: { kind: "ln-to-erc20", indicative: true, economics: TERMS.economics, evm_asset: ASSET,
      funding_confirmations: 2, settlement_confirmations: 2, evm_reference_block: 1000, timelock_delay_blocks: 1800,
      incoming_htlc_expiry_delta_blocks: 200, expires_at: NOW + 600, extensions: {} } };
    if (type === "terms_offer") {
      const invoice = testHoldInvoice(request.payment_hash as string);
      const offer = signedReverse({ ...TERMS, invoice_binding: invoiceBinding(invoice, "regtest"),
        client_evm_address: request.client_evm_address as string, recovery_authorization_xonly_key: request.recovery_authorization_xonly_key as string }, invoice);
      return { payload: offer, contract_hash: offer.terms.contract_hash, message_id: "33".repeat(32) };
    }
    return {};
  }
}
mock.module("../../src/swap/session", () => ({ Session: FakeSession, SwapError: class extends Error {} }));
mock.module("../../src/nostrProviderAnnouncement", () => ({ verifyNostrProviderAnnouncement: () => ({ slot: "test", evmAssets: [ASSET] }) }));
mock.module("../../src/swap/handshake", () => ({
  handshake: async () => ({ transcript: "77".repeat(32), init: fixture.verification_context.handshake_init,
    accept: fixture.verification_context.handshake_accept, acceptSignature: "44".repeat(64) }),
  newKeyPair: () => ({ secret: Uint8Array.from(SECRET), xonly: TERMS.provider_identity_key }),
}));
const { prepareLnErc20Quote } = await import("../../src/swap/lnErc20Swap");
const { lockOf } = await import("../../src/swap/erc20Swap");
const quote = await prepareLnErc20Quote({} as never, { identity: TERMS.provider_identity_key, network: fixture.network_identity, asset: ASSET,
  payoutTokenBase: 51_000_000n, limits: { maxSuccessFeeSat: 200n, minTimelockDelayBlocks: 600, maxIncomingHtlcDelayBlocks: 200 } },
{ announcement: "", clock: () => NOW * 1000 });
let error = "";
try {
  const execution = await quote.prepareExecution({ clientEvmAddress: CLIENT, evmTip: 1000, btcTip: 100,
    ageRecipient: await identityToRecipient(await generateIdentity()), saveSecrets: async () => {
      events.push("secrets:commit"); if (mode === "secrets") throw new Error("secret commit aborted");
    } });
  const rpc = { chainId: async () => ASSET.chain_id, verifyHtlc: async () => {}, blockNumber: async () => 1500,
    findLockups: async () => [{ lock: lockOf(execution.terms), txHash: "55".repeat(32), blockNumber: 1200, logIndex: 0 }],
    lockActive: async () => !(mode === "sponsored-rejected" && submitted), nativeBalance: async () => 1_000_000n, gasPrice: async () => 1n,
    receipt: async () => ({ blockNumber: 1200, status: true }) };
  await execution.execute({ rpc: rpc as never, report: () => {}, showInvoice: () => { events.push("invoice"); },
    saveRecovery: async (_file, stage) => { events.push(`recovery:${stage}`); if (mode === "terms" && stage === "terms") throw new Error("terms commit aborted"); },
    checkWallet: async () => { events.push("wallet:check"); }, claimGas: mode.startsWith("sponsored") ? "sponsored" : "wallet",
    ...(mode === "sponsored-rejected" ? { verifyClaim: async (txHash: string) => {
      events.push(`verify:${txHash}`); throw new Error("operation proof rejected");
    } } : {}),
    markExposure: async () => { events.push("exposure:commit"); if (mode === "exposure") throw new Error("exposure commit aborted"); if (mode === "stale") monotonic = 6_000; },
    claim: async () => { events.push("wallet:claim"); submitted = true; if (mode === "ineffective" || mode === "sponsored-rejected") return "ab".repeat(32); throw new Error("wallet response lost"); } });
} catch (caught) { error = (caught as Error).message; }
console.log(JSON.stringify({ events, error }));
