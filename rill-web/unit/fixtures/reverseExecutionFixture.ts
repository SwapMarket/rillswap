/** Real cryptographic admission with synthetic keys/chain responses and an in-memory journal seam. */
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { schnorr } from "@noble/curves/secp256k1.js";
import { testInvoice } from "../../../rill-payments/tests/helpers";
import { invoiceBinding } from "../../src/swap/bolt11";
import { prepareReverseExecution } from "../../src/swap/reverseExecution";
import { reverseRecord, signReverseRecord } from "./reverseRecoveryCases";
import { clientSessionSecret, identitySecret, providerSessionSecret, signDigest } from "./recoveryInspectionFixture";
import { contractHash, fundingBindingHash, providerTermsHash, handshakeHash } from "../../src/swap/hashes";
import { reconstructTaprootContract } from "../../src/swap/taproot";
import { serializeTransaction, parseTransaction } from "../../src/swap/transaction";
import { createRecoveryKey, decryptRecoveryContainer } from "../../src/recoveryKeys";
import type { Session, Envelope } from "../../src/swap/session";
import type { ReverseFirmQuoteRequest, LnToBtcTerms, ReverseTermsOffer, HandshakeInit, HandshakeAccept } from "../../src/swap/wire";
import type { BrowserReverseJournal, ReverseJournalRecord, ReverseIntentContext } from "../../src/browserReverseJournal";
import type { BrowserHoldPayer, BoundedHoldPlan } from "../../src/swap/browserHoldPayer";
import type { ReverseSwapRequest } from "../../src/swap/reverseSwap";

export async function executionFixture() {
  const source = reverseRecord(); source.contract_terms.required_features = [];
  source.verification_context.handshake_init.required_features = source.verification_context.handshake_accept.required_features = [];
  signReverseRecord(source);
  const saved = source.verification_context, now = { seconds: 1700000000 }, transcript = bytesToHex(handshakeHash(saved.handshake_init, saved.handshake_accept));
  const events: string[] = [], files: Uint8Array[] = [], identity = await createRecoveryKey();
  let approved = true, fail = "", rejectReadback = "", callback = (_stage: string): void => {}, firm: ReverseFirmQuoteRequest, offer: ReverseTermsOffer, fundingHex = "", funding: Envelope;
  let stored: ReverseJournalRecord;
  const update = async (stage: ReverseJournalRecord["stage"], file?: Uint8Array, extra = {}) => {
    events.push(stage); if (file) files.push(Uint8Array.from(file));
    if (fail === stage) throw new Error("storage unavailable");
    stored = { ...stored, ...extra, stage }; callback(stage);
    if (rejectReadback === stage) throw new Error("committed readback unavailable"); return stored;
  };
  const journal = {
    createFresh: async (context: ReverseIntentContext, file: Uint8Array) => { stored = { context, id: "public-id", stage: "secrets-ready", snapshots: [], payment: null, claim: null, digest: "public-digest" }; return update("secrets-ready", file); },
    saveTerms: (_r: ReverseJournalRecord, f: Uint8Array) => update("terms-ready", f),
    beginPayment: (_r: ReverseJournalRecord, endpoint: string, plan: BoundedHoldPlan, f: Uint8Array) => update("payment-unknown", f, { payment: { state: "submission-unknown", endpoint, plan } }),
    saveFunding: (_r: ReverseJournalRecord, f: Uint8Array) => update("funded", f),
    prepareClaim: (_r: ReverseJournalRecord, claim: unknown, f: Uint8Array) => update("claim-ready", f, { claim }),
    beginClaimExposure: () => update("claim-unknown"), reexportIdentical: async () => stored,
    markAccepted: () => update("accepted"),
  } as unknown as BrowserReverseJournal;
  let counter = 0;
  const session = {
    secret: Uint8Array.from(clientSessionSecret), key: saved.client_session_xonly_key, sessionId: saved.handshake_init.session_id, profile: "ln-to-btc/v1", providerKey: saved.provider_session_xonly_key,
    envelope(kind: string, payload: Record<string, unknown>, options = {}) { return { message_type: kind, payload, message_id: String(++counter).padStart(64, "0"), ...options }; },
    async send(envelope: Envelope, _key: string, authorize?: () => void) {
      authorize?.(); events.push(`send:${envelope.message_type}`); if (envelope.message_type === "quote_request") firm = envelope.payload as unknown as ReverseFirmQuoteRequest;
    },
    async replyTo(_envelope: Envelope, kind: string) {
      if (kind === "ack") return { payload: {} };
      const terms: LnToBtcTerms = { ...source.contract_terms, client_contract_compressed_key: firm.client_contract_compressed_key,
        recovery_authorization_xonly_key: firm.recovery_authorization_xonly_key, client_destination_script: firm.client_destination_script,
        invoice_binding: invoiceBinding(testInvoice("reverse-execution", "51100000", now.seconds, now.seconds + 100, "bcrt", firm.payment_hash), "regtest"), terms_expiry: now.seconds + 80 };
      const digest = bytesToHex(contractHash(terms)), providerTerms = { contract_hash: digest, contract_terms: terms, handshake_hash: transcript };
      offer = { terms: providerTerms, provider_terms_signature: signDigest(providerTermsHash(providerTerms), identitySecret),
        hold_invoice: testInvoice("reverse-execution", "51100000", now.seconds, now.seconds + 100, "bcrt", firm.payment_hash) };
      const binding = { ...source.funding_history[0]!.binding, contract_hash: digest, contract_script_pubkey: reconstructTaprootContract(terms).script_pubkey, created_at: now.seconds };
      const raw = serializeTransaction({ version: 2, locktime: 0,
        inputs: [{ txid: binding.lineage_anchor_txid, vout: binding.lineage_anchor_vout, sequence: 0xfffffffd, scriptSig: new Uint8Array(), witness: [] }],
        outputs: [{ value: 51000n, script: hexToBytes(binding.contract_script_pubkey) }] }, true);
      fundingHex = bytesToHex(raw); binding.funding_txid = parseTransaction(raw).txid;
      funding = { sender_session_key: session.providerKey, message_type: "funding_binding", contract_hash: digest, in_reply_to: null,
        payload: { binding, funding_binding_signature: signDigest(fundingBindingHash(binding), providerSessionSecret), funding_transaction: fundingHex } } as unknown as Envelope;
      return { contract_hash: digest, message_id: "f".repeat(64), payload: offer };
    },
    async receive() { events.push("receive-funding"); return funding; },
  } as unknown as Session;
  const assertCurrent = (): void => { if (!approved) throw new Error("approval changed"); };
  const request: ReverseSwapRequest = { identity: saved.handshake_accept.provider_identity_xonly_key,
    network: source.network_identity, payoutSat: 50000n, limits: { maxSuccessFeeSat: 1000n, minClaimFeeReserveSat: 500n, maxClaimFeeSat: 1000n,
      minRefundDelayBlocks: 18, maxIncomingHtlcDelayBlocks: 50 } };
  let plan: BoundedHoldPlan;
  const payer = {
    endpoint: "http://127.0.0.1:8093",
    async plan(_invoice: string, binding: unknown, limits: { feeLimitSat: bigint; deadlineAt: number; minFinalExpiryHeight: number; maxExpiryHeight: number }) {
      events.push("plan"); plan = { nodeIdentity: bytesToHex(schnorr.getPublicKey(clientSessionSecret)), networkIdentity: source.network_identity, paymentHash: firm.payment_hash,
        invoiceBinding: binding, limits: { ...limits, feeLimitSat: limits.feeLimitSat.toString() }, feeMsat: "1000", route: {} } as BoundedHoldPlan; return plan;
    },
    async pay(_plan: BoundedHoldPlan, authorize: () => Promise<void>, check: () => void) {
      check(); await authorize(); check(); events.push("payment-post"); return "IN_FLIGHT";
    },
  } as unknown as BrowserHoldPayer;
  let posts = 0, spent = false, tipHeight = 200;
  const fetch = async (url: string | URL | Request, init?: RequestInit): Promise<Response> => {
    const path = String(url).split("/api/")[1]!; events.push(`api:${init?.method ?? "GET"}:${path}`);
    if (init?.method === "POST") { posts++; return new Response(parseTransaction(hexToBytes(init.body as string)).txid); }
    const responses: Record<string, string> = { "block-height/0": source.network_identity.genesis_hash, "blocks/tip/height": String(tipHeight), "blocks/tip/hash": "a".repeat(64),
      [`tx/${funding?.payload.binding ? (funding.payload.binding as { funding_txid: string }).funding_txid : ""}/hex`]: fundingHex,
      [`tx/${funding?.payload.binding ? (funding.payload.binding as { funding_txid: string }).funding_txid : ""}/status`]: JSON.stringify({ confirmed: true, block_height: 190, block_hash: "d".repeat(64) }),
      [`tx/${funding?.payload.binding ? (funding.payload.binding as { funding_txid: string }).funding_txid : ""}/outspend/0`]: JSON.stringify({ spent }), "block-height/190": "d".repeat(64) };
    if (!(path in responses)) throw new Error("unexpected endpoint"); return new Response(responses[path]!);
  };
  const prepare = () => prepareReverseExecution(session, { init: saved.handshake_init as HandshakeInit, accept: saved.handshake_accept as HandshakeAccept,
    acceptSignature: saved.provider_identity_signature, transcript }, request,
    { destinationScript: source.contract_terms.client_destination_script, tipHeight: 200, ageRecipient: identity.recipient, journal, assertCurrent }, () => now.seconds * 1000);
  return { events, files, prepare, payer, assertCurrent, fetch: Object.assign(fetch, { preconnect: () => {} }) as typeof globalThis.fetch, now, session, request, decrypt: (f: Uint8Array) => decryptRecoveryContainer(f, identity.identity),
    get posts() { return posts; }, get record() { return stored; }, get funding() { return funding; }, get terms() { return offer.terms.contract_terms; },
    set approved(value: boolean) { approved = value; }, set fail(stage: string) { fail = stage; }, set callback(value: (stage: string) => void) { callback = value; },
    set rejectReadback(stage: string) { rejectReadback = stage; },
    set spent(value: boolean) { spent = value; }, set tipHeight(value: number) { tipHeight = value; },
  };
}
