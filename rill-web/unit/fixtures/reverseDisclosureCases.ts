/** Independently signed historical CLI-style evidence, never live nonce authority. */
import canonicalize from "canonicalize";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { appendReverseClaimFallback, constructSelectedReverseClaim, REVERSE_COOPERATIVE_RESERVATION_EXTENSION as BURN,
  REVERSE_DISCLOSURE_EXTENSION as DISCLOSURE, REVERSE_FALLBACK_EXTENSION as FALLBACK } from "../../src/recoveryInspection";
import { buildCooperativeClaimPlan } from "../../src/swap/cooperative";
import { fundingBindingHash, unsignedEnvelopeHash } from "../../src/swap/hashes";
import type { Envelope } from "../../src/swap/session";
import { clientSessionSecret, providerSessionSecret, signDigest } from "./recoveryInspectionFixture";
import { reverseCase, type ReverseFixtureRecord } from "./reverseRecoveryCases";

export const encodeReverseEvidence = (record: unknown): Uint8Array => new TextEncoder().encode(canonicalize(record)!);
export function reverseDisclosureFixture() {
  const data = reverseCase(), context = data.record.verification_context, binding = data.record.funding_history[0]!.binding;
  const claim = constructSelectedReverseClaim(encodeReverseEvidence(data.record), data.expectedNetwork, { ...data,
    rawFundingTransaction: hexToBytes(data.fundingTxHex), sampledTipHeight: data.tipHeight, feeSat: 100n });
  const record = JSON.parse(new TextDecoder().decode(appendReverseClaimFallback(encodeReverseEvidence(data.record), data.expectedNetwork,
    hexToBytes(claim.transactionHex)))) as ReverseFixtureRecord;
  const plan = buildCooperativeClaimPlan(record.contract_terms, binding, 100n);
  const proposal: Envelope = { protocol: "rillswap", wire_version: "1", profile_id: "ln-to-btc/v1", network_identity: data.expectedNetwork,
    session_id: context.handshake_init.session_id, message_id: "ad".repeat(32), sender_session_key: context.client_session_xonly_key,
    sequence: 5, in_reply_to: null, contract_hash: record.contract_hash, message_type: "action_request", required_features: ["cooperative-claim/v1"],
    extensions: {}, signature: null, payload: { action: "cooperative_claim_propose", cooperation_id: "ff".repeat(32),
      unsigned_transaction: bytesToHex(plan.baseTransaction), payment_preimage: record.monotonic_knowledge.preimage,
      public_nonce: "02" + "11".repeat(32) + "03" + "22".repeat(32), deadline_at: record.updated_at + 20,
      deadline_height: record.contract_terms.refund_lock_height - record.contract_terms.timing_policy.claim_confirmation_blocks } };
  const burn = { funding_binding_hash: bytesToHex(fundingBindingHash(binding)), cooperation_id: "ff".repeat(32) };
  const disclosure = { version: 1, funding_binding_hash: burn.funding_binding_hash, proposal };
  record.extensions[BURN] = burn; record.extensions[DISCLOSURE] = disclosure;
  const sign = () => { disclosure.proposal = { ...disclosure.proposal, signature: signDigest(unsignedEnvelopeHash({ ...disclosure.proposal }), clientSessionSecret) }; };
  sign();
  return { ...data, record, burn, disclosure, sign };
}

export function reverseDisclosureCases() {
  const cases: { name: string; record: ReverseFixtureRecord; expectedNetwork: unknown; accepted: boolean }[] = [];
  const add = (name: string, accepted: boolean, mutate: (item: ReturnType<typeof reverseDisclosureFixture>) => void = () => {}) => {
    const item = reverseDisclosureFixture(); mutate(item);
    cases.push({ name, accepted, record: item.record, expectedNetwork: item.expectedNetwork });
  };
  add("valid disclosure and burn", true);
  add("burn only", true, ({ record }) => { delete record.extensions[DISCLOSURE]; });
  add("valid historical disclosure without burn", true, ({ record }) => { delete record.extensions[BURN]; });
  add("expired disclosure is still historical evidence", true, ({ record }) => { record.updated_at += 3600; });
  add("another authorized historical proposal fee", true, (f) => {
    f.disclosure.proposal.payload.unsigned_transaction = bytesToHex(buildCooperativeClaimPlan(f.record.contract_terms, f.record.funding_history[0]!.binding, 200n).baseTransaction); f.sign();
  });
  add("later retained funding does not invalidate historical evidence", true, ({ record }) => {
    const item = structuredClone(record.funding_history[0]!);
    Object.assign(item.binding, { binding_revision: 1, funding_txid: "ee".repeat(32), replaces_txid: item.binding.funding_txid });
    item.funder_session_signature = signDigest(fundingBindingHash(item.binding), providerSessionSecret); record.funding_history.push(item);
  });
  add("missing fallback", false, ({ record }) => { delete record.extensions[FALLBACK]; });
  add("zero burned ID", false, ({ burn }) => { burn.cooperation_id = "00".repeat(32); });
  add("different burned ID", false, ({ burn }) => { burn.cooperation_id = "ee".repeat(32); });
  add("different burn binding", false, ({ burn }) => { burn.funding_binding_hash = "ee".repeat(32); });
  add("different disclosure binding", false, ({ disclosure }) => { disclosure.funding_binding_hash = "ee".repeat(32); });
  add("invalid signature", false, ({ disclosure }) => { disclosure.proposal = { ...disclosure.proposal, signature: "00".repeat(64) }; });
  const mutations: [string, (proposal: Envelope) => Envelope][] = [
    ["wrong sender", (p) => ({ ...p, sender_session_key: "ee".repeat(32) })],
    ["wrong contract", (p) => ({ ...p, contract_hash: "ee".repeat(32) })],
    ["wrong session", (p) => ({ ...p, session_id: "ee".repeat(32) })],
    ["reply dependency", (p) => ({ ...p, in_reply_to: "ee".repeat(32) })],
    ["missing feature", (p) => ({ ...p, required_features: [] })],
    ["unknown feature", (p) => ({ ...p, required_features: ["cooperative-claim/v1", "unknown/v1"] })],
    ["extra payload field", (p) => ({ ...p, payload: { ...p.payload, extra: true } })],
    ["wrong preimage", (p) => ({ ...p, payload: { ...p.payload, payment_preimage: "ee".repeat(32) } })],
    ["Boolean deadline", (p) => ({ ...p, payload: { ...p.payload, deadline_at: true } })],
    ["exhausted height cutoff", (p) => ({ ...p, payload: { ...p.payload, deadline_height: 219 } })],
    ["malformed nonce", (p) => ({ ...p, payload: { ...p.payload, public_nonce: "00" } })],
  ];
  for (const [name, mutate] of mutations) add(name, false, (f) => { f.disclosure.proposal = mutate(f.disclosure.proposal); f.sign(); });
  return cases;
}
