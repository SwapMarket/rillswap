/** Shared browser/native-Core parity cases, always synthetic public test keys. */
import { secp256k1, schnorr } from "@noble/curves/secp256k1.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import mainnet from "../../src/networks/mainnet.json" with { type: "json" };
import { epochBoundSessionId, fundingBindingHash, unsignedEnvelopeHash } from "../../src/swap/hashes";
import {
  appendBinding, clientSessionSecret, fixtureRecord, fundedRecord, moveToNetwork, providerSessionSecret, reservedRecord,
  signDigest, signRecord, type FixtureRecord,
} from "./recoveryInspectionFixture";

export interface InspectionCase { readonly name: string; readonly record: FixtureRecord; readonly accepted: boolean; readonly expectedNetwork: unknown }
const entry = (name: string, record: FixtureRecord, accepted: boolean, expectedNetwork: unknown = record.network_identity): InspectionCase =>
  ({ name, record, accepted, expectedNetwork });
const invalid = (name: string, edit: (r: FixtureRecord) => void, factory = fixtureRecord, resign = true): InspectionCase => {
  const record = factory(); edit(record); if (resign) signRecord(record); return entry(name, record, false);
};

type Proposal = { payload: Record<string, unknown>; signature: string; [key: string]: unknown };
function marker(record: FixtureRecord): { proposal: Proposal; signature_hash: string } {
  return record.extensions["rillswap/cooperative-claim-reservation"] as ReturnType<typeof marker>;
}
const reservationCase = (name: string, edit: (m: ReturnType<typeof marker>, r: FixtureRecord) => void, resign = true): InspectionCase => {
  const record = reservedRecord(); const m = marker(record); edit(m, record);
  if (resign) m.proposal.signature = signDigest(unsignedEnvelopeHash(m.proposal), providerSessionSecret);
  return entry(name, record, false);
};

export function recoveryInspectionCases(): InspectionCase[] {
  const cooperative = fixtureRecord();
  cooperative.contract_terms.required_features = ["cooperative-claim/v1"];
  cooperative.verification_context.handshake_init.required_features = ["cooperative-claim/v1", "epoch-bound-session/v1"];
  cooperative.verification_context.handshake_accept.required_features = ["cooperative-claim/v1", "epoch-bound-session/v1"];
  signRecord(cooperative);
  const main = fixtureRecord(); moveToNetwork(main, mainnet); signRecord(main);
  const epoch = fixtureRecord();
  const epochKey = bytesToHex(schnorr.getPublicKey(hexToBytes("0".repeat(63) + "9")));
  const init = epoch.verification_context.handshake_init, accept = epoch.verification_context.handshake_accept;
  init.required_features = accept.required_features = ["epoch-bound-session/v1"];
  init.extensions = { "rillswap/epoch-bound-session": { epoch_inbox_xonly_key: epochKey } };
  init.session_id = bytesToHex(epochBoundSessionId(init.network_identity, init.expected_provider_identity_xonly_key, epochKey, init.client_session_xonly_key));
  accept.session_id = init.session_id;
  signRecord(epoch);
  const later = reservedRecord(); appendBinding(later);
  const maxHistory = fundedRecord(); while (maxHistory.funding_history.length < 64) appendBinding(maxHistory);
  const optional = fixtureRecord(); optional.extensions = { "example/info": { ignored: true } };
  const cases: InspectionCase[] = [
    entry("original expired session", fixtureRecord(), true),
    entry("expired mainnet session", main, true, mainnet),
    entry("jointly cooperative, no reservation", cooperative, true),
    entry("session bound to another epoch", epoch, true),
    entry("signed funding revision zero", fundedRecord(), true),
    entry("all 64 signed revisions", maxHistory, true),
    entry("expired cooperative reservation against older revision", later, true),
    entry("unknown optional extension remains opaque", optional, true),
    entry("same label but wrong full network", fixtureRecord(), false, { ...fixtureRecord().network_identity, genesis_hash: "a".repeat(64) }),
    invalid("embedded network mismatch", (r) => { r.verification_context.handshake_init.network_identity = { ...r.network_identity, deployment_namespace: "other" }; }),
    invalid("reused purpose key", (r) => { r.contract_terms.recovery_authorization_xonly_key = r.verification_context.client_session_xonly_key; r.recovery_authorization_xonly_key = r.contract_terms.recovery_authorization_xonly_key; }),
    invalid("unknown required feature", (r) => { r.contract_terms.required_features = ["unknown/v1"]; }),
    invalid("feature injection without both handshake halves", (r) => { r.contract_terms.required_features = ["cooperative-claim/v1"]; }),
    // Every session is epoch-bound: neither an unbound session nor a binding without its feature is admitted.
    invalid("unbound session with a random identifier", (r) => {
      const { handshake_init: init, handshake_accept: accept } = r.verification_context;
      init.required_features = accept.required_features = []; init.extensions = {};
      init.session_id = accept.session_id = "10".repeat(32);
    }),
    invalid("epoch binding without its feature", (r) => {
      r.verification_context.handshake_init.required_features = r.verification_context.handshake_accept.required_features = [];
    }),
    invalid("reversed feature order", (r) => { r.verification_context.handshake_init.required_features = ["epoch-bound-session/v1", "cooperative-claim/v1"]; }),
    invalid("same session and challenge", (r) => { r.verification_context.handshake_init.client_challenge = r.verification_context.handshake_init.session_id; r.verification_context.handshake_accept.client_challenge = r.verification_context.handshake_init.session_id; }),
    invalid("selected capability not requested", (r) => { r.verification_context.handshake_accept.selected_capabilities = ["unknown/v1"]; }),
    invalid("accept profile not echoed", (r) => { r.verification_context.handshake_accept.profile_id = "ln-to-btc/v1"; }),
    invalid("provider challenge collides with client challenge", (r) => { r.verification_context.handshake_accept.provider_challenge = r.verification_context.handshake_init.client_challenge; }),
    invalid("invalid payee curve point", (r) => { r.contract_terms.invoice_binding.payee_compressed_pubkey = "02" + "f".repeat(64); }),
    invalid("invoice amount inconsistent", (r) => { r.contract_terms.invoice_binding.amount_msat = "1"; }),
    invalid("expiry must follow creation", (r) => { r.contract_terms.invoice_binding.expires_at = r.contract_terms.invoice_binding.created_at; }),
    invalid("economics mismatch despite valid signatures", (r) => { r.contract_terms.economics.success_fee_sat = "999"; }),
    invalid("fee over monetary maximum", (r) => { r.contract_terms.max_claim_fee_sat = "2100000000000001"; r.fee_policy.max_claim_fee_sat = r.contract_terms.max_claim_fee_sat; }),
    invalid("HTLC at refund boundary", (r) => { r.contract_terms.timing_policy.max_outgoing_htlc_expiry_height = r.contract_terms.refund_lock_height + 1 - r.contract_terms.timing_policy.learn_and_claim_blocks; }),
    invalid("timestamps decrease", (r) => { r.updated_at = r.created_at - 1; }),
    invalid("birthday after refund", (r) => { r.chain_scan_birthday_height = r.contract_terms.refund_lock_height + 1; }),
    invalid("metadata recovery key mismatch", (r) => { r.recovery_authorization_xonly_key = "a".repeat(64); }),
    invalid("fee policy mismatch", (r) => { r.fee_policy.max_refund_fee_sat = "1"; }),
    invalid("contract secret mismatch", (r) => { r.user_secret.contract_secret_key = "0".repeat(63) + "9"; }),
    invalid("invalid contract secret scalar", (r) => { r.user_secret.contract_secret_key = "0".repeat(64); }),
    invalid("known preimage missing", (r) => { r.monotonic_knowledge.preimage_known = true; }),
    invalid("preimage present but unknown", (r) => { r.monotonic_knowledge.preimage = "a".repeat(64); }),
    invalid("known preimage mismatches hash", (r) => { r.monotonic_knowledge = { ...r.monotonic_knowledge, preimage_known: true, preimage: "a".repeat(64) }; }),
    invalid("reverse fallback on forward record", (r) => { r.extensions = { "rillswap/reverse-claim-fallback": { version: 1, funding_binding_hash: "a".repeat(64), transaction: "00" } }; }),
    invalid("partial funding record missing field", (r) => { delete (r.funding_history[0]!.binding as unknown as Record<string, unknown>).funding_attempt_id; }, fundedRecord),
    invalid("funding wrong role", (r) => { r.funding_history[0]!.binding.funder_role = "provider"; }, fundedRecord),
    invalid("funding wrong amount", (r) => { r.funding_history[0]!.binding.contract_value_sat = "1"; }, fundedRecord),
    invalid("funding outpoint too large", (r) => { r.funding_history[0]!.binding.contract_vout = 0x100000000; }, fundedRecord),
    invalid("funding anchor index too large", (r) => { r.funding_history[0]!.binding.lineage_anchor_vout = 0x100000000; }, fundedRecord),
    invalid("revision zero has predecessor", (r) => { r.funding_history[0]!.binding.replaces_txid = "1".repeat(64); }, fundedRecord),
    invalid("history gap", (r) => { appendBinding(r); r.funding_history[1]!.binding.binding_revision = 2; }, fundedRecord),
    invalid("history changed attempt", (r) => { appendBinding(r); r.funding_history[1]!.binding.funding_attempt_id = "1".repeat(64); }, fundedRecord),
    invalid("history changed anchor", (r) => { appendBinding(r); r.funding_history[1]!.binding.lineage_anchor_vout = 2; }, fundedRecord),
    invalid("history wrong predecessor", (r) => { appendBinding(r); r.funding_history[1]!.binding.replaces_txid = "1".repeat(64); }, fundedRecord),
    invalid("history duplicate transaction", (r) => { appendBinding(r); r.funding_history[1]!.binding.funding_txid = r.funding_history[0]!.binding.funding_txid; }, fundedRecord),
    invalid("invalid older history signature", (r) => { appendBinding(r); r.funding_history[0]!.funder_session_signature = "0".repeat(128); }, fundedRecord, false),
    invalid("too many funding revisions", (r) => { while (r.funding_history.length < 65) appendBinding(r); }, fundedRecord),
    reservationCase("reservation wrong session", (m) => { m.proposal.session_id = "0".repeat(64); }),
    reservationCase("reservation reply not null", (m) => { m.proposal.in_reply_to = "1".repeat(64); }),
    reservationCase("reservation wrong signature", (m) => { m.proposal.signature = "0".repeat(128); }, false),
    reservationCase("reservation changed preimage", (m) => { m.proposal.payload.payment_preimage = "a".repeat(64); }),
    reservationCase("reservation wrong sighash", (m) => { m.signature_hash = "0".repeat(64); }),
    reservationCase("reservation too late height", (m, r) => { m.proposal.payload.deadline_height = r.contract_terms.refund_lock_height; }),
    reservationCase("reservation invalid nonce length", (m) => { m.proposal.payload.public_nonce = "0".repeat(130); }),
    reservationCase("reservation zero cutoff time", (m) => { m.proposal.payload.deadline_at = 0; }),
    reservationCase("reservation extra payload member", (m) => { m.proposal.payload.extra = true; }),
    reservationCase("reservation transaction mismatches every binding", (m) => { m.proposal.payload.unsigned_transaction = "00".repeat(60); }),
    reservationCase("reservation signer role wrong", (m) => { m.proposal.sender_session_key = bytesToHex(schnorr.getPublicKey(clientSessionSecret)); m.proposal.signature = signDigest(unsignedEnvelopeHash(m.proposal), clientSessionSecret); }, false),
    reservationCase("reservation missing cooperative feature", (m) => { m.proposal.required_features = []; }),
  ];
  for (const field of ["provider_identity_signature", "provider_terms_signature", "client_acceptance_signature"] as const) {
    cases.push(invalid(`invalid ${field}`, (r) => { r.verification_context[field] = "0".repeat(128); }, fixtureRecord, false));
  }
  for (const field of Object.keys(fixtureRecord().taproot_contract)) {
    cases.push(invalid(`altered Taproot ${field}`, (r) => {
      const artifact = r.taproot_contract as unknown as Record<string, unknown>;
      artifact[field] = typeof artifact[field] === "number" ? 1 - (artifact[field] as number) : "00";
    }, fixtureRecord, false));
  }
  const badEpoch = structuredClone(epoch); (badEpoch.verification_context.handshake_init.extensions["rillswap/epoch-bound-session"] as Record<string, unknown>).epoch_inbox_xonly_key = bytesToHex(secp256k1.getPublicKey(hexToBytes("0".repeat(63) + "8"), true)).slice(2); signRecord(badEpoch);
  cases.push(entry("epoch hash mismatch despite re-signing", badEpoch, false));
  return cases;
}
