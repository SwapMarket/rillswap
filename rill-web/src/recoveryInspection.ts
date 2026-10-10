/**
 * Offline RS-007 BTC to LN inspection, matching Core's historical checks.
 * This proves internal consistency under embedded signers, not provenance,
 * ownership, chain inclusion, unspent state, or authority to sign/broadcast.
 * Return values and errors contain no secrets. Immutable parsed strings cannot
 * be guaranteed erased from browser memory. There are no live-time gates.
 */
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { validateNetwork } from "./generated/manualAdvertisementValidators.js";
import { parseRecoveryPlaintext } from "./recoveryDocument";
import { COOPERATIVE_RESERVATION_EXTENSION, verifyCooperativeClaimProposal } from "./swap/cooperative";
import type { FundingBinding } from "./swap/funding";
import {
  clientAcceptanceHash, contractHash, epochBoundSessionId, fundingBindingHash, handshakeAcceptHash,
  handshakeHash, handshakeInitHash, jcs, providerTermsHash, unsignedEnvelopeHash,
} from "./swap/hashes";
import { reconstructTaprootContract, type TaprootContract } from "./swap/taproot";
import {
  COOPERATIVE_CLAIM_FEATURE, EPOCH_SESSION_EXTENSION, EPOCH_SESSION_FEATURE, MAX_SATS, sats,
  verifySchnorr, type BtcToLnTerms, type HandshakeAccept, type HandshakeInit,
} from "./swap/wire";

export interface RecoveryInspection {
  readonly verification: "historical-static";
  readonly networkName: string;
  readonly profileId: "btc-to-ln/v1";
  readonly contractHash: string;
  readonly refundLockHeight: number;
  readonly firstRefundEligibleHeight: number;
  /** Signed revisions, NOT evidence that any output actually exists or is unspent. */
  readonly recordedBindingCount: number;
}

export class RecoveryInspectionRefusedError extends Error {
  constructor() {
    super("Recovery document could not be authenticated");
    this.name = "RecoveryInspectionRefusedError";
  }
}

interface HistoricalBinding extends Omit<FundingBinding, "binding_revision" | "replaces_txid"> {
  readonly binding_revision: number;
  readonly replaces_txid: string | null;
}

/** Only used after bounded, canonical admission has checked every field's shape. */
interface RecoveryRecord {
  readonly network_identity: { readonly name: string };
  readonly profile_id: string;
  readonly contract_hash: string;
  readonly created_at: number;
  readonly updated_at: number;
  readonly contract_terms: BtcToLnTerms;
  readonly verification_context: {
    readonly handshake_init: HandshakeInit;
    readonly handshake_accept: HandshakeAccept;
    readonly provider_identity_signature: string;
    readonly handshake_hash: string;
    readonly client_session_xonly_key: string;
    readonly provider_session_xonly_key: string;
    readonly provider_terms_signature: string;
    readonly client_acceptance_signature: string;
  };
  readonly taproot_contract: TaprootContract;
  readonly user_secret: { readonly contract_secret_key: string };
  readonly funding_history: readonly { readonly binding: HistoricalBinding; readonly funder_session_signature: string }[];
  readonly chain_scan_birthday_height: number;
  readonly recovery_authorization_xonly_key: string;
  readonly fee_policy: { readonly max_claim_fee_sat: string; readonly max_refund_fee_sat: string };
  readonly monotonic_knowledge: { readonly preimage_known: boolean; readonly preimage: string | null };
  readonly extensions: Readonly<Record<string, unknown>>;
}

const same = (left: unknown, right: unknown): boolean => bytesToHex(jcs(left)) === bytesToHex(jcs(right));
function require(condition: boolean): void {
  if (!condition) throw new RecoveryInspectionRefusedError();
}

function curveKey(key: string, compressed = false): void {
  // Schema establishes exact lowercase encoding; SEC point decoding establishes curve membership.
  secp256k1.Point.fromBytes(hexToBytes(compressed ? key : `02${key}`)).assertValidity();
}

function features(list: readonly string[], supported: readonly string[]): void {
  require(list.every((item, i) => supported.includes(item) && (i === 0 || list[i - 1]! < item)));
}

/** Historical model/validate_against rules, intentionally NOT the live admission helper. */
function checkHandshake(record: RecoveryRecord): void {
  const { handshake_init: init, handshake_accept: accept } = record.verification_context;
  const supported = [COOPERATIVE_CLAIM_FEATURE, EPOCH_SESSION_FEATURE];
  features(init.required_features, supported);
  features(accept.required_features, supported);
  features(record.contract_terms.required_features, [COOPERATIVE_CLAIM_FEATURE]);
  for (const feature of supported) {
    require(init.required_features.includes(feature) === accept.required_features.includes(feature));
  }
  require(record.contract_terms.required_features.includes(COOPERATIVE_CLAIM_FEATURE) === init.required_features.includes(COOPERATIVE_CLAIM_FEATURE));
  require(init.session_id !== init.client_challenge && init.client_session_xonly_key !== init.expected_provider_identity_xonly_key);
  require(new Set([accept.client_session_xonly_key, accept.provider_session_xonly_key, accept.provider_identity_xonly_key]).size === 3);
  require(![accept.session_id, accept.client_challenge].includes(accept.provider_challenge));
  const echoed = ["protocol", "wire_version", "profile_id", "network_identity", "session_id", "client_challenge", "client_session_xonly_key"] as const;
  require(echoed.every((field) => same(accept[field], init[field])));
  require(accept.handshake_init_hash === bytesToHex(handshakeInitHash(init)));
  require(accept.provider_identity_xonly_key === init.expected_provider_identity_xonly_key);
  require(init.requested_encryption_suites.includes(accept.selected_encryption_suite));
  require(accept.selected_capabilities.every((item) => init.requested_capabilities.includes(item)));
  for (const key of [init.client_session_xonly_key, init.expected_provider_identity_xonly_key,
    accept.client_session_xonly_key, accept.provider_session_xonly_key, accept.provider_identity_xonly_key]) curveKey(key);
  if (init.required_features.includes(EPOCH_SESSION_FEATURE)) {
    const extension = init.extensions[EPOCH_SESSION_EXTENSION];
    require(extension !== null && typeof extension === "object" && !Array.isArray(extension));
    const object = extension as Record<string, unknown>;
    require(Object.keys(object).length === 1 && typeof object.epoch_inbox_xonly_key === "string");
    const epoch = object.epoch_inbox_xonly_key as string;
    require(/^[0-9a-f]{64}$/.test(epoch));
    curveKey(epoch);
    require(accept.provider_session_xonly_key !== epoch);
    require(init.session_id === bytesToHex(epochBoundSessionId(init.network_identity, init.expected_provider_identity_xonly_key, epoch, init.client_session_xonly_key)));
  }
}

function checkTerms(terms: BtcToLnTerms): void {
  // The parser already enforced the closed schema, including profile roles, networks, lists, and extensions.
  require(terms.profile_id === "btc-to-ln/v1" && terms.economics.kind === "btc-to-ln" && terms.timing_policy.kind === "btc-to-ln");
  require(terms.claimant === "provider" && terms.refund_party === "client");
  const principal = sats(terms.economics.lightning_principal_sat, "principal", true);
  const fee = sats(terms.economics.success_fee_sat, "success fee");
  require(principal + fee === sats(terms.economics.contract_amount_sat, "contract amount", true));
  for (const value of [terms.max_funding_fee_sat, terms.max_claim_fee_sat, terms.max_refund_fee_sat]) sats(value, "fee cap");
  for (const key of [terms.client_contract_compressed_key, terms.provider_contract_compressed_key, terms.invoice_binding.payee_compressed_pubkey]) curveKey(key, true);
  curveKey(terms.provider_identity_key);
  curveKey(terms.recovery_authorization_xonly_key);
  const invoice = terms.invoice_binding;
  const msats = BigInt(invoice.amount_msat);
  require(msats > 0n && msats <= MAX_SATS * 1000n && msats === principal * 1000n && invoice.expires_at > invoice.created_at);
  require(terms.timing_policy.max_outgoing_htlc_expiry_height + terms.timing_policy.learn_and_claim_blocks < terms.refund_lock_height + 1);
  const destination = /^(0014[0-9a-f]{40}|5120[0-9a-f]{64})$/;
  require(destination.test(terms.client_destination_script) && destination.test(terms.provider_destination_script));
}

function checkHistory(record: RecoveryRecord): void {
  const history = record.funding_history;
  const seen = new Set<string>();
  for (const [revision, item] of history.entries()) {
    const binding = item.binding;
    require(binding.contract_hash === record.contract_hash && binding.funder_role === "client" && binding.binding_revision === revision);
    require(sats(binding.contract_value_sat, "funding value", true) === BigInt(record.contract_terms.economics.contract_amount_sat));
    require(binding.contract_script_pubkey === record.taproot_contract.script_pubkey);
    require(binding.contract_vout <= 0xffffffff && binding.lineage_anchor_vout <= 0xffffffff);
    require(!seen.has(binding.funding_txid));
    seen.add(binding.funding_txid);
    if (revision === 0) require(binding.replaces_txid === null);
    else {
      const previous = history[revision - 1]!.binding;
      require(binding.replaces_txid === previous.funding_txid && binding.funding_attempt_id === previous.funding_attempt_id);
      require(binding.lineage_anchor_txid === previous.lineage_anchor_txid && binding.lineage_anchor_vout === previous.lineage_anchor_vout);
    }
    verifySchnorr(record.verification_context.client_session_xonly_key, fundingBindingHash(binding), item.funder_session_signature, "funding");
  }
}

interface Reservation {
  readonly signature_hash: string;
  readonly proposal: Record<string, unknown> & {
    readonly required_features: readonly string[];
    readonly signature: string | null;
    readonly payload: Record<string, unknown>;
  };
}

function checkReservation(record: RecoveryRecord): void {
  if (!Object.hasOwn(record.extensions, COOPERATIVE_RESERVATION_EXTENSION)) return;
  // The recovery schema checked the closed marker and embedded envelope.
  const reservation = record.extensions[COOPERATIVE_RESERVATION_EXTENSION] as Reservation;
  const proposal = reservation.proposal;
  const context = record.verification_context;
  require(record.funding_history.length > 0 && record.monotonic_knowledge.preimage_known);
  features(proposal.required_features, [COOPERATIVE_CLAIM_FEATURE, EPOCH_SESSION_FEATURE]);
  require(record.contract_terms.required_features.includes(COOPERATIVE_CLAIM_FEATURE) && proposal.required_features.includes(COOPERATIVE_CLAIM_FEATURE));
  require(proposal.session_id === context.handshake_init.session_id && proposal.profile_id === record.profile_id);
  require(same(proposal.network_identity, record.network_identity) && proposal.sender_session_key === context.provider_session_xonly_key);
  require(proposal.message_type === "action_request" && proposal.contract_hash === record.contract_hash && proposal.in_reply_to === null);
  require(proposal.signature !== null);
  verifySchnorr(context.provider_session_xonly_key, unsignedEnvelopeHash(proposal), proposal.signature!, "reservation");
  const payload = proposal.payload;
  const fields = ["action", "cooperation_id", "payment_preimage", "public_nonce", "unsigned_transaction", "deadline_at", "deadline_height"];
  require(Object.keys(payload).length === fields.length && fields.every((field) => Object.hasOwn(payload, field)));
  require(payload.action === "cooperative_claim_propose");
  for (const field of ["cooperation_id", "payment_preimage"]) require(typeof payload[field] === "string" && /^[0-9a-f]{64}$/.test(payload[field] as string));
  require(typeof payload.public_nonce === "string" && /^[0-9a-f]{132}$/.test(payload.public_nonce));
  require(typeof payload.unsigned_transaction === "string" && /^(?:[0-9a-f]{2}){60,1000}$/.test(payload.unsigned_transaction));
  require(typeof payload.deadline_at === "number" && Number.isSafeInteger(payload.deadline_at) && payload.deadline_at > 0);
  require(typeof payload.deadline_height === "number" && Number.isSafeInteger(payload.deadline_height) && payload.deadline_height > 0 &&
    payload.deadline_height <= record.contract_terms.refund_lock_height - record.contract_terms.timing_policy.claim_confirmation_blocks);
  require(payload.payment_preimage === record.monotonic_knowledge.preimage);
  let matches = 0;
  for (const { binding } of record.funding_history) {
    let digest: string;
    try {
      digest = bytesToHex(verifyCooperativeClaimProposal(hexToBytes(payload.unsigned_transaction as string), record.contract_terms, binding).signatureHash);
    } catch { continue; } // Another retained revision may be the proposal's original outpoint.
    require(digest === reservation.signature_hash);
    matches++;
  }
  require(matches === 1);
}

/** Network selection is external to the document. Success is a redacted report, never spending authority. */
export function inspectRecoveryPlaintext(plaintext: Uint8Array, independentlySelectedNetwork: unknown): RecoveryInspection {
  try {
    // Validate/snapshot the trust anchor; malformed or absent expectations never select a network for us.
    const network = JSON.parse(new TextDecoder().decode(jcs(independentlySelectedNetwork))) as unknown;
    require(validateNetwork(network));
    const record = parseRecoveryPlaintext(plaintext).document as unknown as RecoveryRecord;
    const terms = record.contract_terms;
    const context = record.verification_context;
    const init = context.handshake_init, accept = context.handshake_accept;
    require(record.profile_id === "btc-to-ln/v1" && init.profile_id === record.profile_id);
    require([record.network_identity, terms.network_identity, init.network_identity, accept.network_identity].every((item) => same(item, network)));
    checkHandshake(record);
    checkTerms(terms);
    require(context.client_session_xonly_key === init.client_session_xonly_key && context.provider_session_xonly_key === accept.provider_session_xonly_key);
    require(terms.provider_identity_key === init.expected_provider_identity_xonly_key);
    require(new Set([init.client_session_xonly_key, accept.provider_session_xonly_key, terms.provider_identity_key,
      terms.client_contract_compressed_key.slice(2), terms.provider_contract_compressed_key.slice(2), terms.recovery_authorization_xonly_key]).size === 6);
    require(record.contract_hash === bytesToHex(contractHash(terms)));
    require(context.handshake_hash === bytesToHex(handshakeHash(init, accept)));
    verifySchnorr(terms.provider_identity_key, handshakeAcceptHash(accept), context.provider_identity_signature, "handshake");
    verifySchnorr(terms.provider_identity_key, providerTermsHash({ contract_hash: record.contract_hash, contract_terms: terms,
      handshake_hash: context.handshake_hash }), context.provider_terms_signature, "terms");
    verifySchnorr(init.client_session_xonly_key, clientAcceptanceHash({ contract_hash: record.contract_hash,
      handshake_hash: context.handshake_hash, session_id: init.session_id, client_session_xonly_key: init.client_session_xonly_key,
      provider_session_xonly_key: accept.provider_session_xonly_key }), context.client_acceptance_signature, "acceptance");
    require(record.updated_at >= record.created_at && record.chain_scan_birthday_height <= terms.refund_lock_height);
    require(record.recovery_authorization_xonly_key === terms.recovery_authorization_xonly_key);
    require(record.fee_policy.max_claim_fee_sat === terms.max_claim_fee_sat && record.fee_policy.max_refund_fee_sat === terms.max_refund_fee_sat);
    const knowledge = record.monotonic_knowledge;
    require(knowledge.preimage_known === (knowledge.preimage !== null));
    if (knowledge.preimage !== null) require(bytesToHex(sha256(hexToBytes(knowledge.preimage))) === terms.invoice_binding.payment_hash);
    // The signing key stays local and is used only for deriving the public point, never for a signature.
    const secret = hexToBytes(record.user_secret.contract_secret_key);
    try { require(bytesToHex(secp256k1.getPublicKey(secret, true)) === terms.client_contract_compressed_key); }
    finally { secret.fill(0); }
    const reconstructed = reconstructTaprootContract(terms);
    require((Object.keys(reconstructed) as (keyof TaprootContract)[]).every((field) => record.taproot_contract[field] === reconstructed[field]));
    checkHistory(record);
    require(!Object.hasOwn(record.extensions, "rillswap/reverse-claim-fallback") && !Object.hasOwn(record.extensions, "rillswap/reverse-preimage-disclosure"));
    checkReservation(record);
    return Object.freeze({ verification: "historical-static", networkName: record.network_identity.name,
      profileId: "btc-to-ln/v1", contractHash: record.contract_hash, refundLockHeight: terms.refund_lock_height,
      firstRefundEligibleHeight: terms.refund_lock_height + 1, recordedBindingCount: record.funding_history.length });
  } catch { /* Do not attach errors from parsers, crypto, or secret-bearing documents. */ }
  throw new RecoveryInspectionRefusedError();
}
