/** Public fixture secrets only, never suitable for real funds. Native BIP340 signatures. */
import { schnorr } from "@noble/curves/secp256k1.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { sha256 } from "@noble/hashes/sha2.js";
import {
  clientAcceptanceHash, contractHash, epochBoundSessionId, fundingBindingHash, handshakeAcceptHash, handshakeHash,
  handshakeInitHash, providerTermsHash, unsignedEnvelopeHash,
} from "../../src/swap/hashes";
import { reconstructTaprootContract } from "../../src/swap/taproot";
import { buildCooperativeClaimPlan } from "../../src/swap/cooperative";
import type { BtcToLnTerms } from "../../src/swap/wire";
import type { FundingBinding } from "../../src/swap/funding";
import original from "./initial-btc-to-ln-v1.json" with { type: "json" };

export const identitySecret = hexToBytes("0".repeat(63) + "1");
export const clientSessionSecret = hexToBytes("0".repeat(63) + "2");
export const providerSessionSecret = hexToBytes("0".repeat(63) + "3");
export const testPreimage = "1".repeat(64);
type FixtureBinding = { -readonly [K in keyof FundingBinding]: K extends "binding_revision" ? number : K extends "replaces_txid" ? string | null : K extends "funder_role" ? "client" | "provider" : FundingBinding[K] };
type Mutable<T> = { -readonly [K in keyof T]: T[K] extends readonly (infer Item)[] ? Item[] : T[K] extends object ? Mutable<T[K]> : T[K] };
export type FixtureRecord = Omit<typeof original, "contract_terms" | "verification_context" | "funding_history" | "monotonic_knowledge" | "extensions"> & {
  contract_terms: Mutable<BtcToLnTerms>;
  verification_context: Omit<typeof original.verification_context, "handshake_init" | "handshake_accept"> & {
    handshake_init: Omit<typeof original.verification_context.handshake_init, "required_features" | "extensions"> & { required_features: string[]; extensions: Record<string, unknown> };
    handshake_accept: Omit<typeof original.verification_context.handshake_accept, "required_features"> & { required_features: string[] };
  };
  funding_history: { binding: FixtureBinding; funder_session_signature: string }[];
  monotonic_knowledge: { preimage_known: boolean; preimage: string | null; dangerous_signature_issued: boolean };
  extensions: Record<string, unknown>;
};
export const fixtureRecord = (): FixtureRecord => structuredClone(original) as unknown as FixtureRecord;
export const signDigest = (digest: Uint8Array, secret: Uint8Array): string => bytesToHex(schnorr.sign(digest, secret));

/** Move a record to another network; its epoch-bound session ID commits to the network, so it is rederived. */
export function moveToNetwork(record: FixtureRecord, network: unknown): void {
  const identity = structuredClone(network) as FixtureRecord["network_identity"];
  record.network_identity = identity;
  record.contract_terms.network_identity = structuredClone(identity) as FixtureRecord["contract_terms"]["network_identity"];
  const { handshake_init: init, handshake_accept: accept } = record.verification_context;
  init.network_identity = accept.network_identity = identity;
  const { epoch_inbox_xonly_key: epoch } = init.extensions["rillswap/epoch-bound-session"] as { epoch_inbox_xonly_key: string };
  init.session_id = accept.session_id = bytesToHex(
    epochBoundSessionId(identity, init.expected_provider_identity_xonly_key, epoch, init.client_session_xonly_key));
}

/** Re-sign after a mutation so semantic rejection tests do not merely exercise broken signatures. */
export function signRecord(record: FixtureRecord): FixtureRecord {
  const context = record.verification_context;
  context.handshake_accept.handshake_init_hash = bytesToHex(handshakeInitHash(context.handshake_init));
  context.provider_identity_signature = signDigest(handshakeAcceptHash(context.handshake_accept), identitySecret);
  context.handshake_hash = bytesToHex(handshakeHash(context.handshake_init, context.handshake_accept));
  record.contract_hash = bytesToHex(contractHash(record.contract_terms));
  context.provider_terms_signature = signDigest(providerTermsHash({ contract_hash: record.contract_hash,
    contract_terms: record.contract_terms, handshake_hash: context.handshake_hash }), identitySecret);
  context.client_acceptance_signature = signDigest(clientAcceptanceHash({ contract_hash: record.contract_hash,
    handshake_hash: context.handshake_hash, session_id: context.handshake_init.session_id,
    client_session_xonly_key: context.client_session_xonly_key, provider_session_xonly_key: context.provider_session_xonly_key }), clientSessionSecret);
  record.taproot_contract = reconstructTaprootContract(record.contract_terms) as FixtureRecord["taproot_contract"];
  for (const item of record.funding_history) {
    item.binding.contract_hash = record.contract_hash;
    item.binding.contract_script_pubkey = record.taproot_contract.script_pubkey;
    item.funder_session_signature = signDigest(fundingBindingHash(item.binding), clientSessionSecret);
  }
  return record;
}

export function fundedRecord(): FixtureRecord {
  const record = fixtureRecord();
  record.funding_history = [{ binding: {
    contract_hash: record.contract_hash, funding_attempt_id: "a".repeat(64), binding_revision: 0, funder_role: "client",
    lineage_anchor_txid: "b".repeat(64), lineage_anchor_vout: 1, funding_txid: "c".repeat(64), contract_vout: 0,
    contract_value_sat: record.contract_terms.economics.contract_amount_sat, contract_script_pubkey: record.taproot_contract.script_pubkey,
    replaces_txid: null, created_at: record.created_at,
  }, funder_session_signature: "0".repeat(128) }];
  return signRecord(record);
}

export function appendBinding(record: FixtureRecord): void {
  const previous = record.funding_history.at(-1)!;
  const revision = record.funding_history.length;
  const binding = { ...previous.binding, binding_revision: revision, funding_txid: (revision + 12).toString(16).padStart(64, "0"),
    replaces_txid: previous.binding.funding_txid };
  record.funding_history.push({ binding, funder_session_signature: signDigest(fundingBindingHash(binding), clientSessionSecret) });
}

/** Valid reservation against revision zero, retained even if later bindings are appended. */
export function reservedRecord(): FixtureRecord {
  const record = fundedRecord();
  const context = record.verification_context;
  context.handshake_init.required_features = ["cooperative-claim/v1", "epoch-bound-session/v1"];
  context.handshake_accept.required_features = ["cooperative-claim/v1", "epoch-bound-session/v1"];
  record.contract_terms.required_features = ["cooperative-claim/v1"];
  record.contract_terms.invoice_binding.payment_hash = bytesToHex(sha256(hexToBytes(testPreimage)));
  record.monotonic_knowledge = { ...record.monotonic_knowledge, preimage_known: true, preimage: testPreimage };
  signRecord(record);
  const plan = buildCooperativeClaimPlan(record.contract_terms as unknown as BtcToLnTerms,
    record.funding_history[0]!.binding, 100n);
  const proposal = { protocol: "rillswap", wire_version: "1", profile_id: "btc-to-ln/v1",
    network_identity: record.network_identity, session_id: context.handshake_init.session_id, message_id: "d".repeat(64),
    message_type: "action_request", sender_session_key: context.provider_session_xonly_key, in_reply_to: null,
    contract_hash: record.contract_hash, sequence: 1, required_features: ["cooperative-claim/v1"], extensions: {},
    payload: { action: "cooperative_claim_propose", cooperation_id: "e".repeat(64), payment_preimage: testPreimage,
      public_nonce: "0".repeat(132), unsigned_transaction: bytesToHex(plan.baseTransaction), deadline_at: 1,
      deadline_height: record.contract_terms.refund_lock_height - record.contract_terms.timing_policy.claim_confirmation_blocks },
    signature: "",
  };
  proposal.signature = signDigest(unsignedEnvelopeHash(proposal), providerSessionSecret);
  record.extensions = { "rillswap/cooperative-claim-reservation": { version: 1, proposal, signature_hash: bytesToHex(plan.signatureHash) } };
  return record;
}
