/** Synthetic public keys and outpoints only, never funded wallets. */
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { sha256 } from "@noble/hashes/sha2.js";
import type { LnToBtcTerms } from "../../src/swap/wire";
import { reconstructTaprootContract } from "../../src/swap/taproot";
import { parseTransaction, serializeTransaction } from "../../src/swap/transaction";
import { clientAcceptanceHash, contractHash, fundingBindingHash, handshakeAcceptHash, handshakeHash, handshakeInitHash, providerTermsHash } from "../../src/swap/hashes";
import { fundedRecord, signDigest, identitySecret, clientSessionSecret, providerSessionSecret, testPreimage, type FixtureRecord } from "./recoveryInspectionFixture";

type Mutable<T> = { -readonly [K in keyof T]: T[K] extends readonly (infer I)[] ? I[] : T[K] extends object ? Mutable<T[K]> : T[K] };
export type ReverseFixtureRecord = Omit<FixtureRecord, "contract_terms"> & { contract_terms: Mutable<LnToBtcTerms> };
export function signReverseRecord(record: ReverseFixtureRecord): void {
  const context = record.verification_context;
  context.handshake_accept.handshake_init_hash = bytesToHex(handshakeInitHash(context.handshake_init));
  context.provider_identity_signature = signDigest(handshakeAcceptHash(context.handshake_accept), identitySecret);
  context.handshake_hash = bytesToHex(handshakeHash(context.handshake_init, context.handshake_accept));
  record.contract_hash = bytesToHex(contractHash(record.contract_terms));
  context.provider_terms_signature = signDigest(providerTermsHash({ contract_hash: record.contract_hash, contract_terms: record.contract_terms, handshake_hash: context.handshake_hash }), identitySecret);
  context.client_acceptance_signature = signDigest(clientAcceptanceHash({ contract_hash: record.contract_hash, handshake_hash: context.handshake_hash,
    session_id: context.handshake_init.session_id, client_session_xonly_key: context.client_session_xonly_key, provider_session_xonly_key: context.provider_session_xonly_key }), clientSessionSecret);
  record.taproot_contract = reconstructTaprootContract(record.contract_terms);
  for (const item of record.funding_history) {
    item.binding.contract_hash = record.contract_hash; item.binding.contract_script_pubkey = record.taproot_contract.script_pubkey;
    item.funder_session_signature = signDigest(fundingBindingHash(item.binding), providerSessionSecret);
  }
}
export function reverseRecord(): ReverseFixtureRecord {
  const record = fundedRecord() as unknown as ReverseFixtureRecord, context = record.verification_context;
  record.profile_id = context.handshake_init.profile_id = context.handshake_accept.profile_id = "ln-to-btc/v1";
  context.handshake_init.required_features = context.handshake_accept.required_features = ["cooperative-claim/v1"];
  Object.assign(record.contract_terms, { profile_id: "ln-to-btc/v1", claimant: "client", refund_party: "provider", required_features: ["cooperative-claim/v1"],
    funding_confirmations: 1, max_claim_fee_sat: "1000", refund_lock_height: 220,
    economics: { kind: "ln-to-btc", contract_amount_sat: "51000", nominal_payout_sat: "50000", claim_fee_reserve_sat: "1000", success_fee_sat: "100", mining_prepayment_sat: "0", hold_invoice_sat: "51100" },
    timing_policy: { kind: "ln-to-btc", min_incoming_htlc_expiry_height: 240, refund_and_ln_resolution_blocks: 10, client_response_blocks: 2, claim_confirmation_blocks: 2 } });
  record.contract_terms.invoice_binding.amount_msat = "51100000";
  record.contract_terms.invoice_binding.payment_hash = bytesToHex(sha256(hexToBytes(testPreimage)));
  record.chain_scan_birthday_height = 100; record.fee_policy.max_claim_fee_sat = "1000";
  record.monotonic_knowledge = { preimage_known: true, preimage: testPreimage, dangerous_signature_issued: false };
  record.funding_history[0]!.binding.funder_role = "provider";
  record.funding_history[0]!.binding.contract_value_sat = "51000";
  signReverseRecord(record); return record;
}
export interface ReverseRecoveryCase {
  readonly name: string;
  readonly record: ReverseFixtureRecord;
  readonly expectedNetwork: unknown;
  readonly fundingTxHex: string;
  readonly fundingAttemptId: string;
  readonly bindingRevision: number;
  readonly tipHeight: number;
  readonly confirmations: number;
  readonly feeSat: string;
  readonly accepted: boolean;
}
export function reverseCase(name = "P2WPKH reverse claim", record = reverseRecord()): ReverseRecoveryCase {
  const binding = record.funding_history[0]!.binding;
  const raw = serializeTransaction({ version: 2, locktime: 0,
    inputs: [{ txid: binding.lineage_anchor_txid, vout: binding.lineage_anchor_vout, scriptSig: new Uint8Array(), sequence: 0xfffffffd, witness: [] }],
    outputs: [{ value: BigInt(binding.contract_value_sat), script: hexToBytes(binding.contract_script_pubkey) }, { value: 1000n, script: hexToBytes("0014" + "33".repeat(20)) }],
  }, true);
  binding.funding_txid = parseTransaction(raw).txid; signReverseRecord(record);
  return { name, record, expectedNetwork: record.network_identity, fundingTxHex: bytesToHex(raw), fundingAttemptId: binding.funding_attempt_id,
    bindingRevision: 0, tipHeight: 200, confirmations: 1, feeSat: "100", accepted: true };
}
export function reverseRecoveryCases(): ReverseRecoveryCase[] {
  const valid = reverseCase(), tr = reverseRecord(); tr.contract_terms.client_destination_script = "5120" + "22".repeat(32); signReverseRecord(tr);
  const malformedFunding = ["value", "lineage", "duplicate contract", "scriptSig", "nonstandard change"].map((kind) => {
    const item = reverseCase(`signed binding cannot authorize wrong funding ${kind}`), parsed = parseTransaction(hexToBytes(item.fundingTxHex));
    const transaction = { ...parsed, inputs: [...parsed.inputs], outputs: [...parsed.outputs] };
    if (kind === "value") transaction.outputs[0] = { ...transaction.outputs[0]!, value: 51001n };
    if (kind === "lineage") transaction.inputs[0] = { ...transaction.inputs[0]!, txid: "f".repeat(64) };
    if (kind === "duplicate contract") transaction.outputs.push({ ...transaction.outputs[0]! });
    if (kind === "scriptSig") transaction.inputs[0] = { ...transaction.inputs[0]!, scriptSig: hexToBytes("01ff") };
    if (kind === "nonstandard change") transaction.outputs[1] = { ...transaction.outputs[1]!, script: hexToBytes("6a01ff") };
    const raw = serializeTransaction(transaction, true);
    item.record.funding_history[0]!.binding.funding_txid = parseTransaction(raw).txid; signReverseRecord(item.record);
    return { ...item, fundingTxHex: bytesToHex(raw), accepted: false };
  });
  return [valid, reverseCase("P2TR reverse claim", tr), { ...reverseCase("zero fee"), feeSat: "0" }, { ...reverseCase("full reserve"), feeSat: "1000" },
    { ...reverseCase("last admitted height"), tipHeight: 218 },
    { ...reverseCase("claim margin exhausted"), tipHeight: 219, accepted: false },
    { ...reverseCase("fee cap exceeded"), feeSat: "1001", accepted: false },
    { ...reverseCase("fee negative"), feeSat: "-1", accepted: false },
    { ...reverseCase("insufficient funding depth"), confirmations: 0, accepted: false },
    { ...reverseCase("impossible funding depth"), confirmations: 202, accepted: false },
    { ...reverseCase("missing selected revision"), bindingRevision: 1, accepted: false },
    { ...reverseCase("foreign funding attempt"), fundingAttemptId: "f".repeat(64), accepted: false }, ...malformedFunding];
}
