/** Public synthetic recovery keys only. None of these outpoints are spendable funds. */
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import mainnet from "../../src/networks/mainnet.json" with { type: "json" };
import { buildCooperativeClaimPlan } from "../../src/swap/cooperative";
import { unsignedEnvelopeHash } from "../../src/swap/hashes";
import { parseTransaction, serializeTransaction, type Transaction } from "../../src/swap/transaction";
import {
  appendBinding, fundedRecord, moveToNetwork, providerSessionSecret, reservedRecord, signDigest, signRecord, type FixtureRecord,
} from "./recoveryInspectionFixture";

export interface RecoveryRefundCase {
  readonly name: string;
  readonly record: FixtureRecord;
  readonly expectedNetwork: unknown;
  readonly fundingTxHex: string;
  readonly fundingAttemptId: string;
  readonly bindingRevision: number;
  readonly tipHeight: number;
  readonly feeSat: string;
  readonly accepted: boolean;
}

type FundingTransaction = Pick<Transaction, "version" | "locktime"> & {
  inputs: Transaction["inputs"][number][];
  outputs: Transaction["outputs"][number][];
};
type Reservation = { proposal: { payload: Record<string, unknown>; signature: string }; signature_hash: string };

/** Retain any paid reservation against the same revision after assigning real synthetic bytes. */
function assignFundingBytes(record: FixtureRecord, transaction: FundingTransaction): string {
  const raw = serializeTransaction(transaction, true);
  const binding = record.funding_history[0]!.binding;
  binding.funding_txid = parseTransaction(raw).txid;
  signRecord(record);
  const marker = record.extensions["rillswap/cooperative-claim-reservation"] as Reservation | undefined;
  if (marker) {
    const plan = buildCooperativeClaimPlan(record.contract_terms, binding, 100n);
    marker.proposal.payload.unsigned_transaction = bytesToHex(plan.baseTransaction);
    marker.signature_hash = bytesToHex(plan.signatureHash);
    marker.proposal.signature = signDigest(unsignedEnvelopeHash(marker.proposal), providerSessionSecret);
  }
  return bytesToHex(raw);
}

export function refundCase(name = "P2WPKH refund", record = fundedRecord()): RecoveryRefundCase {
  const binding = record.funding_history[0]!.binding;
  const transaction: FundingTransaction = {
    version: 2, locktime: 0,
    inputs: [{ txid: binding.lineage_anchor_txid, vout: binding.lineage_anchor_vout, scriptSig: new Uint8Array(), sequence: 0xfffffffd, witness: [] }],
    outputs: [{ value: BigInt(binding.contract_value_sat), script: hexToBytes(binding.contract_script_pubkey) },
      { value: 1000n, script: hexToBytes("0014" + "33".repeat(20)) }],
  };
  const fundingTxHex = assignFundingBytes(record, transaction);
  return { name, record, fundingTxHex, fundingAttemptId: binding.funding_attempt_id, bindingRevision: 0,
    tipHeight: record.contract_terms.refund_lock_height + 1, feeSat: "100", expectedNetwork: record.network_identity, accepted: true };
}

const invalid = (name: string, edit: (item: RecoveryRefundCase) => RecoveryRefundCase | void): RecoveryRefundCase => {
  const item = refundCase(name);
  return { ...(edit(item) ?? item), accepted: false };
};

function changedFunding(name: string, edit: (tx: FundingTransaction, record: FixtureRecord) => void): RecoveryRefundCase {
  const item = refundCase(name);
  const parsed = parseTransaction(hexToBytes(item.fundingTxHex));
  const tx: FundingTransaction = { ...parsed, inputs: [...parsed.inputs], outputs: [...parsed.outputs] };
  edit(tx, item.record);
  return { ...item, fundingTxHex: assignFundingBytes(item.record, tx), accepted: false };
}

export function recoveryRefundCases(): RecoveryRefundCase[] {
  const p2tr = fundedRecord(); p2tr.contract_terms.client_destination_script = "5120" + "44".repeat(32); signRecord(p2tr);
  const main = fundedRecord(); moveToNetwork(main, mainnet); signRecord(main);
  const paid = reservedRecord(); paid.monotonic_knowledge.dangerous_signature_issued = true;
  const earlier = refundCase("explicit older revision selection"); appendBinding(earlier.record);
  const latest = structuredClone(earlier);
  const laterTx = parseTransaction(hexToBytes(latest.fundingTxHex));
  const laterRaw = serializeTransaction({ ...laterTx, locktime: 1 }, true);
  latest.record.funding_history[1]!.binding.funding_txid = parseTransaction(laterRaw).txid;
  signRecord(latest.record);
  const cases = [
    refundCase(), refundCase("P2TR refund", p2tr), refundCase("existing mainnet refund", main),
    refundCase("paid and reserved refund snapshot", paid), earlier,
    { ...latest, name: "explicit newest revision selection", fundingTxHex: bytesToHex(laterRaw), bindingRevision: 1 },
    { ...refundCase("zero fee permitted offline"), feeSat: "0" },
    { ...refundCase("signed fee cap inclusive"), feeSat: "600" },
    invalid("tip exactly at refund lock", (c) => ({ ...c, tipHeight: c.record.contract_terms.refund_lock_height })),
    invalid("tip below refund lock", (c) => ({ ...c, tipHeight: c.record.contract_terms.refund_lock_height - 1 })),
    invalid("wrong attempt selector", (c) => ({ ...c, fundingAttemptId: "f".repeat(64) })),
    invalid("wrong revision selector", (c) => ({ ...c, bindingRevision: 1 })),
    invalid("negative fee", (c) => ({ ...c, feeSat: "-1" })),
    invalid("over signed fee cap", (c) => ({ ...c, feeSat: "601" })),
    invalid("wrong independently selected network", (c) => ({ ...c, expectedNetwork: mainnet })),
    invalid("unselected history signature corrupted", (c) => { appendBinding(c.record); c.record.funding_history[1]!.funder_session_signature = "0".repeat(128); }),
    invalid("funding bytes differ from binding txid", (c) => {
      const tx = parseTransaction(hexToBytes(c.fundingTxHex)); return { ...c, fundingTxHex: bytesToHex(serializeTransaction({ ...tx, locktime: 1 }, true)) };
    }),
    invalid("funding vout nonexistent", (c) => { c.record.funding_history[0]!.binding.contract_vout = 2; signRecord(c.record); }),
    changedFunding("funding anchor absent", (tx) => { tx.inputs[0] = { ...tx.inputs[0]!, txid: "e".repeat(64) }; }),
    changedFunding("funding duplicate inputs", (tx) => { (tx.inputs as Transaction["inputs"][number][]).push(tx.inputs[0]!); }),
    changedFunding("funding nonempty scriptSig", (tx) => { tx.inputs[0] = { ...tx.inputs[0]!, scriptSig: Uint8Array.of(0x00) }; }),
    changedFunding("funding wrong contract value", (tx) => { tx.outputs[0] = { ...tx.outputs[0]!, value: 100999n }; }),
    changedFunding("funding wrong contract script", (tx) => { tx.outputs[0] = { ...tx.outputs[0]!, script: hexToBytes("5120" + "55".repeat(32)) }; }),
    changedFunding("funding duplicate contract outputs", (tx) => { (tx.outputs as Transaction["outputs"][number][]).push(tx.outputs[0]!); }),
    changedFunding("funding unsupported change script", (tx) => { tx.outputs[1] = { ...tx.outputs[1]!, script: Uint8Array.of(0x6a) }; }),
    changedFunding("funding aggregate exceeds money range", (tx) => { tx.outputs[1] = { ...tx.outputs[1]!, value: 2100000000000000n }; }),
  ];
  for (const [name, namespace, profile, accepted] of [
    ["another explicitly selected regtest namespace", "other-development", "bitcoin-core-v30.0-regtest-default", true],
    ["unsupported execution consensus profile", "rillswap-e2e-v1", "unknown-profile", false],
  ] as const) {
    const record = fundedRecord();
    moveToNetwork(record, { ...record.network_identity, deployment_namespace: namespace, consensus_profile: profile });
    signRecord(record);
    cases.push({ ...refundCase(name, record), accepted });
  }
  for (const [name, destination, dust] of [["P2WPKH", "0014" + "31".repeat(20), 294n], ["P2TR", "5120" + "44".repeat(32), 330n]] as const) {
    const record = fundedRecord(); record.contract_terms.client_destination_script = destination;
    record.contract_terms.max_refund_fee_sat = record.fee_policy.max_refund_fee_sat = "101000";
    signRecord(record);
    const boundary = refundCase(`${name} dust floor inclusive`, record);
    cases.push({ ...boundary, feeSat: (101000n - dust).toString() });
    cases.push({ ...structuredClone(boundary), name: `${name} below dust`, feeSat: (101000n - dust + 1n).toString(), accepted: false });
  }
  return cases;
}
