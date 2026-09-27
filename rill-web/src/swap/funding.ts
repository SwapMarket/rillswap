/**
 * Authorize the user's own funding transaction against signed terms, then
 * bind it (RS-003, BTC to LN, client funder). Nothing here broadcasts.
 */
import { bytesToHex } from "@noble/hashes/utils.js";

import { reconstructTaprootContract, type TaprootTermsInput } from "./taproot";
import { extractFinalizedPsbt, type FinalizedFunding, TransactionRefusedError } from "./transaction";

const P2WPKH = /^0014[0-9a-f]{40}$/;
const P2TR = /^5120[0-9a-f]{64}$/;

export interface FundingTermsInput extends TaprootTermsInput {
  readonly economics: { readonly contract_amount_sat: string };
  readonly max_funding_fee_sat: string;
}

export interface AuthorizedFunding {
  readonly txid: string;
  readonly raw: string;
  readonly contractVout: number;
  readonly contractScript: string;
  readonly contractValueSat: bigint;
  readonly feeSat: bigint;
  readonly anchor: { readonly txid: string; readonly vout: number };
}

export interface FundingBinding {
  readonly contract_hash: string;
  readonly funding_attempt_id: string;
  readonly binding_revision: 0;
  readonly funder_role: "client";
  readonly lineage_anchor_txid: string;
  readonly lineage_anchor_vout: number;
  readonly funding_txid: string;
  readonly contract_vout: number;
  readonly contract_value_sat: string;
  readonly contract_script_pubkey: string;
  readonly replaces_txid: null;
  readonly created_at: number;
}

/** Check the exact funding transaction the user's wallet signed. */
export function authorizeFunding(funding: FinalizedFunding, terms: FundingTermsInput): AuthorizedFunding {
  const { transaction, inputValues } = funding;
  const script = reconstructTaprootContract(terms).script_pubkey;
  const value = BigInt(terms.economics.contract_amount_sat);
  const outpoints = new Set(transaction.inputs.map((input) => `${input.txid}:${input.vout}`));
  if (outpoints.size !== transaction.inputs.length) throw new TransactionRefusedError("duplicate input");
  const contract = transaction.outputs.flatMap((output, index) =>
    bytesToHex(output.script) === script ? [index] : [],
  );
  if (contract.length !== 1) throw new TransactionRefusedError("exactly one contract output required");
  const vout = contract[0]!;
  if (transaction.outputs[vout]!.value !== value) {
    throw new TransactionRefusedError("contract output must carry exactly the contract amount");
  }
  for (const [index, output] of transaction.outputs.entries()) {
    const hex = bytesToHex(output.script);
    if (index !== vout && !P2WPKH.test(hex) && !P2TR.test(hex)) {
      throw new TransactionRefusedError("other outputs must be native P2WPKH or P2TR");
    }
  }
  const spent = inputValues.reduce((sum, item) => sum + item, 0n);
  const created = transaction.outputs.reduce((sum, output) => sum + output.value, 0n);
  const fee = spent - created;
  if (fee < 0n || fee > BigInt(terms.max_funding_fee_sat)) {
    throw new TransactionRefusedError("funding fee exceeds the signed maximum");
  }
  const anchor = transaction.inputs[0]!;
  return {
    txid: transaction.txid,
    raw: bytesToHex(transaction.raw),
    contractVout: vout,
    contractScript: script,
    contractValueSat: value,
    feeSat: fee,
    anchor: { txid: anchor.txid, vout: anchor.vout },
  };
}

/** Parse a finalized PSBT (base64 or hex) and authorize it. */
export function authorizeFundingPsbt(text: string, terms: FundingTermsInput): AuthorizedFunding {
  const trimmed = text.trim();
  let bytes: Uint8Array;
  if (/^[0-9a-fA-F]+$/.test(trimmed) && trimmed.length % 2 === 0) {
    bytes = Uint8Array.from(trimmed.match(/../g)!.map((pair) => Number.parseInt(pair, 16)));
  } else if (/^[A-Za-z0-9+/]+={0,2}$/.test(trimmed)) {
    bytes = Uint8Array.from(atob(trimmed), (char) => char.charCodeAt(0));
  } else {
    throw new TransactionRefusedError("paste a finalized PSBT in base64 or hex");
  }
  return authorizeFunding(extractFinalizedPsbt(bytes), terms);
}

export function fundingBinding(
  contractHash: string,
  funding: AuthorizedFunding,
  attemptId: string,
  createdAt: number,
): FundingBinding {
  if (!/^[0-9a-f]{64}$/.test(attemptId)) throw new Error("attempt id must be 32 bytes of hex");
  return {
    contract_hash: contractHash,
    funding_attempt_id: attemptId,
    binding_revision: 0,
    funder_role: "client",
    lineage_anchor_txid: funding.anchor.txid,
    lineage_anchor_vout: funding.anchor.vout,
    funding_txid: funding.txid,
    contract_vout: funding.contractVout,
    contract_value_sat: funding.contractValueSat.toString(),
    contract_script_pubkey: funding.contractScript,
    replaces_txid: null,
    created_at: createdAt,
  };
}
