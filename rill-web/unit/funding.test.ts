import { describe, expect, test } from "bun:test";

import { authorizeFundingPsbt, type FundingTermsInput, fundingBinding } from "../src/swap/funding";
import { TransactionRefusedError, parseTransaction } from "../src/swap/transaction";
import core from "./fixtures/funding-psbt-regtest.json";
import taproot from "./fixtures/taproot-cases-v1.json";

const vector = taproot.valid[0]!;
const terms = { ...vector.contract_terms, max_funding_fee_sat: "500" } as unknown as FundingTermsInput;
const hex = (text: string): Uint8Array => Uint8Array.from(text.match(/../g)!.map((pair) => Number.parseInt(pair, 16)));

describe("funding authorization against a Bitcoin Core PSBT", () => {
  test("the finalized PSBT extracts to Core's exact transaction", () => {
    const funding = authorizeFundingPsbt(core.finalized_psbt, terms);
    expect(funding.txid).toBe(core.txid);
    expect(funding.raw).toBe(core.hex);
    expect(funding.contractVout).toBe(core.contract_vout);
    expect(funding.feeSat).toBe(BigInt(core.fee_sat));
    expect(parseTransaction(hex(core.hex)).txid).toBe(core.txid);
    const binding = fundingBinding(vector.contract_hash, funding, "31".repeat(32), 1_700_000_100);
    expect(binding.contract_script_pubkey).toBe(vector.artifacts.script_pubkey);
    expect(binding.contract_value_sat).toBe("101000");
    expect(binding.lineage_anchor_txid).toMatch(/^[0-9a-f]{64}$/);
  });

  test("hex PSBT input is accepted too", () => {
    const bytes = Uint8Array.from(atob(core.finalized_psbt), (char) => char.charCodeAt(0));
    const asHex = Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
    expect(authorizeFundingPsbt(asHex, terms).txid).toBe(core.txid);
  });

  test("the signed fee cap, contract amount, and script bind the transaction", () => {
    expect(() => authorizeFundingPsbt(core.finalized_psbt, { ...terms, max_funding_fee_sat: "1" })).toThrow(
      TransactionRefusedError,
    );
    const otherAmount = { ...terms, economics: { ...terms.economics, contract_amount_sat: "101001" } };
    expect(() => authorizeFundingPsbt(core.finalized_psbt, otherAmount)).toThrow(TransactionRefusedError);
    const otherContract = { ...terms, refund_lock_height: 1101 };
    expect(() => authorizeFundingPsbt(core.finalized_psbt, otherContract)).toThrow(TransactionRefusedError);
  });

  test("raw transactions, trailing bytes, and other versions are refused", () => {
    expect(() => authorizeFundingPsbt(core.hex, terms)).toThrow(TransactionRefusedError);
    expect(() => parseTransaction(hex(`${core.hex}00`))).toThrow(TransactionRefusedError);
    expect(() => authorizeFundingPsbt("not a psbt!", terms)).toThrow(TransactionRefusedError);
    const version1 = `01${core.hex.slice(2)}`;
    expect(() => parseTransaction(hex(version1))).toThrow(TransactionRefusedError);
  });
});
