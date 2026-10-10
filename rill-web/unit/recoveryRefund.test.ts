import { expect, spyOn, test } from "bun:test";
import canonicalize from "canonicalize";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { schnorr } from "@noble/curves/secp256k1.js";
import {
  constructSelectedRecoveryRefund, inspectRecoveryPlaintext, verifySelectedRecoveryRefund, RecoveryRefundRefusedError, type SelectedRecoveryRefundInput,
} from "../src/recoveryInspection";
import { parseTransaction, serializeTransaction } from "../src/swap/transaction";
import { recoveryRefundCases, refundCase, type RecoveryRefundCase } from "./fixtures/recoveryRefundCases";

const plaintext = (c: RecoveryRefundCase): Uint8Array => new TextEncoder().encode(canonicalize(c.record)!);
const input = (c: RecoveryRefundCase): SelectedRecoveryRefundInput => ({ fundingAttemptId: c.fundingAttemptId,
  bindingRevision: c.bindingRevision, rawFundingTransaction: hexToBytes(c.fundingTxHex), sampledTipHeight: c.tipHeight, feeSat: BigInt(c.feeSat) });

for (const item of recoveryRefundCases()) {
  test(`offline refund: ${item.name}`, () => {
    const sign = spyOn(schnorr, "sign");
    const bytes = plaintext(item), before = Uint8Array.from(bytes), args = input(item), rawBefore = Uint8Array.from(args.rawFundingTransaction);
    try {
      if (item.accepted) {
        const result = constructSelectedRecoveryRefund(bytes, item.expectedNetwork, args);
        expect(Object.isFrozen(result)).toBe(true);
        const parsed = parseTransaction(hexToBytes(result.transactionHex));
        expect(parsed.txid).toBe(result.txid);
        expect(parsed.locktime).toBe(item.record.contract_terms.refund_lock_height);
        expect(parsed.inputs).toHaveLength(1); expect(parsed.outputs).toHaveLength(1);
        expect(parsed.inputs[0]!.txid).toBe(item.record.funding_history[item.bindingRevision]!.binding.funding_txid);
        expect(parsed.inputs[0]!.sequence).toBe(0xfffffffd);
        expect(parsed.inputs[0]!.scriptSig).toHaveLength(0);
        expect(parsed.inputs[0]!.witness.map((part) => part.length)).toEqual([64, hexToBytes(item.record.taproot_contract.refund_script).length, 65]);
        expect(bytesToHex(parsed.inputs[0]!.witness[1]!)).toBe(item.record.taproot_contract.refund_script);
        expect(bytesToHex(parsed.inputs[0]!.witness[2]!)).toBe(item.record.taproot_contract.refund_control_block);
        expect(bytesToHex(parsed.outputs[0]!.script)).toBe(item.record.contract_terms.client_destination_script);
        expect(parsed.outputs[0]!.value).toBe(BigInt(item.record.contract_terms.economics.contract_amount_sat) - BigInt(item.feeSat));
        expect(sign).toHaveBeenCalledTimes(1);
      } else {
        expect(() => constructSelectedRecoveryRefund(bytes, item.expectedNetwork, args)).toThrow(RecoveryRefundRefusedError);
        expect(sign).not.toHaveBeenCalled();
      }
      expect(bytes).toEqual(before); expect(args.rawFundingTransaction).toEqual(rawBefore);
    } finally { sign.mockRestore(); }
  });
}

test("refund runtime inputs fail closed before signing, with generic errors", () => {
  const item = refundCase(), args = input(item), bytes = plaintext(item);
  const sign = spyOn(schnorr, "sign");
  try {
    for (const change of [
      { bindingRevision: true }, { bindingRevision: -1 }, { bindingRevision: 0.5 }, { bindingRevision: 64 },
      { sampledTipHeight: true }, { sampledTipHeight: NaN }, { sampledTipHeight: 1101.5 }, { sampledTipHeight: 500000000 },
      { feeSat: 100 }, { feeSat: "100" }, { feeSat: 2100000000000001n }, { fundingAttemptId: null },
      { rawFundingTransaction: new Uint8Array(100001) }, { rawFundingTransaction: new Uint8Array() }, { rawFundingTransaction: "00" },
    ]) {
      expect(() => constructSelectedRecoveryRefund(bytes, item.expectedNetwork, { ...args, ...change } as SelectedRecoveryRefundInput)).toThrow(RecoveryRefundRefusedError);
    }
    expect(sign).not.toHaveBeenCalled();
  } finally { sign.mockRestore(); }
});

test("inspection never signs, and the constructor never accesses network or storage or logs", () => {
  const item = refundCase();
  const sign = spyOn(schnorr, "sign"), fetch = spyOn(globalThis, "fetch");
  const logs = [spyOn(console, "log"), spyOn(console, "warn"), spyOn(console, "error")];
  try {
    inspectRecoveryPlaintext(plaintext(item), item.expectedNetwork);
    expect(sign).not.toHaveBeenCalled();
    constructSelectedRecoveryRefund(plaintext(item), item.expectedNetwork, input(item));
    expect(fetch).not.toHaveBeenCalled(); for (const log of logs) expect(log).not.toHaveBeenCalled();
  } finally { sign.mockRestore(); fetch.mockRestore(); for (const log of logs) log.mockRestore(); }
});

test("randomness failure and signer/verification failures expose no underlying details or causes", () => {
  const item = refundCase();
  const assertRedacted = (): void => {
    try { constructSelectedRecoveryRefund(plaintext(item), item.expectedNetwork, input(item)); throw new Error("expected refusal"); }
    catch (error) {
      expect(error).toBeInstanceOf(RecoveryRefundRefusedError);
      expect((error as Error).message).toBe("Recovery refund construction refused");
      expect(Object.hasOwn(error as object, "cause")).toBe(false);
      expect(JSON.stringify(error)).not.toContain("private-error-canary");
    }
  };
  const sign = spyOn(schnorr, "sign");
  const rng = spyOn(crypto, "getRandomValues").mockImplementation(() => { throw new Error("private-error-canary"); });
  try { assertRedacted(); expect(sign).not.toHaveBeenCalled(); } finally { rng.mockRestore(); sign.mockRestore(); }
  const signer = spyOn(schnorr, "sign").mockImplementation(() => { throw new Error("private-error-canary"); });
  try { assertRedacted(); } finally { signer.mockRestore(); }
  const verifier = spyOn(schnorr, "verify");
  // Retain admission verification, fail only after signing.
  const original = schnorr.sign;
  const afterSign = spyOn(schnorr, "sign").mockImplementation((...args) => { const signed = original(...args); verifier.mockReturnValue(false); return signed; });
  try { assertRedacted(); } finally { verifier.mockRestore(); afterSign.mockRestore(); }
});

test("refund results expose only allowlisted primitives and signing owns its snapshots", () => {
  const item = refundCase(), bytes = plaintext(item), args = input(item);
  const originalRng = crypto.getRandomValues.bind(crypto);
  const rng = spyOn(crypto, "getRandomValues").mockImplementation((array: Uint8Array) => {
    bytes.fill(0); args.rawFundingTransaction.fill(0);
    (args as { feeSat: bigint }).feeSat = 0n;
    (item.expectedNetwork as Record<string, unknown>).genesis_hash = "f".repeat(64);
    return originalRng(array);
  });
  try {
    const result = constructSelectedRecoveryRefund(bytes, item.expectedNetwork, args);
    expect(result.feeSat).toBe("100");
    expect(result.outputValueSat).toBe("100900");
    expect(Object.keys(result).sort()).toEqual(["contractHash", "destinationScript", "feeSat", "fundingTxid", "fundingVout", "outputValueSat", "refundLockHeight", "transactionHex", "txid", "vsize"]);
    for (const value of Object.values(result)) expect(["string", "number"].includes(typeof value)).toBe(true);
    expect(JSON.stringify(result)).not.toContain(item.record.user_secret.contract_secret_key);
  } finally { rng.mockRestore(); }
});

test("stored refunds are independently reauthorized without signing, randomness, or a current unspent claim", () => {
  for (const item of recoveryRefundCases().filter((item) => item.accepted)) {
    const document = plaintext(item), args = input(item), signed = constructSelectedRecoveryRefund(document, item.expectedNetwork, args);
    const sign = spyOn(schnorr, "sign"), rng = spyOn(crypto, "getRandomValues");
    try {
      const checked = verifySelectedRecoveryRefund(document, item.expectedNetwork, args, args.rawFundingTransaction, hexToBytes(signed.transactionHex));
      expect(checked).toEqual(signed); expect(sign).not.toHaveBeenCalled(); expect(rng).not.toHaveBeenCalled();
      const parsed = parseTransaction(hexToBytes(signed.transactionHex));
      const alternatives = [
        { ...parsed, locktime: parsed.locktime - 1 },
        { ...parsed, outputs: [{ ...parsed.outputs[0]!, value: parsed.outputs[0]!.value - 1n }] },
        { ...parsed, inputs: [{ ...parsed.inputs[0]!, sequence: 0xffffffff }] },
        { ...parsed, inputs: [{ ...parsed.inputs[0]!, witness: [new Uint8Array(64), ...parsed.inputs[0]!.witness.slice(1)] }] },
        { ...parsed, outputs: [{ ...parsed.outputs[0]!, script: hexToBytes("0014" + "66".repeat(20)) }] },
      ];
      for (const altered of alternatives) expect(() => verifySelectedRecoveryRefund(document, item.expectedNetwork, args, args.rawFundingTransaction, serializeTransaction(altered, true))).toThrow(RecoveryRefundRefusedError);
    } finally { sign.mockRestore(); rng.mockRestore(); }
  }
});
