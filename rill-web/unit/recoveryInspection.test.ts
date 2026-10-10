import { expect, test } from "bun:test";
import canonicalize from "canonicalize";
import { inspectRecoveryPlaintext, RecoveryInspectionRefusedError } from "../src/recoveryInspection";
import { recoveryInspectionCases } from "./fixtures/recoveryInspectionCases";
import { fixtureRecord, reservedRecord } from "./fixtures/recoveryInspectionFixture";

const bytes = (value: unknown): Uint8Array => new TextEncoder().encode(canonicalize(value)!);

for (const { name, record, accepted, expectedNetwork } of recoveryInspectionCases()) {
  test(`historical recovery: ${name}`, () => {
    const plaintext = bytes(record);
    const before = Uint8Array.from(plaintext);
    if (accepted) {
      const report = inspectRecoveryPlaintext(plaintext, expectedNetwork);
      expect(report.recordedBindingCount).toBe(record.funding_history.length);
      expect(report.firstRefundEligibleHeight).toBe(record.contract_terms.refund_lock_height + 1);
      expect(Object.isFrozen(report)).toBe(true);
      expect(report.verification).toBe("historical-static");
    } else expect(() => inspectRecoveryPlaintext(plaintext, expectedNetwork)).toThrow(RecoveryInspectionRefusedError);
    expect(plaintext).toEqual(before);
  });
}

test("reports expose only allowlisted public metadata, with no raw or nested secret-bearing object", () => {
  const record = reservedRecord();
  const report = inspectRecoveryPlaintext(bytes(record), record.network_identity);
  expect(Object.keys(report).sort()).toEqual(["contractHash", "firstRefundEligibleHeight", "fundingHistory", "networkName", "profileId", "recordedBindingCount", "refundLockHeight", "verification"]);
  for (const [key, value] of Object.entries(report)) if (key !== "fundingHistory") expect(["string", "number"].includes(typeof value)).toBe(true);
  expect(Object.isFrozen(report.fundingHistory)).toBe(true);
  expect(Object.isFrozen(report.fundingHistory[0])).toBe(true);
  expect(Object.keys(report.fundingHistory[0]!).sort()).toEqual(["binding_revision", "contract_hash", "contract_script_pubkey", "contract_value_sat", "contract_vout", "created_at", "funder_role", "funding_attempt_id", "funding_txid", "lineage_anchor_txid", "lineage_anchor_vout", "replaces_txid"]);
  expect(JSON.stringify(report)).not.toContain(record.user_secret.contract_secret_key);
  expect(JSON.stringify(report)).not.toContain(record.monotonic_knowledge.preimage!);
});

test("absent/invalid network expectations and malformed input fail redacted without causes or plaintext", () => {
  const record = fixtureRecord();
  for (const input of [new Uint8Array(), new TextEncoder().encode('private-error-canary'), bytes(record)]) {
    try { inspectRecoveryPlaintext(input, null); throw new Error("expected refusal"); }
    catch (error) {
      expect(error).toBeInstanceOf(RecoveryInspectionRefusedError);
      expect((error as Error).message).toBe("Recovery document could not be authenticated");
      expect(Object.hasOwn(error as object, "cause")).toBe(false);
      expect(JSON.stringify(error)).not.toContain("private-error-canary");
    }
  }
});
