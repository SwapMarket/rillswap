import { expect, test } from "bun:test";
import canonicalize from "canonicalize";
import fixture from "./fixtures/initial-btc-to-ln-v1.json";
import { parseRecoveryPlaintext, RecoveryDocumentRefusedError } from "../src/recoveryDocument";
import { MAX_RECOVERY_PLAINTEXT_BYTES } from "../src/recoveryAgeContainer";

const encoder = new TextEncoder();
const text = canonicalize(fixture)!;
const bytes = (value: unknown): Uint8Array => encoder.encode(canonicalize(value)!);

test("a legacy, expired RS-007 vector is admitted as secret-bearing unverified data only", () => {
  const parsed = parseRecoveryPlaintext(encoder.encode(text));
  expect(parsed.authentication).toBe("unverified");
  expect(parsed.document.format).toBe("rillswap-recovery");
  expect((parsed.document.contract_terms as { required_features: unknown[] }).required_features).toEqual([]);
  expect(Object.isFrozen(parsed)).toBe(true);
  const allFrozen = (value: unknown): boolean => !value || typeof value !== "object" ||
    (Object.isFrozen(value) && Object.values(value).every(allFrozen));
  expect(allFrozen(parsed.document)).toBe(true);
  const tampered = structuredClone(fixture);
  tampered.verification_context.provider_identity_signature = "0".repeat(128);
  expect(parseRecoveryPlaintext(bytes(tampered)).authentication).toBe("unverified");
});

test("original bytes must equal JCS exactly, including BOM, ordering, escapes, and negative zero", () => {
  const variants = [" " + text, text + "\n", JSON.stringify(fixture, null, 2),
    text.replace('"rillswap-recovery"', '"\\u0072illswap-recovery"'),
    text.replace('"created_at":1700000100', '"created_at":1700000100.0'),
    text.replace('"created_at":1700000100', '"created_at":1700000100e0')];
  for (const raw of variants) expect(() => parseRecoveryPlaintext(encoder.encode(raw))).toThrow(RecoveryDocumentRefusedError);
  expect(() => parseRecoveryPlaintext(new Uint8Array([0xef, 0xbb, 0xbf, ...encoder.encode(text)]))).toThrow(RecoveryDocumentRefusedError);
  const negativeZero = text.replace('"extensions":{}', '"extensions":{"x/zero":-0}');
  expect(() => parseRecoveryPlaintext(encoder.encode(negativeZero))).toThrow(RecoveryDocumentRefusedError);
});

test("JCS key ordering follows UTF-16, including supplementary Unicode", () => {
  const value = { ...fixture, extensions: { "x/ordering": { "\uffff": 1, "😀": 2 } } };
  const canonical = canonicalize(value)!;
  expect(canonical).toContain('{"😀":2,"\uffff":1}');
  expect(parseRecoveryPlaintext(encoder.encode(canonical)).authentication).toBe("unverified");
  expect(() => parseRecoveryPlaintext(encoder.encode(canonical.replace('{"😀":2,"\uffff":1}', '{"\uffff":1,"😀":2}')))).toThrow();
});

test("byte limits are inclusive and malformed UTF-8 is never replaced", () => {
  const pads = Array<string>(8).fill("");
  const value = { ...fixture, extensions: { "x/pad": pads } };
  let remaining = MAX_RECOVERY_PLAINTEXT_BYTES - bytes(value).length;
  for (let i = 0; i < pads.length; i++) { const size = Math.min(remaining, 16 * 1024); pads[i] = "x".repeat(size); remaining -= size; }
  expect(remaining).toBe(0);
  const atLimit = bytes(value);
  expect(atLimit.length).toBe(MAX_RECOVERY_PLAINTEXT_BYTES);
  expect(parseRecoveryPlaintext(atLimit).authentication).toBe("unverified");
  const over = new Uint8Array(atLimit.length + 1); over.set(atLimit); over[over.length - 1] = 32;
  for (const input of [over, new Uint8Array(), new Uint8Array([0xc0, 0xaf]), new Uint8Array([0xff])]) {
    expect(() => parseRecoveryPlaintext(input)).toThrow(RecoveryDocumentRefusedError);
  }
});

test("closed schema and version rules reject extra properties or malformed required fields", () => {
  for (const value of [{ ...fixture, format_version: "2" }, { ...fixture, extra: true }, { ...fixture, contract_hash: "invalid" },
    { ...fixture, user_secret: {} }, { ...fixture, network_identity: {} }, { ...fixture, extensions: { "bad-name": {} } }]) {
    expect(() => parseRecoveryPlaintext(bytes(value))).toThrow(RecoveryDocumentRefusedError);
  }
  const missing = structuredClone(fixture) as Record<string, unknown>; delete missing.contract_terms;
  expect(() => parseRecoveryPlaintext(bytes(missing))).toThrow(RecoveryDocumentRefusedError);
});

test("recognized extension shapes are enforced without granting historical action authority", () => {
  const extension = { version: 1, funding_binding_hash: "a".repeat(64), transaction: "00" };
  const value = (data: unknown) => ({ ...fixture, extensions: { "rillswap/reverse-claim-fallback": data } });
  // Even this shape-valid, semantically inappropriate one-byte transaction is only unverified data.
  expect(parseRecoveryPlaintext(bytes(value(extension))).authentication).toBe("unverified");
  for (const invalid of [{ ...extension, version: 2 }, { ...extension, transaction: "0" },
    { ...extension, funding_binding_hash: "bad" }, { ...extension, extra: true }]) {
    expect(() => parseRecoveryPlaintext(bytes(value(invalid)))).toThrow(RecoveryDocumentRefusedError);
  }
});

test("the recovery schema shares Core's key and scalar depth boundary", () => {
  const nested = (scalar: boolean) => JSON.parse("[".repeat(15) + (scalar ? "0" : "") + "]".repeat(15));
  expect(parseRecoveryPlaintext(bytes({ ...fixture, extensions: { "x/depth": nested(false) } })).authentication).toBe("unverified");
  expect(() => parseRecoveryPlaintext(bytes({ ...fixture, extensions: { "x/depth": nested(true) } }))).toThrow(RecoveryDocumentRefusedError);
});

test("duplicate/unsafe JSON and all boundary errors are generic and redact input-bearing details", () => {
  for (const raw of [text.replace('"created_at":1700000100', '"created_at":1700000100,"created_at":1700000100'),
    text.replace('"created_at":1700000100', '"created_at":9007199254740992'),
    text.replace('"format":"rillswap-recovery"', '"format":"private-error-canary"')]) {
    try { parseRecoveryPlaintext(encoder.encode(raw)); throw new Error("should refuse"); }
    catch (error) {
      expect(error).toBeInstanceOf(RecoveryDocumentRefusedError);
      expect((error as Error).message).toBe("Recovery document could not be parsed");
      expect(Object.hasOwn(error as object, "cause")).toBe(false);
      expect(JSON.stringify(error)).not.toContain("private-error-canary");
    }
  }
});

test("hostile extension property names remain frozen data without prototype mutation", () => {
  const hostile = JSON.parse('{"__proto__":{"polluted":true},"constructor":{"prototype":{"polluted":true}}}');
  const parsed = parseRecoveryPlaintext(bytes({ ...fixture, extensions: { "x/hostile": hostile } }));
  const extensions = parsed.document.extensions as Record<string, object>;
  expect(Object.hasOwn(extensions["x/hostile"]!, "__proto__")).toBe(true);
  expect(Object.getPrototypeOf(extensions["x/hostile"]!)).toBe(Object.prototype);
  expect(({} as Record<string, unknown>).polluted).toBeUndefined();
  expect(Object.isFrozen(extensions["x/hostile"])).toBe(true);
});
