import { expect, test } from "bun:test";
import { invoiceBinding } from "../src/bolt11";
import { validateLnurlPayInvoice, type LnurlInvoiceExpectation, type LnurlPayDescriptor } from "../src/lnurlPay";
import { receiver, testInvoice } from "./helpers";

const metadata = '[["text/plain","Receiver"],["text/identifier","buyer@receiver.example"]]';
const descriptor: LnurlPayDescriptor = { version: "lnurl-pay-request/1", lightningAddress: "buyer@receiver.example", receiverOrigin: "https://receiver.example",
  callback: "https://receiver.example/invoice", metadata, description: "Receiver", minSendableMsat: "1", maxSendableMsat: "1000000" };
const expected: LnurlInvoiceExpectation = { networkName: "regtest", amountMsat: "1000000", payee: receiver, now: 1000, minExpiresAt: 2000, metadataHashPolicy: "not_required" };
const signed = testInvoice("lnurl-response");
const response = { pr: signed, routes: [] };

test("modern unhashed invoice matches independent pins with inclusive minimum expiry", () => {
  const result = validateLnurlPayInvoice(descriptor, response, expected);
  expect(result.invoice).toBe(signed); expect(result.binding).toEqual(invoiceBinding(signed, "regtest"));
  expect(Object.keys(result)).toEqual(["invoice", "binding", "metadataHashPolicy"]);
  expect(Object.keys(result.binding).length).toBe(7); expect(result.metadataHashPolicy).toBe("not_required");
  expect(Object.isFrozen(result) && Object.isFrozen(result.binding)).toBe(true);
});

test("independent payee, amount, distinguishable currency and lifetime pins are mandatory", () => {
  for (const change of [{ payee: "03" + "ab".repeat(32) }, { amountMsat: "999000" }, { networkName: "mainnet" },
    { now: 999 }, { now: 2000, minExpiresAt: 2001 }, { minExpiresAt: 2001 }]) {
    expect(() => validateLnurlPayInvoice(descriptor, response, { ...expected, ...change })).toThrow("unresolved");
  }
  expect(() => validateLnurlPayInvoice(descriptor, { pr: testInvoice("future", "1000000", 1001), routes: [] }, expected)).toThrow("unresolved");
});

test("testnet3 and testnet4 share BOLT11 currency and need independent rail configuration", () => {
  const testnet = { pr: testInvoice("testnet", "1000000", 1000, 2000, "tb"), routes: [] };
  for (const networkName of ["testnet3", "testnet4"]) {
    expect(validateLnurlPayInvoice(descriptor, testnet, { ...expected, networkName }).binding.payee_compressed_pubkey).toBe(receiver);
  }
  expect(() => validateLnurlPayInvoice(descriptor, testnet, { ...expected, networkName: "signet" })).toThrow("unresolved");
});

test("metadata hash policy is explicit and strict matching does not alter ordinary admission", () => {
  const strict = { ...expected, metadataHashPolicy: "strict_hash" as const };
  expect(() => validateLnurlPayInvoice(descriptor, response, strict)).toThrow("unresolved");
  const hashed = { pr: testInvoice("strict", "1000000", 1000, 2000, "bcrt", undefined, metadata), routes: [] };
  const result = validateLnurlPayInvoice(descriptor, hashed, strict);
  expect(result.binding).toEqual(invoiceBinding(hashed.pr, "regtest")); expect(result.metadataHashPolicy).toBe("strict_hash");
  expect(() => validateLnurlPayInvoice({ ...descriptor, metadata: metadata + " " }, hashed, strict)).toThrow("unresolved");
  expect(validateLnurlPayInvoice({ ...descriptor, metadata: metadata + " " }, hashed, expected).invoice).toBe(hashed.pr);
});

test("malformed expected scalar values never become implicit policies or prices", () => {
  for (const change of [{ amountMsat: "0" }, { amountMsat: "01000000" }, { amountMsat: "1000001" }, { amountMsat: "2100000000000000001" },
    { amountMsat: 1000000 }, { payee: receiver.toUpperCase() }, { payee: "private-value" }, { networkName: "__proto__" },
    { now: NaN }, { now: -1 }, { now: 1000.5 }, { minExpiresAt: 1000 }, { minExpiresAt: Number.MAX_SAFE_INTEGER + 1 },
    { metadataHashPolicy: undefined }, { metadataHashPolicy: true }, { metadataHashPolicy: "strict" }]) {
    expect(() => validateLnurlPayInvoice(descriptor, response, { ...expected, ...change } as LnurlInvoiceExpectation)).toThrow("unresolved");
  }
});

test("descriptor facts are validated without treating origin or claimed identity as authority", () => {
  for (const change of [{ version: "old" }, { minSendableMsat: "1000001" }, { maxSendableMsat: "999000" }, { maxSendableMsat: "9007199254740992" },
    { minSendableMsat: "0" }, { maxSendableMsat: "01" }, { metadata: "x".repeat(16385) }, { metadata: "\ud800" }]) {
    expect(() => validateLnurlPayInvoice({ ...descriptor, ...change } as LnurlPayDescriptor, response, expected)).toThrow("unresolved");
  }
  const untrustedClaim = { ...descriptor, metadata: '[["text/plain","x"],["text/identifier","someone-else"]]' };
  expect(validateLnurlPayInvoice(untrustedClaim, response, expected).binding.payee_compressed_pubkey).toBe(receiver);
  expect(() => validateLnurlPayInvoice(null as unknown as LnurlPayDescriptor, response, expected)).toThrow("unresolved");
});

test("missing or nonempty routes, errors and malformed invoices refuse without private context", () => {
  for (const value of [null, [], {}, { pr: signed }, { pr: signed, routes: null }, { pr: signed, routes: ["hint"] },
    { pr: "PRIVATE_INVALID_INVOICE_CANARY", routes: [] }, { ...response, status: "ERROR", reason: "PRIVATE_REASON_CANARY" }]) {
    try { validateLnurlPayInvoice(descriptor, value, expected); throw new Error("must refuse"); }
    catch (error) { expect((error as Error).message).toBe("LNURL invoice response is unresolved"); expect((error as Error).cause).toBeUndefined(); }
  }
});

test("verification and success-action extensions are never accessed or returned", () => {
  const supplied = { ...response };
  for (const field of ["verify", "successAction", "disposable"]) {
    Object.defineProperty(supplied, field, { get() { throw new Error("PRIVATE_EXTENSION_CANARY"); }, enumerable: true });
  }
  expect(validateLnurlPayInvoice(descriptor, supplied, expected)).toEqual(validateLnurlPayInvoice(descriptor, response, expected));
});

test("the selected policy is captured once, never upgraded by a changing getter", () => {
  let reads = 0;
  const dynamic = { ...expected };
  Object.defineProperty(dynamic, "metadataHashPolicy", { get() { return reads++ === 0 ? "not_required" : "strict_hash"; } });
  expect(validateLnurlPayInvoice(descriptor, response, dynamic).metadataHashPolicy).toBe("not_required"); expect(reads).toBe(1);
});
