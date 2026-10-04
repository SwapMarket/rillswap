import { afterEach, expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { resolve } from "node:path";
import { MerchantLedger, type ReceiptObservation } from "../src/merchant";
import { createMerchantService, verifyAcceptance } from "../src/server";
import { createCheckout, type CheckoutCheckpoint, type CheckoutStore, type IntentView } from "../src/sdk";
import { receiver, testInvoice } from "./helpers";
import { ed25519 } from "@noble/curves/ed25519.js";
import { bytesToHex } from "@noble/hashes/utils.js";

const cleanups: (() => void)[] = []; afterEach(() => { for (const cleanup of cleanups.splice(0)) cleanup(); });
async function fixture() {
  mkdirSync("tmp", { recursive: true }); const directory = mkdtempSync(resolve("tmp/service-"));
  const identity = { origin: "https://merchant.example", receiver, network: "regtest" as const, issuerId: "fixture" };
  const ledger = MerchantLedger.provision(directory + "/ledger", identity);
  cleanups.push(() => { ledger.close(); rmSync(directory, { recursive: true, force: true }); });
  let paid = false;
  const issuer = { identity: async () => identity, create: async (op: { operationId: string }) => testInvoice(op.operationId) };
  const observer = { identity: async () => identity, lookup: async (paymentHash: string): Promise<ReceiptObservation> => ({
    receiver, network: "regtest", paymentHash, invoiceAmountMsat: "1000000", paidMsat: paid ? "1000000" : "0", state: paid ? "SETTLED" : "OPEN", settledAt: paid ? 1200 : null,
  }) };
  const adminToken = "a".repeat(43);
  const service = createMerchantService({ ledger, issuer, observer, adminToken, statusKey: new Uint8Array(32).fill(2), eventSigningKey: new Uint8Array(32).fill(3), now: () => 1200 });
  const call = (path: string, token = adminToken, method = "GET", input?: unknown) => service.fetch(new Request(identity.origin + path, {
    method, headers: { Authorization: "Bearer " + token, "Content-Type": "application/json", "Idempotency-Key": "integration-key-0001" }, body: input === undefined ? undefined : JSON.stringify(input),
  }));
  const created = await (await call("/v1/intents", adminToken, "POST", { orderRef: "order", amountMsat: "1000000", expiresAt: 2000 })).json() as IntentView & { statusToken: string };
  await call(`/v1/intents/${created.id}/attempts`, adminToken, "POST", {});
  const rows = new Map<string, CheckoutCheckpoint>();
  const store: CheckoutStore = { load: async (id) => rows.get(id) ?? null,
    begin: async (record) => { if (rows.has(record.attemptId)) return false; rows.set(record.attemptId, structuredClone(record)); return true; },
    update: async (record) => { rows.set(record.attemptId, structuredClone(record)); } };
  const options = { intentUrl: `${identity.origin}/v1/intents/${created.id}`, statusToken: created.statusToken,
    policy: { version: "native-lightning/1" as const, merchantOrigin: identity.origin, receiver, network: "regtest" as const, maxBuyerExtraMsat: "100000", maxBuyerExtraBps: 1000 },
    recoveryStore: store, now: () => 1200,
    fetch: (input: RequestInfo | URL, init?: RequestInit) => service.fetch(new Request(input, init)) };
  return { service, ledger, call, created, adminToken, options, rows, expectedPublicKey: bytesToHex(ed25519.getPublicKey(new Uint8Array(32).fill(3))), settle: () => { paid = true; } };
}
test("status capabilities cannot set price, create attempts or fulfill using evidence", async () => {
  const f = await fixture(), url = `/v1/intents/${f.created.id}`;
  expect((await f.call("/v1/intents", f.created.statusToken, "POST", { orderRef: "attacker", amountMsat: "1000", expiresAt: 2000 })).status).toBe(401);
  expect((await f.call(url + "/attempts", f.created.statusToken, "POST", {})).status).toBe(403);
  expect((await f.call(url, "invalid")).status).toBe(404);
  await f.call(url + "/evidence", f.created.statusToken, "POST", { paid: true, preimage: "forged" });
  expect(f.ledger.getIntent(f.created.id).status).toBe("waiting"); expect(f.ledger.pendingEvents()).toHaveLength(0);
});
test("native SDK and merchant settlement integration never trusts wallet success", async () => {
  const f = await fixture(); let calls = 0; const progress: string[] = [];
  const checkout = createCheckout({ ...f.options, wallet: { canLimitFees: true, payInvoice: async (_invoice, fee) => { expect(fee).toBe("100000"); calls++; } } });
  checkout.on("progress", (event) => progress.push(event.state)); await checkout.open(); await checkout.pay();
  expect(calls).toBe(1); expect(progress).not.toContain("merchant_paid");
  expect((await checkout.open()).status).toBe("waiting");
  await expect(checkout.pay()).rejects.toThrow("already dispatched");
  f.settle(); await f.service.tick(); expect((await checkout.open()).status).toBe("paid"); expect(progress.at(-1)).toBe("merchant_paid");
  const event = (await (await f.call(`/v1/intents/${f.created.id}/events`, f.created.statusToken)).json())[0];
  expect(verifyAcceptance(event, f.expectedPublicKey)).toBe(true);
  expect(verifyAcceptance(event, bytesToHex(ed25519.getPublicKey(new Uint8Array(32).fill(4))))).toBe(false);
  expect(verifyAcceptance({ ...event, event: { ...event.event, amountMsat: "2000000" } }, f.expectedPublicKey)).toBe(false);
  expect(verifyAcceptance({ ...event, event: { ...event.event, extra: "unsigned" } }, f.expectedPublicKey)).toBe(false);
  let deliveries = 0;
  await expect(f.service.deliverEvents(async () => { deliveries++; throw new Error("ack lost"); })).rejects.toThrow();
  expect(f.ledger.pendingEvents()).toHaveLength(1);
  await f.service.deliverEvents(async (retry) => { deliveries++; expect(retry.event.id).toBe(event.event.id); });
  expect(deliveries).toBe(2); expect(f.ledger.pendingEvents()).toHaveLength(0);
});
test("two checkout instances reserve one dispatch, and a new instance resumes without paying", async () => {
  const f = await fixture(); let calls = 0; const wallet = { canLimitFees: true as const, payInvoice: async () => { calls++; } };
  const first = createCheckout({ ...f.options, wallet }), second = createCheckout({ ...f.options, wallet });
  const results = await Promise.allSettled([first.pay(), second.pay()]);
  expect(results.filter((x) => x.status === "fulfilled")).toHaveLength(1); expect(calls).toBe(1);
  const resumed = createCheckout({ ...f.options, wallet, now: () => 2100 }); const progress: string[] = [];
  resumed.on("progress", (event) => progress.push(event.state)); await resumed.open(); expect(progress).toEqual(["observing"]);
  await expect(resumed.pay()).rejects.toThrow("expired"); expect(calls).toBe(1);
});
test("ambiguous wallet failure persists and cannot authorize a second payment", async () => {
  const f = await fixture(); let calls = 0;
  const checkout = createCheckout({ ...f.options, wallet: { canLimitFees: true, payInvoice: async () => { calls++; throw new Error("response lost"); } } });
  await expect(checkout.pay()).rejects.toThrow(); expect([...f.rows.values()][0]?.stage).toBe("ambiguous");
  await expect(checkout.pay()).rejects.toThrow("already dispatched"); expect(calls).toBe(1);
});
test("expiry is rechecked after the durable checkpoint and invalid invoice never reaches wallet", async () => {
  const f = await fixture(); let now = 1200, calls = 0;
  const store: CheckoutStore = { ...f.options.recoveryStore, begin: async (record) => { await f.options.recoveryStore.begin(record); now = 2000; return true; } };
  const checkout = createCheckout({ ...f.options, now: () => now, recoveryStore: store, wallet: { canLimitFees: true, payInvoice: async () => { calls++; } } });
  await expect(checkout.pay()).rejects.toThrow("expired"); expect(calls).toBe(0);
  const invalid = createCheckout({ ...f.options, wallet: { canLimitFees: true, payInvoice: async () => { calls++; } },
    fetch: async () => { const view = await (await f.call(`/v1/intents/${f.created.id}`)).json(); view.attempt.invoice = testInvoice("wrong", "2000000"); return Response.json(view); } });
  await expect(invalid.pay()).rejects.toThrow("differs"); expect(calls).toBe(0);
});
