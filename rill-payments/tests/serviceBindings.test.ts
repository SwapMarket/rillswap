import { afterEach, expect, test } from "bun:test";
import { Database } from "bun:sqlite";
import { ed25519 } from "@noble/curves/ed25519.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { chmodSync, mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { LightningAcceptanceConsumer } from "../src/acceptanceConsumer";
import { MerchantLedger, type ReceiptObservation } from "../src/merchant";
import { createMerchantService, verifyAcceptance } from "../src/server";
import { createCheckout, type CheckoutCheckpoint, type CheckoutStore, type IntentView } from "../src/sdk";
import { receiver, testInvoice } from "./helpers";

const handles: { close(): void }[] = [], roots: string[] = [];
afterEach(() => { for (const handle of handles.splice(0)) { try { handle.close(); } catch {} } for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true }); });
function fixture(optIn = true, eventKey: Uint8Array = new Uint8Array(32).fill(3)) {
  mkdirSync("tmp", { recursive: true }); const root = mkdtempSync("tmp/service-bindings-"); chmodSync(root, 0o700); roots.push(root);
  const identity = { origin: "https://merchant.example", receiver, network: "regtest" as const, issuerId: "fixture" };
  const ledgerPath = join(root, "merchant.sqlite"), consumerPath = join(root, "consumer.sqlite");
  const ledger = MerchantLedger.provision(ledgerPath, identity); handles.push(ledger);
  const consumerIdentity = { merchantOrigin: identity.origin, receiver, network: identity.network, merchantPublicKey: bytesToHex(ed25519.getPublicKey(eventKey)) };
  const consumer = LightningAcceptanceConsumer.provision(consumerPath, consumerIdentity); handles.push(consumer);
  const state = { now: 1000, paid: false, issued: 0 };
  const issuer = { identity: async () => identity, create: async (op: { operationId: string }) => { state.issued++; return testInvoice(op.operationId); } };
  const observer = { identity: async () => identity, lookup: async (paymentHash: string): Promise<ReceiptObservation> => ({ receiver, network: "regtest", paymentHash,
    invoiceAmountMsat: "1000000", paidMsat: state.paid ? "1000000" : "0", state: state.paid ? "SETTLED" : "OPEN", settledAt: state.paid ? 1090 : null }) };
  const admin = "a".repeat(43), options = { ledger, issuer, observer, adminToken: admin, statusKey: new Uint8Array(32).fill(2), eventSigningKey: eventKey, now: () => state.now };
  const service = createMerchantService({ ...options, ...(optIn ? { acceptanceConsumer: consumer } : {}) });
  const call = (path: string, token = admin, method = "GET", input?: unknown) => service.fetch(new Request(identity.origin + path, { method,
    headers: { Authorization: "Bearer " + token, "Content-Type": "application/json", "Idempotency-Key": "original_request_key_001" }, body: input === undefined ? undefined : JSON.stringify(input) }));
  return { root, ledgerPath, consumerPath, ledger, consumer, consumerIdentity, service, options, eventKey, state, admin, call };
}
async function create(f: ReturnType<typeof fixture>) {
  const body = { orderRef: "original-order", amountMsat: "1000000", expiresAt: 1100 };
  const view = await (await f.call("/v1/intents", f.admin, "POST", body)).json() as IntentView & { statusToken: string };
  return { body, view, url: "/v1/intents/" + view.id };
}

test("every invoice-bearing snapshot withholds unbound original invoices without passive registration", async () => {
  const f = fixture(), { body, view, url } = await create(f);
  expect(view.attempt).toBeNull();
  expect((await (await f.call(url + "/attempts", f.admin, "POST", {})).json()).attempt).toBeNull();
  const original = f.ledger.attemptForIntent(view.id)!; expect(original.invoice).not.toBeNull();
  for (const token of [f.admin, view.statusToken]) expect((await (await f.call(url, token)).json()).attempt).toBeNull();
  expect((await (await f.call("/v1/intents", f.admin, "POST", body)).json()).attempt).toBeNull();
  expect((await (await f.call(url + "/attempts", f.admin, "POST", {})).json()).attempt).toBeNull();
  await f.service.tick(); expect(() => f.consumer.getOrder(body.orderRef)).toThrow("Unknown"); expect(f.state.issued).toBe(1);
  let walletCalls = 0;
  const records = new Map<string, CheckoutCheckpoint>();
  const store: CheckoutStore = { load: async (id) => records.get(id) ?? null,
    begin: async (record) => { if (records.has(record.attemptId)) return false; records.set(record.attemptId, structuredClone(record)); return true; },
    update: async (record) => { records.set(record.attemptId, structuredClone(record)); } };
  const checkout = createCheckout({ intentUrl: f.options.ledger.identity.origin + url, statusToken: view.statusToken,
    policy: { version: "native-lightning/1", merchantOrigin: f.options.ledger.identity.origin, receiver, network: "regtest", maxBuyerExtraMsat: "0", maxBuyerExtraBps: 0 },
    recoveryStore: store, now: () => 1000, wallet: { canLimitFees: true, payInvoice: async () => { walletCalls++; } },
    fetch: (input, init) => f.service.fetch(new Request(input, init)) });
  await checkout.open(); await expect(checkout.pay()).rejects.toThrow(); expect(walletCalls).toBe(0);
  expect(records.size).toBe(0);
  await f.call(url + "/order-binding", f.admin, "PUT", { orderRef: body.orderRef, amountMsat: body.amountMsat });
  await checkout.open(); await checkout.pay(); expect(walletCalls).toBe(1); expect(records.size).toBe(1);
  await expect(checkout.pay()).rejects.toThrow("already dispatched"); expect(walletCalls).toBe(1);
  expect(f.consumer.getOrder(body.orderRef).state).toBe("waiting"); // Exposure/payment dispatch is not acceptance.
});

test("admin-only resource registration requires original issued terms and independent matching order price", async () => {
  const f = fixture(), { body, view, url } = await create(f), binding = { orderRef: body.orderRef, amountMsat: body.amountMsat };
  expect((await f.call(url + "/order-binding", f.admin, "PUT", binding)).status).toBe(409); expect(f.state.issued).toBe(0);
  await f.call(url + "/attempts", f.admin, "POST", {}); const invoice = f.ledger.attemptForIntent(view.id)!.invoice;
  expect((await f.call(url + "/order-binding", view.statusToken, "PUT", binding)).status).toBe(403);
  expect((await f.call(url + "/order-binding", "invalid", "PUT", binding)).status).toBe(404);
  expect((await f.call(url + "/order-binding", f.admin, "POST", binding)).status).toBe(405);
  for (const invalid of [{ ...binding, orderRef: "foreign" }, { ...binding, amountMsat: "999000" }, { orderRef: body.orderRef }, { ...binding, extra: true }]) {
    expect((await f.call(url + "/order-binding", f.admin, "PUT", invalid)).status).toBe(400);
  }
  const registered = await f.call(url + "/order-binding", f.admin, "PUT", binding); expect(registered.status).toBe(200);
  expect((await registered.json()).attempt.invoice).toBe(invoice);
  // Acknowledgment-loss retries are replay-safe by resource, not arbitrary header keys.
  const retry = await f.service.fetch(new Request(f.options.ledger.identity.origin + url + "/order-binding", { method: "PUT",
    headers: { Authorization: "Bearer " + f.admin, "Content-Type": "application/json" }, body: JSON.stringify(binding) }));
  expect(retry.status).toBe(200); expect((await retry.json()).attempt.invoice).toBe(invoice); expect(f.state.issued).toBe(1);
  expect((await (await f.call(url, view.statusToken)).json()).attempt.invoice).toBe(invoice);
  expect(f.consumer.getOrder(body.orderRef).state).toBe("waiting");
});

test("opt-in rejects incompatible consumer identity and pins the configured event signing key", async () => {
  const f = fixture();
  for (const changed of [{ merchantOrigin: "https://other.example" }, { merchantPublicKey: "22".repeat(32) }, { network: "signet" as const }, { receiver: "03" + "ab".repeat(32) }]) {
    const consumer = LightningAcceptanceConsumer.provision(join(f.root, "foreign-" + handles.length), { ...f.consumerIdentity, ...changed }); handles.push(consumer);
    expect(() => createMerchantService({ ...f.options, acceptanceConsumer: consumer })).toThrow("identity");
  }
  const { body, view, url } = await create(f); await f.call(url + "/attempts", f.admin, "POST", {});
  await f.call(url + "/order-binding", f.admin, "PUT", { orderRef: body.orderRef, amountMsat: body.amountMsat });
  f.eventKey.fill(9); f.state.paid = true; f.state.now = 1200; await f.service.tick();
  const events = await (await f.call(url + "/events", view.statusToken)).json(); expect(verifyAcceptance(events[0], f.consumerIdentity.merchantPublicKey)).toBe(true);
});

test("full binding conflicts or corrupt persisted provenance produce 503 with no invoice", async () => {
  for (const corrupt of [false, true]) {
    const f = fixture(), { body, view, url } = await create(f); await f.call(url + "/attempts", f.admin, "POST", {});
    const terms = f.ledger.terms(f.ledger.attemptForIntent(view.id)!.id);
    f.consumer.bindOrder(body.orderRef, body.amountMsat, { ...terms, expiresAt: terms.expiresAt + 1 });
    if (corrupt) {
      const db = new Database(f.consumerPath, { readwrite: true, create: false }); db.query("UPDATE orders SET payment_hash=?").run("22".repeat(32)); db.close();
    }
    for (const token of [f.admin, view.statusToken]) {
      const result = await f.call(url, token); expect(result.status).toBe(503); expect(JSON.stringify(await result.json())).not.toContain("invoice");
    }
    expect((await f.call(url + "/attempts", f.admin, "POST", {})).status).toBe(503);
    expect((await f.call("/v1/intents", f.admin, "POST", body)).status).toBe(503);
  }
});

test("opt-in copies Buffer-backed event keys for both history and outbox delivery", async () => {
  const f = fixture(true, Buffer.alloc(32, 3)), { body, view, url } = await create(f);
  await f.call(url + "/attempts", f.admin, "POST", {});
  await f.call(url + "/order-binding", f.admin, "PUT", { orderRef: body.orderRef, amountMsat: body.amountMsat });
  f.eventKey.fill(9); f.state.paid = true; f.state.now = 1200; await f.service.tick();
  const events = await (await f.call(url + "/events", view.statusToken)).json();
  expect(verifyAcceptance(events[0], f.consumerIdentity.merchantPublicKey)).toBe(true);
  await f.service.deliverEvents(async (event) => {
    expect(verifyAcceptance(event, f.consumerIdentity.merchantPublicKey)).toBe(true);
    expect(f.consumer.consume(event, 1200).state).toBe("accepted");
  });
  expect(f.ledger.pendingEvents().length).toBe(0);
});

test("upgrading an existing ready invoice with missing binding performs no initialization or historical backfill", async () => {
  const f = fixture(false), { body, view, url } = await create(f); await f.call(url + "/attempts", f.admin, "POST", {});
  const oldInvoice = f.ledger.attemptForIntent(view.id)!.invoice; f.ledger.close(); f.consumer.close();
  const ledger = MerchantLedger.open(f.ledgerPath, f.options.ledger.identity), consumer = LightningAcceptanceConsumer.open(f.consumerPath, f.consumerIdentity); handles.push(ledger, consumer);
  const service = createMerchantService({ ...f.options, ledger, acceptanceConsumer: consumer });
  const result = await service.fetch(new Request(f.options.ledger.identity.origin + url, { headers: { Authorization: "Bearer " + view.statusToken } }));
  expect(result.status).toBe(200); expect((await result.json()).attempt).toBeNull(); expect(() => consumer.getOrder(body.orderRef)).toThrow("Unknown");
  expect(ledger.attemptForIntent(view.id)!.invoice).toBe(oldInvoice); expect(f.state.issued).toBe(1);
});

test("explicit paid legacy registration permits matching allocation without proving historical binding time", async () => {
  const f = fixture(false), { body, view, url } = await create(f); await f.call(url + "/attempts", f.admin, "POST", {});
  const invoice = f.ledger.attemptForIntent(view.id)!.invoice; f.state.paid = true; f.state.now = 1200; await f.service.tick();
  const service = createMerchantService({ ...f.options, acceptanceConsumer: f.consumer });
  const call = (method: string, operation = "", data?: unknown) => service.fetch(new Request(f.options.ledger.identity.origin + url + operation, { method,
    headers: { Authorization: "Bearer " + f.admin, "Content-Type": "application/json" }, body: data === undefined ? undefined : JSON.stringify(data) }));
  expect((await (await call("GET")).json()).attempt).toBeNull();
  expect(() => f.consumer.getOrder(body.orderRef)).toThrow("Unknown");
  const registered = await call("PUT", "/order-binding", { orderRef: body.orderRef, amountMsat: body.amountMsat });
  expect(registered.status).toBe(200); const snapshot = await registered.json(); expect(snapshot.status).toBe("paid"); expect(snapshot.attempt.invoice).toBe(invoice);
  await service.deliverEvents(async (event) => { expect(f.consumer.consume(event, 1200).state).toBe("accepted"); });
  expect(f.consumer.getOrder(body.orderRef).state).toBe("accepted"); expect(f.state.issued).toBe(1);
});

test("default service exposure and event-key behavior stay unchanged, with no registration endpoint", async () => {
  const f = fixture(false), { body, url } = await create(f);
  const issued = await (await f.call(url + "/attempts", f.admin, "POST", {})).json(); expect(issued.attempt.invoice).toBeTruthy();
  expect((await f.call(url + "/order-binding", f.admin, "PUT", { orderRef: body.orderRef, amountMsat: body.amountMsat })).status).toBe(404);
  expect(() => f.consumer.getOrder(body.orderRef)).toThrow("Unknown");
  f.eventKey.fill(9); f.state.paid = true; f.state.now = 1200; await f.service.tick();
  const events = await (await f.call(url + "/events")).json(); expect(verifyAcceptance(events[0], bytesToHex(ed25519.getPublicKey(f.eventKey)))).toBe(true);
});
