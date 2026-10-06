import { afterEach, expect, test } from "bun:test";
import { Database } from "bun:sqlite";
import { ed25519 } from "@noble/curves/ed25519.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { chmodSync, existsSync, linkSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { LightningAcceptanceConsumer, type AcceptanceConsumerIdentity, type BoundOrderStatus } from "../src/acceptanceConsumer";
import { MerchantLedger, type AcceptanceEvent, type InvoiceIssuer, type ReceiptObserver } from "../src/merchant";
import { createMerchantService, signAcceptance } from "../src/server";
import type { NativeLightningTerms } from "../src/contract";
import { receiver, testInvoice } from "./helpers";

const key = new Uint8Array(32).fill(17), origin = "https://merchant.example";
const identity: AcceptanceConsumerIdentity = { merchantOrigin: origin, merchantPublicKey: bytesToHex(ed25519.getPublicKey(key)), receiver, network: "regtest" };
const terms: NativeLightningTerms = { version: "checkout/0.1", policyVersion: "native-lightning/1", merchantOrigin: origin,
  intentId: "intent_original_001", attemptId: "attempt_original_001", network: "regtest", amountMsat: "1000000", paymentHash: "11".repeat(32), receiver, expiresAt: 1100, buyerExtraMsat: "0" };
const event: AcceptanceEvent = { version: "checkout-event/1", id: "event_original_001", merchantOrigin: origin,
  type: "payment.accepted", intentId: terms.intentId, attemptId: terms.attemptId, paymentHash: terms.paymentHash, amountMsat: terms.amountMsat, acceptedAt: 1200 };
const handles: { close(): void }[] = [], roots: string[] = [];
afterEach(() => { for (const handle of handles.splice(0)) { try { handle.close(); } catch {} } for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true }); });
function root() { mkdirSync("tmp", { recursive: true }); const path = mkdtempSync("tmp/acceptance-consumer-"); chmodSync(path, 0o700); roots.push(path); return path; }
function fixture() {
  const path = join(root(), "consumer.sqlite"), consumer = LightningAcceptanceConsumer.provision(path, identity); handles.push(consumer);
  return { path, consumer };
}
function alter(path: string, sql: string, ...bindings: (string | number)[]) {
  const db = new Database(path, { readwrite: true, create: false }); try { db.query(sql).run(...bindings); } finally { db.close(); }
}

test("explicit provisioning never silently opens absent, partial, unsupported or foreign stores", () => {
  const path = join(root(), "store.sqlite"); expect(() => LightningAcceptanceConsumer.open(path, identity)).toThrow(); expect(existsSync(path)).toBe(false);
  writeFileSync(path, "", { mode: 0o600 }); expect(() => LightningAcceptanceConsumer.open(path, identity)).toThrow(); expect(() => LightningAcceptanceConsumer.provision(path, identity)).toThrow();
  const f = fixture(); f.consumer.close();
  expect(() => LightningAcceptanceConsumer.open(f.path, { ...identity, merchantPublicKey: "22".repeat(32) })).toThrow("identity");
  expect(() => LightningAcceptanceConsumer.open(f.path, { ...identity, network: "mainnet" })).toThrow("identity");
  alter(f.path, "UPDATE metadata SET value='lightning-acceptance-consumer/0' WHERE key='format'");
  expect(() => LightningAcceptanceConsumer.open(f.path, identity)).toThrow("format");
  alter(f.path, "UPDATE metadata SET value='lightning-acceptance-consumer/2' WHERE key='format'");
  expect(() => LightningAcceptanceConsumer.open(f.path, identity)).toThrow("format");
});

test("private files and exact schema are required without repairing invalid stores", () => {
  const f = fixture(); f.consumer.close(); chmodSync(f.path, 0o644); expect(() => LightningAcceptanceConsumer.open(f.path, identity)).toThrow("private"); chmodSync(f.path, 0o600);
  const alias = join(root(), "alias.sqlite"); symlinkSync(f.path, alias); expect(() => LightningAcceptanceConsumer.open(alias, identity)).toThrow();
  const hard = join(root(), "hard.sqlite"); linkSync(f.path, hard); expect(() => LightningAcceptanceConsumer.open(hard, identity)).toThrow("private"); rmSync(hard);
  alter(f.path, "CREATE TABLE unexpected (id TEXT)"); expect(() => LightningAcceptanceConsumer.open(f.path, identity)).toThrow("schema");
  const parent = root(); chmodSync(parent, 0o755); const unsafe = join(parent, "new.sqlite");
  expect(() => LightningAcceptanceConsumer.provision(unsafe, identity)).toThrow("private"); expect(existsSync(unsafe)).toBe(false);
});

test("trusted price and immutable term binding are required before any event can be consumed", () => {
  const { consumer } = fixture(), signed = signAcceptance(event, key);
  expect(() => consumer.consume(signed, 1200)).toThrow("original order binding");
  expect(() => consumer.bindOrder("order-1", "999000", terms)).toThrow("price");
  expect(() => consumer.bindOrder("order-1", terms.amountMsat, { ...terms, merchantOrigin: "https://foreign.example" })).toThrow("identity");
  expect(consumer.bindOrder("order-1", terms.amountMsat, terms)).toEqual({ orderRef: "order-1", state: "waiting", eventId: null });
  expect(consumer.bindOrder("order-1", terms.amountMsat, terms).state).toBe("waiting");
  expect(() => consumer.bindOrder("order-1", terms.amountMsat, { ...terms, expiresAt: 1200 })).toThrow("replaced");
  expect(() => consumer.bindOrder("order-2", terms.amountMsat, terms)).toThrow();
  expect(() => consumer.getOrder("unknown-order")).toThrow("Unknown");
});

test("late observation preserves producer timeliness semantics and exact replay survives restart", () => {
  const f = fixture(); f.consumer.bindOrder("order-1", terms.amountMsat, terms);
  const signed = signAcceptance(event, key), result = f.consumer.consume(signed, 1200);
  expect(result).toEqual({ orderRef: "order-1", state: "accepted", eventId: event.id }); expect(Object.isFrozen(result)).toBe(true);
  expect(f.consumer.consume(signed, 1201)).toEqual(result); f.consumer.close();
  const reopened = LightningAcceptanceConsumer.open(f.path, identity); handles.push(reopened);
  expect(reopened.getOrder("order-1")).toEqual(result); expect(reopened.consume(signed, 1300)).toEqual(result);
  expect(reopened.bindOrder("order-1", terms.amountMsat, terms)).toEqual(result);
});

test("each intent, attempt and payment hash independently belongs to only one order", () => {
  for (const field of ["intentId", "attemptId", "paymentHash"] as const) {
    const f = fixture(); f.consumer.bindOrder("order-1", terms.amountMsat, terms);
    const collision = { ...terms, intentId: "intent_distinct_001", attemptId: "attempt_distinct_001", paymentHash: "33".repeat(32) };
    collision[field] = terms[field];
    expect(() => f.consumer.bindOrder("order-2", terms.amountMsat, collision)).toThrow();
    expect(f.consumer.getOrder("order-1").state).toBe("waiting"); expect(() => f.consumer.getOrder("order-2")).toThrow("Unknown");
  }
});

test("signatures alone cannot replace independent origin, amount, IDs, hash or original order binding", () => {
  for (const changed of [{ merchantOrigin: "https://foreign.example" }, { amountMsat: "999000" }, { intentId: "foreign_intent_001" },
    { attemptId: "foreign_attempt_001" }, { paymentHash: "22".repeat(32) }, { acceptedAt: 1201 }]) {
    const f = fixture(); f.consumer.bindOrder("order-1", terms.amountMsat, terms);
    expect(() => f.consumer.consume(signAcceptance({ ...event, ...changed }, key), 1200)).toThrow(); expect(f.consumer.getOrder("order-1").state).toBe("waiting");
  }
  const f = fixture(); f.consumer.bindOrder("order-1", terms.amountMsat, terms);
  expect(() => f.consumer.consume(signAcceptance(event, new Uint8Array(32).fill(19)), 1200)).toThrow();
  expect(() => f.consumer.consume({ ...signAcceptance(event, key), extra: "private" } as ReturnType<typeof signAcceptance>, 1200)).toThrow();
  expect(() => f.consumer.consume(signAcceptance({ ...event, extra: "private" } as AcceptanceEvent, key), 1200)).toThrow();
  expect(() => f.consumer.consume(signAcceptance({ ...event, version: "native-sandbox-event/1" } as unknown as AcceptanceEvent, key), 1200)).toThrow();
  expect(() => f.consumer.consume(signAcceptance(event, key), NaN)).toThrow("clock");
});

test("independent database handles deduplicate competing deliveries and reject signed conflicts", async () => {
  const f = fixture(); f.consumer.bindOrder("order-1", terms.amountMsat, terms);
  const other = LightningAcceptanceConsumer.open(f.path, identity); handles.push(other); const signed = signAcceptance(event, key);
  const results = await Promise.all([Promise.resolve().then(() => f.consumer.consume(signed, 1200)), Promise.resolve().then(() => other.consume(signed, 1200))]);
  expect(results[0]).toEqual(results[1]);
  expect(() => other.consume(signAcceptance({ ...event, acceptedAt: 1201 }, key), 1201)).toThrow("Conflicting");
  expect(() => other.consume(signAcceptance({ ...event, id: "event_other_valid_001" }, key), 1200)).toThrow("cannot be replaced");
  expect(other.getOrder("order-1").eventId).toBe(event.id);
  const second = { ...terms, intentId: "intent_second_001", attemptId: "attempt_second_001", paymentHash: "22".repeat(32) };
  other.bindOrder("order-2", second.amountMsat, second);
  const collision = { ...event, intentId: second.intentId, attemptId: second.attemptId, paymentHash: second.paymentHash };
  expect(() => other.consume(signAcceptance(collision, key), 1200)).toThrow("Conflicting"); expect(other.getOrder("order-2").state).toBe("waiting");
});

test("concurrent worker connections serialize delivery of the same signed event", async () => {
  const f = fixture(); f.consumer.bindOrder("order-1", terms.amountMsat, terms);
  const workers = [new Worker(new URL("./acceptanceConsumer.worker.ts", import.meta.url).href), new Worker(new URL("./acceptanceConsumer.worker.ts", import.meta.url).href)];
  try {
    const results = workers.map((worker) => {
      let ready!: () => void;
      const admitted = new Promise<void>((resolve) => { ready = resolve; });
      const complete = new Promise<BoundOrderStatus>((resolve, reject) => {
        worker.onmessage = (message) => {
          if (message.data.kind === "ready") ready();
          else if (message.data.kind === "result") resolve(message.data.status);
          else { ready(); reject(new Error("Concurrent consumer refused")); }
        };
        worker.onerror = () => { ready(); reject(new Error("Consumer worker failed")); };
      });
      void complete.catch(() => {}); // Failure can arrive before both workers are admitted.
      worker.postMessage({ kind: "initialize", path: f.path, identity, envelope: signAcceptance(event, key) });
      return { admitted, complete };
    });
    await Promise.all(results.map((result) => result.admitted));
    for (const worker of workers) worker.postMessage({ kind: "consume" });
    const accepted = await Promise.all(results.map((result) => result.complete));
    expect(accepted[0]).toEqual(accepted[1]); expect(f.consumer.getOrder("order-1")).toEqual(accepted[0]!);
  } finally { for (const worker of workers) await worker.terminate(); }
}, 15000);

test("tampered accepted payload, binding indices or signed envelope cannot yield accepted status or replay", () => {
  const mutations = [
    ["UPDATE acceptances SET event_id=?", "event_fake_marker_001"],
    ["UPDATE acceptances SET envelope=?", JSON.stringify({ ...signAcceptance(event, key), signature: "00".repeat(64) })],
    ["UPDATE orders SET payment_hash=?", "22".repeat(32)],
    ["UPDATE orders SET amount_msat=?", "999000"],
    ["UPDATE orders SET terms=?", JSON.stringify({ ...terms, paymentHash: "22".repeat(32) })],
  ];
  for (const [sql, value] of mutations) {
    const f = fixture(); f.consumer.bindOrder("order-1", terms.amountMsat, terms); f.consumer.consume(signAcceptance(event, key), 1200); f.consumer.close();
    alter(f.path, sql!, value!); const reopened = LightningAcceptanceConsumer.open(f.path, identity); handles.push(reopened);
    expect(() => reopened.getOrder("order-1")).toThrow(); expect(() => reopened.consume(signAcceptance(event, key), 1200)).toThrow();
    expect(() => reopened.bindOrder("order-1", terms.amountMsat, terms)).toThrow();
  }
});

test("an otherwise valid signed envelope attached to the wrong order is not acceptance provenance", () => {
  const f = fixture(); f.consumer.bindOrder("order-1", terms.amountMsat, terms);
  const second = { ...terms, intentId: "intent_second_001", attemptId: "attempt_second_001", paymentHash: "22".repeat(32) };
  f.consumer.bindOrder("order-2", second.amountMsat, second); f.consumer.consume(signAcceptance(event, key), 1200); f.consumer.close();
  alter(f.path, "UPDATE acceptances SET order_ref='order-2'");
  const reopened = LightningAcceptanceConsumer.open(f.path, identity); handles.push(reopened);
  expect(() => reopened.getOrder("order-2")).toThrow("bound order"); expect(() => reopened.consume(signAcceptance(event, key), 1200)).toThrow();
  expect(reopened.getOrder("order-1").state).toBe("waiting"); // A removed row never reconstructs acceptance from history.
});

test("real producer observation, signed delivery and acknowledgment loss retain one bound acceptance", async () => {
  const path = root(), merchantIdentity = { origin, receiver, network: "regtest" as const, issuerId: "fixture_issuer" };
  const ledger = MerchantLedger.provision(join(path, "merchant.sqlite"), merchantIdentity); handles.push(ledger);
  const consumer = LightningAcceptanceConsumer.provision(join(path, "consumer.sqlite"), identity); handles.push(consumer);
  const invoice = testInvoice("producer"), issuer: InvoiceIssuer = { identity: async () => merchantIdentity, create: async () => invoice };
  const intent = ledger.createIntent("external-order", "1000000", 1100, "intent_request_001", 1000);
  const attempt = ledger.createAttempt(intent.id, "attempt_request_001", 1000); await ledger.issue(attempt.id, issuer, () => 1000);
  // Bind after issuance, before buyer exposure or payment. No browser-supplied price.
  const bound = ledger.terms(attempt.id); consumer.bindOrder(intent.order_ref, intent.amount_msat, bound);
  const observer: ReceiptObserver = { identity: async () => merchantIdentity, lookup: async () => ({ receiver, network: "regtest", paymentHash: bound.paymentHash,
    invoiceAmountMsat: intent.amount_msat, paidMsat: intent.amount_msat, state: "SETTLED", settledAt: 1090 }) };
  await ledger.observe(attempt.id, observer, () => 1200); expect(ledger.getIntent(intent.id).status).toBe("paid");
  const service = createMerchantService({ ledger, issuer, observer, adminToken: "fixture_admin_token_00000000000000", statusKey: new Uint8Array(32).fill(7), eventSigningKey: key, now: () => 1200 });
  let deliveries = 0;
  await expect(service.deliverEvents(async (envelope) => { deliveries++; consumer.consume(envelope, 1200); throw new Error("acknowledgment lost"); })).rejects.toThrow("lost");
  const accepted = consumer.getOrder(intent.order_ref); expect(accepted.state).toBe("accepted"); expect(ledger.pendingEvents().length).toBe(1); consumer.close();
  const reopened = LightningAcceptanceConsumer.open(join(path, "consumer.sqlite"), identity); handles.push(reopened);
  await service.deliverEvents(async (envelope) => { deliveries++; expect(reopened.consume(envelope, 1201)).toEqual(accepted); });
  expect(deliveries).toBe(2); expect(ledger.pendingEvents().length).toBe(0); expect(reopened.getOrder(intent.order_ref)).toEqual(accepted);
});

test("accepted-order facts are exposed only after a verified acceptance and fail closed on tampering", () => {
  const f = fixture();
  expect(() => f.consumer.acceptedOrder("order-1")).toThrow("Unknown");
  f.consumer.bindOrder("order-1", terms.amountMsat, terms);
  expect(f.consumer.acceptedOrder("order-1")).toBeNull();
  f.consumer.consume(signAcceptance(event, key), 1200);
  expect(f.consumer.acceptedOrder("order-1")).toEqual({ orderRef: "order-1", amountMsat: terms.amountMsat, paymentHash: terms.paymentHash, eventId: event.id });
  expect(Object.isFrozen(f.consumer.acceptedOrder("order-1"))).toBe(true);
  f.consumer.close();
  alter(f.path, "UPDATE orders SET payment_hash=? WHERE order_ref='order-1'", "22".repeat(32));
  const reopened = LightningAcceptanceConsumer.open(f.path, identity); handles.push(reopened);
  expect(() => reopened.acceptedOrder("order-1")).toThrow();
});
