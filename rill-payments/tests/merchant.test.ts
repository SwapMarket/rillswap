import { afterEach, describe, expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { Database } from "bun:sqlite";
import { MerchantLedger, type InvoiceIssuer, type IssueOperation, type MerchantIdentity, type ReceiptObservation } from "../src/merchant";
import { receiver, testInvoice } from "./helpers";

const identity: MerchantIdentity = { origin: "https://merchant.example", receiver, network: "regtest", issuerId: "fixture" };
const stores: MerchantLedger[] = [], directories: string[] = [];
function location(): string {
  mkdirSync("tmp", { recursive: true });
  const directory = mkdtempSync(resolve("tmp/merchant-")); directories.push(directory); return directory + "/ledger.sqlite";
}
function provision(): { store: MerchantLedger; path: string } {
  const path = location(), store = MerchantLedger.provision(path, identity); stores.push(store); return { store, path };
}
afterEach(() => { for (const store of stores.splice(0)) { try { store.close(); } catch {} } for (const directory of directories.splice(0)) rmSync(directory, { recursive: true, force: true }); });
const issuer: InvoiceIssuer = { identity: async () => identity, create: async (op) => testInvoice(op.operationId, op.amountMsat, 1000, op.expiresAt) };
async function ready(store: MerchantLedger, ref = "order-1") {
  const intent = store.createIntent(ref, "1000000", 2000, "intent-key-0000001-" + ref, 1000);
  const attempt = store.createAttempt(intent.id, "attempt-key-000001-" + ref, 1000);
  return { intent, attempt: await store.issue(attempt.id, issuer, () => 1000) };
}
function observation(hash: string, patch: Partial<ReceiptObservation> = {}) {
  return { identity: async () => identity, lookup: async () => ({ receiver, network: "regtest" as const, paymentHash: hash,
    invoiceAmountMsat: "1000000", paidMsat: "1000000", state: "SETTLED" as const, settledAt: 1100, ...patch }) };
}

describe("merchant ledger authority and restart", () => {
  test("explicit provision and conservative absent/foreign/old/new/partial state", () => {
    const path = location(); expect(() => MerchantLedger.open(path, identity)).toThrow();
    writeFileSync(path, "", { mode: 0o600 }); expect(() => MerchantLedger.open(path, identity)).toThrow();
    expect(() => MerchantLedger.provision(path, identity)).toThrow();
    const { store, path: good } = provision();
    expect(() => MerchantLedger.open(good, { ...identity, issuerId: "foreign" })).toThrow();
    store.close(); const db = new Database(good);
    for (const version of ["0", "2"]) { db.query("UPDATE metadata SET value=? WHERE key='version'").run(version); expect(() => MerchantLedger.open(good, identity)).toThrow(); }
    db.close();
  });
  test("mainnet provisioning and reopen preserve identity without starting work", () => {
    const path = location(), mainnet = { ...identity, network: "mainnet" as const };
    const store = MerchantLedger.provision(path, mainnet); store.close();
    const reopened = MerchantLedger.open(path, mainnet); stores.push(reopened);
    expect(reopened.identity).toEqual(mainnet);
    expect(reopened.pendingAttempts()).toEqual([]); expect(reopened.pendingEvents()).toEqual([]);
    expect(() => MerchantLedger.open(path, identity)).toThrow("identity mismatch");
  });
  test("idempotency and one payable attempt across separate clients", () => {
    const { store, path } = provision(); const second = MerchantLedger.open(path, identity); stores.push(second);
    const intent = store.createIntent("order", "1000000", 2000, "intent-key-0000001", 1000);
    expect(second.createIntent("order", "1000000", 2000, "intent-key-0000001", 1000).id).toBe(intent.id);
    expect(() => store.createIntent("different", "1000000", 2000, "intent-key-0000001", 1000)).toThrow("Conflicting");
    const first = store.createAttempt(intent.id, "attempt-key-000001", 1000);
    expect(second.createAttempt(intent.id, "different-key-001", 1000).id).toBe(first.id);
    expect(second.pendingAttempts()).toHaveLength(1);
    expect(store.createIntent("order", "1000000", 2000, "intent-key-0000001", 3000).id).toBe(intent.id);
  });
  test("startup rejects missing constraints and unexpected triggers", () => {
    for (const sql of [
      "ALTER TABLE attempts RENAME TO discarded; CREATE TABLE attempts AS SELECT * FROM discarded; DROP TABLE discarded;",
      "CREATE TRIGGER erase_event AFTER INSERT ON outbox BEGIN DELETE FROM outbox; END;",
      "CREATE TRIGGER sqliteXerase_event AFTER INSERT ON outbox BEGIN DELETE FROM outbox; END;",
    ]) {
      const { store, path } = provision(); store.close(); const db = new Database(path); db.exec(sql); db.close();
      expect(() => MerchantLedger.open(path, identity)).toThrow("schema mismatch");
    }
  });
  test("clock rechecks before dispatch and after invoice creation", async () => {
    const { store } = provision(); const intent = store.createIntent("order", "1000000", 2000, "intent-key-0000001", 1000);
    const attempt = store.createAttempt(intent.id, "attempt-key-000001", 1000); let now = 1000; let calls = 0;
    const slow: InvoiceIssuer = { identity: async () => { now = 2000; return identity; }, create: async () => { calls++; throw new Error(); } };
    await expect(store.issue(attempt.id, slow, () => now)).rejects.toThrow("expired"); expect(calls).toBe(0);
    now = 1000;
    const delayed: InvoiceIssuer = { identity: async () => identity, create: async (op) => { now = 1002; return testInvoice(op.operationId, op.amountMsat, 1001); } };
    expect((await store.issue(attempt.id, delayed, () => now)).state).toBe("ready");
    await expect(store.observe(attempt.id, observation(store.getAttempt(attempt.id).payment_hash!, { settledAt: 1000 }), () => 1100)).rejects.toThrow("settlement time");
  });
  test("issuer timeout after creation resumes the exact operation after restart", async () => {
    const { store, path } = provision(); const intent = store.createIntent("order", "1000000", 2000, "intent-key-0000001", 1000);
    const attempt = store.createAttempt(intent.id, "attempt-key-000001", 1000);
    let created: IssueOperation | null = null;
    const ambiguous: InvoiceIssuer = { identity: async () => identity, create: async (op) => { created = op; throw new Error("RPC response lost"); } };
    await expect(store.issue(attempt.id, ambiguous, () => 1000)).rejects.toThrow();
    expect(store.getAttempt(attempt.id).state).toBe("unknown"); store.close();
    const reopened = MerchantLedger.open(path, identity); stores.push(reopened);
    expect(reopened.getAttempt(attempt.id).operation_id).toBe(created!.operationId);
    const result = await reopened.issue(attempt.id, issuer, () => 1000);
    expect(result.invoice).toBe(testInvoice(created!.operationId));
    expect(reopened.pendingAttempts()).toHaveLength(1);
  });
  test("unknown issuance recovered after expiry stays recorded for observation", async () => {
    const { store } = provision(); const intent = store.createIntent("order", "1000000", 2000, "intent-key-0000001", 1000);
    const attempt = store.createAttempt(intent.id, "attempt-key-000001", 1000);
    await expect(store.issue(attempt.id, { ...issuer, create: async () => { throw new Error("lost"); } }, () => 1000)).rejects.toThrow();
    expect((await store.issue(attempt.id, issuer, () => 2100)).state).toBe("ready");
    expect(store.terms(attempt.id).expiresAt).toBe(2000);
  });
  test("wrong issuer and invoice cannot expose funding instructions", async () => {
    const { store } = provision(); const intent = store.createIntent("order", "1000000", 2000, "intent-key-0000001", 1000);
    const attempt = store.createAttempt(intent.id, "attempt-key-000001", 1000);
    await expect(store.issue(attempt.id, { ...issuer, identity: async () => ({ ...identity, network: "signet" }) }, () => 1000)).rejects.toThrow();
    await expect(store.issue(attempt.id, { ...issuer, create: async (op) => testInvoice(op.operationId, "2000000") }, () => 1000)).rejects.toThrow();
    expect(() => store.terms(attempt.id)).toThrow("unresolved");
  });
  test("accepted HTLC or forged status cannot accept, receiver settlement accepts once", async () => {
    const { store, path } = provision(); const { intent, attempt } = await ready(store);
    expect((await store.observe(attempt.id, observation(attempt.payment_hash!, { state: "ACCEPTED", paidMsat: "0", settledAt: null }), () => 1200)).status).toBe("waiting");
    expect((await store.observe(attempt.id, observation(attempt.payment_hash!, { state: "ACCEPTED", settledAt: null }), () => 1200)).status).toBe("waiting");
    await expect(store.observe(attempt.id, observation("f".repeat(64)), () => 1200)).rejects.toThrow();
    expect(store.pendingEvents()).toHaveLength(0);
    expect((await store.observe(attempt.id, observation(attempt.payment_hash!), () => 1200)).status).toBe("paid");
    const event = store.pendingEvents()[0]!; store.close(); const reopened = MerchantLedger.open(path, identity); stores.push(reopened);
    await reopened.observe(attempt.id, observation(attempt.payment_hash!), () => 1201);
    expect(reopened.pendingEvents()).toEqual([event]); expect(reopened.getIntent(intent.id).status).toBe("paid");
    expect(JSON.stringify(event)).not.toContain("preimage"); reopened.acknowledgeEvent(event.id); expect(reopened.pendingEvents()).toHaveLength(0);
  });
  test.each([{ paidMsat: "999000" }, { paidMsat: "1001000" }, { settledAt: 2000 }])("late/excess/insufficient receipt reconciles without fulfillment %j", async (patch) => {
    const { store } = provision(); const { attempt } = await ready(store);
    expect((await store.observe(attempt.id, observation(attempt.payment_hash!, patch), () => 2100)).status).toBe("reconciliation");
    expect(store.pendingEvents()).toHaveLength(0);
  });
  test("settled contradictions preserve paid history and receipt uniqueness", async () => {
    const { store } = provision(); const first = await ready(store, "one"); await store.observe(first.attempt.id, observation(first.attempt.payment_hash!), () => 1200);
    await expect(store.observe(first.attempt.id, observation(first.attempt.payment_hash!, { paidMsat: "1001000" }), () => 1201)).rejects.toThrow("Conflicting");
    expect(store.getIntent(first.intent.id).status).toBe("paid");
    const second = store.createIntent("two", "1000000", 2000, "intent-key-0000002", 1000);
    const attempt = store.createAttempt(second.id, "attempt-key-000002", 1000);
    await expect(store.issue(attempt.id, { ...issuer, create: async () => first.attempt.invoice! }, () => 1000)).rejects.toThrow();
    expect(store.getIntent(second.id).status).toBe("waiting");
  });
  test("runtime observer states validated and secret fields never persisted", async () => {
    const { store, path } = provision(); const { attempt } = await ready(store);
    await expect(store.observe(attempt.id, observation(attempt.payment_hash!, { state: "UNRECOGNIZED" as "OPEN" }), () => 1200)).rejects.toThrow();
    await expect(store.observe(attempt.id, observation(attempt.payment_hash!, { state: "OPEN" }), () => 1200)).rejects.toThrow();
    const extra = observation(attempt.payment_hash!); const normal = await extra.lookup();
    await store.observe(attempt.id, { identity: extra.identity, lookup: async () => ({ ...normal, r_preimage: "never store this", credential: "or this" }) }, () => 1200);
    const db = new Database(path, { readonly: true }); const row = db.query("SELECT payload FROM receipts").get() as { payload: string }; db.close();
    expect(row.payload).not.toContain("preimage"); expect(row.payload).not.toContain("credential");
    await expect(store.observe(attempt.id, observation(attempt.payment_hash!, { state: "OPEN", paidMsat: "0", settledAt: null }), () => 1300)).rejects.toThrow("Conflicting");
  });
});
