import { afterEach, expect, test } from "bun:test";
import { randomBytes } from "node:crypto";
import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { resolve } from "node:path";
import { ed25519 } from "@noble/curves/ed25519.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { MoneroReceiptLedger } from "../src/moneroLedger";
import { createMoneroRegtestService } from "../src/moneroServer";
import { verifyMoneroRegtestReceipt, type MoneroRegtestView } from "../src/moneroContract";
import { FakeMonero, NETWORK, PRIMARY, transfer, txid } from "./moneroFake";

const cleanup: (() => void)[] = []; afterEach(() => { for (const close of cleanup.splice(0)) close(); });
const config = { origin: "https://shop.example", primaryAddress: PRIMARY, network: NETWORK };
const key = (n: number) => `idem-key-${String(n).padStart(8, "0")}`;
const XMR = 1_000_000_000_000n;
function fixture() {
  mkdirSync("tmp", { recursive: true }); const directory = mkdtempSync(resolve("tmp/monero-")), path = directory + "/monero.sqlite";
  const ledger = MoneroReceiptLedger.provision(path, config), rpc = new FakeMonero(), clock = { now: 1500 };
  cleanup.push(() => { try { ledger.close(); } catch {} rmSync(directory, { recursive: true, force: true }); });
  return { ledger, rpc, clock, path, now: () => clock.now };
}

test("intents get fresh stored subaddresses, replay by key or order, and refuse changed terms", async () => {
  const { ledger, rpc, now } = fixture();
  const first = await ledger.createIntent("order-1", "3000000000000", 2000, key(1), rpc, now);
  expect([first.subaddressIndex, first.status, first.createdAt]).toEqual([1, "waiting", 1500]);
  expect(rpc.calls).toEqual(["snapshot:1", "create:rill:", "store"]);
  expect(await ledger.createIntent("order-1", "3000000000000", 2000, key(1), rpc, now)).toEqual(first);
  expect(await ledger.createIntent("order-1", "3000000000000", 2000, key(2), rpc, now)).toEqual(first);
  expect(ledger.createIntent("order-1", "3000000000001", 2000, key(1), rpc, now)).rejects.toThrow("Conflicting");
  expect(ledger.createIntent("order-1", "3000000000001", 2000, key(3), rpc, now)).rejects.toThrow("immutable");
  expect(ledger.createIntent("order-2", "1", 1500, key(4), rpc, now)).rejects.toThrow("Expired");
  expect((await ledger.createIntent("order-2", "1", 2000, key(5), rpc, now)).subaddressIndex).toBe(2);
});

test("a crashed wallet re-offering allocated indices is skipped, never reused", async () => {
  const { ledger, rpc, now } = fixture();
  rpc.stored = 1; // wallet file stored before any allocation
  await ledger.createIntent("order-1", "1", 2000, key(1), rpc, now);
  await ledger.createIntent("order-2", "1", 2000, key(2), rpc, now);
  rpc.stored = 1; rpc.crash(); // the next create_address returns index 1 again
  const third = await ledger.createIntent("order-3", "1", 2000, key(3), rpc, now);
  expect(third.subaddressIndex).toBe(3);
  expect(rpc.stored).toBe(4);
});

test("a lost store or allocation response commits nothing and a retry allocates anew", async () => {
  const { ledger, rpc, now } = fixture();
  rpc.failStore = true;
  expect(ledger.createIntent("order-1", "1", 2000, key(1), rpc, now)).rejects.toThrow("store failed");
  await Bun.sleep(0);
  rpc.failStore = false;
  const intent = await ledger.createIntent("order-1", "1", 2000, key(1), rpc, now);
  expect(intent.subaddressIndex).toBe(2); // index 1 is an orphan nobody was shown
});

test("wrong network, chain, wallet or a lagging wallet blocks allocation and observation", async () => {
  const { ledger, rpc, now } = fixture();
  const intent = await ledger.createIntent("order-1", "1", 2000, key(1), rpc, now);
  for (const [snap, message] of [[{ nettype: "mainnet" }, "fakechain"], [{ anchorHash: "b".repeat(64) }, "chain differs"],
    [{ primaryAddress: "4" + "C".repeat(94) }, "wallet differs"], [{ walletHeight: 199 }, "caught up"]] as const) {
    rpc.snap = snap; rpc.entries = [transfer(1, 1n)];
    expect(ledger.createIntent("order-2", "1", 2000, key(2), rpc, now)).rejects.toThrow(message);
    expect(ledger.observe(rpc, now)).rejects.toThrow(message);
    await Bun.sleep(0);
  }
  expect(ledger.getIntent(intent.intentId).status).toBe("waiting");
  expect(ledger.pendingEvents()).toEqual([]);
  expect(rpc.calls.filter((call) => call.startsWith("transfers") || call.startsWith("create"))).toEqual(["create:rill:"]);
});

test("payment is accepted once, survives reorgs as latched impairment and never re-accepts", async () => {
  const { ledger, rpc, now, clock } = fixture();
  const intent = await ledger.createIntent("order-1", String(3n * XMR), 2000, key(1), rpc, now);
  rpc.entries = [transfer(1, 3n * XMR, { confirmations: 2, locked: true })];
  expect(await ledger.observe(rpc, now)).toEqual({ decided: 0, impaired: 0 });
  expect(ledger.getProgress(intent.intentId)).toEqual({ seenAtomic: String(3n * XMR), confirmedAtomic: "0", observedAt: 1500 });
  rpc.entries = [transfer(1, 3n * XMR)]; clock.now = 1600;
  const [a, b] = await Promise.all([ledger.observe(rpc, now), ledger.observe(rpc, now)]);
  expect([a.decided, b.decided]).toEqual([1, 0]);
  expect(ledger.getIntent(intent.intentId).status).toBe("paid");
  const events = ledger.pendingEvents();
  expect(events).toHaveLength(1);
  expect(events[0]!.acceptedAt).toBe(1600);
  rpc.entries = [transfer(1, 3n * XMR, { type: "pool", confirmations: 0 })];
  expect(await ledger.observe(rpc, now)).toEqual({ decided: 0, impaired: 1 });
  rpc.entries = [transfer(1, 3n * XMR)];
  expect(await ledger.observe(rpc, now)).toEqual({ decided: 0, impaired: 0 });
  expect(ledger.getReceipts(intent.intentId).impaired).toBe(true);
  expect(ledger.pendingEvents()).toEqual(events);
  expect(rpc.calls.at(-1)).toBe("transfers:"); // nothing left to watch
});

test("an unusable observation leaves paid receipts unimpaired", async () => {
  const { ledger, rpc, now } = fixture();
  const intent = await ledger.createIntent("order-1", "5", 2000, key(1), rpc, now);
  rpc.entries = [transfer(1, 5n)]; await ledger.observe(rpc, now);
  rpc.entries = []; rpc.snap = { walletHeight: 150 };
  expect(ledger.observe(rpc, now)).rejects.toThrow("caught up"); await Bun.sleep(0);
  expect(ledger.getReceipts(intent.intentId).impaired).toBe(false);
});

test("a re-mined or no longer qualifying paid transaction is impaired", async () => {
  for (const changed of [{ height: 105, timestamp: 1610 }, { confirmations: 3, locked: true }, { doubleSpendSeen: true }]) {
    const { ledger, rpc, now } = fixture();
    const intent = await ledger.createIntent("order-1", "5", 2000, key(1), rpc, now);
    rpc.entries = [transfer(1, 5n)]; await ledger.observe(rpc, now);
    rpc.entries = [transfer(1, 5n, changed)];
    expect(await ledger.observe(rpc, now)).toEqual({ decided: 0, impaired: 1 });
    expect(ledger.getIntent(intent.intentId).status).toBe("paid");
  }
});

test("future-timestamped evidence is accepted only once observation time catches up, and the event stays valid", async () => {
  const { ledger, rpc, clock, path } = fixture();
  const keys = { adminToken: "a".repeat(40), capabilityKey: randomBytes(32), eventSigningKey: randomBytes(32) };
  const service = createMoneroRegtestService({ ledger, rpc, ...keys, now: () => clock.now });
  const intent = await ledger.createIntent("order-1", "5", 2000, key(1), rpc, () => clock.now);
  rpc.entries = [transfer(1, 5n, { timestamp: 1600 })];
  await service.tick();
  expect(ledger.getIntent(intent.intentId).status).toBe("waiting");
  clock.now = 1700; await service.tick();
  ledger.close();
  const reopened = MoneroReceiptLedger.open(path, config); cleanup.push(() => reopened.close());
  const again = createMoneroRegtestService({ ledger: reopened, rpc, ...keys, now: () => clock.now });
  const response = await again.fetch(new Request(`https://shop.example/v1/monero-regtest/intents/${intent.intentId}`, { headers: { Authorization: `Bearer ${keys.adminToken}` } }));
  const view = await response.json() as MoneroRegtestView;
  expect(view.status).toBe("regtest_receipt_recorded");
  expect(verifyMoneroRegtestReceipt(view.event!, bytesToHex(ed25519.getPublicKey(keys.eventSigningKey)), view.terms)).toBe(true);
});

test("reconciliation records the evidence and is terminal", async () => {
  const { ledger, rpc, now } = fixture();
  const intent = await ledger.createIntent("order-1", "5", 2000, key(1), rpc, now);
  rpc.entries = [transfer(1, 6n)];
  await ledger.observe(rpc, now);
  expect(ledger.getIntent(intent.intentId)).toMatchObject({ status: "reconciliation", reconciliation: "overpaid" });
  expect(ledger.getReceipts(intent.intentId).receipts.map((receipt) => receipt.amountAtomic)).toEqual(["6"]);
  expect(ledger.pendingEvents()).toEqual([]);
  expect(await ledger.observe(rpc, now)).toEqual({ decided: 0, impaired: 0 });
});

test("reopen requires the exact config and keeps state; provision never overwrites", async () => {
  const { ledger, rpc, now, path } = fixture();
  const intent = await ledger.createIntent("order-1", "5", 2000, key(1), rpc, now); ledger.close();
  expect(() => MoneroReceiptLedger.open(path, { ...config, network: { ...NETWORK, confirmations: 11 } })).toThrow("config mismatch");
  expect(() => MoneroReceiptLedger.open(path, { ...config, network: { ...NETWORK, confirmations: 9 } })).toThrow("profile");
  expect(() => MoneroReceiptLedger.provision(path, config)).toThrow();
  const reopened = MoneroReceiptLedger.open(path, config); cleanup.push(() => reopened.close());
  expect(reopened.getIntent(intent.intentId)).toEqual(intent);
});

test("service: admin creates, read capability views, signed event verifies and resists tampering", async () => {
  const { ledger, rpc, clock } = fixture();
  const adminToken = "a".repeat(40), eventSigningKey = randomBytes(32);
  const service = createMoneroRegtestService({ ledger, rpc, adminToken, capabilityKey: randomBytes(32), eventSigningKey, now: () => clock.now });
  const call = (path: string, token: string, init: RequestInit = {}) => service.fetch(new Request(`https://shop.example${path}`,
    { ...init, headers: { Authorization: `Bearer ${token}`, ...(init.headers ?? {}) } }));
  const create = (token: string) => call("/v1/monero-regtest/intents", token, { method: "POST",
    headers: { "Content-Type": "application/json", "Idempotency-Key": key(1) }, body: JSON.stringify({ orderRef: "order-1", amountAtomic: "5", expiresAt: 2000 }) });
  expect((await create("b".repeat(40))).status).toBe(401);
  const created = await create(adminToken);
  expect(created.status).toBe(201);
  expect(created.headers.get("Cache-Control")).toBe("no-store");
  const { view, readCapability } = await created.json() as { view: MoneroRegtestView; readCapability: string };
  expect([view.status, view.terms.subaddressIndex, view.terms.network]).toEqual(["awaiting_funds", 1, NETWORK]);
  const path = `/v1/monero-regtest/intents/${view.terms.intentId}`;
  expect((await call(path, "c".repeat(43))).status).toBe(404);
  expect((await call(path, readCapability, { method: "POST" })).status).toBe(405);
  rpc.entries = [transfer(1, 5n, { txid: txid(1), timestamp: 1600 })]; clock.now = 1700;
  await service.tick();
  const paid = await (await call(path, readCapability)).json() as MoneroRegtestView;
  expect(paid.status).toBe("regtest_receipt_recorded");
  const publicKey = bytesToHex(ed25519.getPublicKey(eventSigningKey));
  expect(verifyMoneroRegtestReceipt(paid.event!, publicKey, view.terms)).toBe(true);
  const tampered = { ...paid.event!, event: { ...paid.event!.event, receipts: [{ ...paid.event!.event.receipts[0]!, amountAtomic: "6" }] } };
  expect(verifyMoneroRegtestReceipt(tampered, publicKey, view.terms)).toBe(false);
  expect(verifyMoneroRegtestReceipt(paid.event!, publicKey, { ...view.terms, amountAtomic: "6" })).toBe(false);
  clock.now = 2100;
  const other = await (await call("/v1/monero-regtest/intents", adminToken, { method: "POST", headers: { "Content-Type": "application/json", "Idempotency-Key": key(2) },
    body: JSON.stringify({ orderRef: "order-2", amountAtomic: "5", expiresAt: 2050 }) })).json();
  expect(other).toEqual({ error: "monero_regtest_request_refused" });
});
