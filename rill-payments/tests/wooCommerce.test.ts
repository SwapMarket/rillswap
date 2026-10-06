import { afterEach, expect, spyOn, test } from "bun:test";
import { Database } from "bun:sqlite";
import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { resolve } from "node:path";
import { MerchantLedger, type ReceiptObservation } from "../src/merchant";
import { LightningAcceptanceConsumer } from "../src/acceptanceConsumer";
import { ed25519 } from "@noble/curves/ed25519.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { createMerchantService } from "../src/server";
import { btcTotalToMsat, createWooCommerceOrderSource, WooCommerceOrderRefused, type WooCommerceOrderSource } from "../src/woocommerce";
import { receiver, testInvoice } from "./helpers";

const store = "https://shop.example", key = "ck_" + "a".repeat(40), secret = "cs_" + "b".repeat(40), orderKey = "wc_order_AbC123xyz";
const order = (extra: Record<string, unknown> = {}) => ({ id: 42, order_key: orderKey, status: "pending", currency: "BTC", total: "0.00012345", line_items: [], ...extra });
const json = (value: unknown, status = 200, type = "application/json; charset=UTF-8") => new Response(JSON.stringify(value), { status, headers: { "Content-Type": type } });
const reason = async (promise: Promise<unknown>) => { try { await promise; return "accepted"; } catch (error) { return error instanceof WooCommerceOrderRefused ? error.reason : "other"; } };

test("BTC totals convert exactly to whole-satoshi millisatoshis", () => {
  expect(btcTotalToMsat("0.00012345")).toBe("12345000");
  expect(btcTotalToMsat("1")).toBe("100000000000");
  expect(btcTotalToMsat("0.1")).toBe("10000000000");
  expect(btcTotalToMsat("21000000.00000000")).toBe("2100000000000000000");
  for (const bad of ["0", "0.00000000", "0.000000001", "-1", "1e-8", "01.0", ".5", "1.", " 1", "1,5", "21000000.00000001"]) expect(() => btcTotalToMsat(bad)).toThrow("Invalid BTC total");
});

test("order reads use exact authenticated URLs and admit only pending BTC orders with the matching key", async () => {
  const seen: { url: string; init: RequestInit }[] = [];
  let next: () => Response = () => json(order());
  const source = createWooCommerceOrderSource({ storeOrigin: store, consumerKey: key, consumerSecret: secret, fetch: async (url, init) => { seen.push({ url, init }); return next(); } });
  const price = await source.readPayableOrder("42", orderKey);
  expect(price.amountMsat).toBe("12345000"); expect(price.orderRef).toMatch(/^woocommerce:[0-9a-f]{32}:42$/);
  expect(seen[0]!.url).toBe(store + "/wp-json/wc/v3/orders/42");
  expect(seen[0]!.init.redirect).toBe("error");
  expect((seen[0]!.init.headers as Record<string, string>).Authorization).toBe("Basic " + Buffer.from(key + ":" + secret).toString("base64"));
  expect(await reason(source.readPayableOrder("42", "wc_order_other"))).toBe("not_found");
  next = () => json({ code: "woocommerce_rest_shop_order_invalid_id" }, 404);
  expect(await reason(source.readPayableOrder("42", orderKey))).toBe("not_found");
  for (const changed of [{ status: "processing" }, { status: "on-hold" }, { currency: "USD" }, { total: "0" }, { total: 0.1 }, { total: "0.000000001" }]) {
    next = () => json(order(changed)); expect(await reason(source.readPayableOrder("42", orderKey))).toBe("not_payable");
  }
  for (const response of [() => json(order({ id: 43 })), () => json(order({ id: "42" })), () => json(order(), 401), () => json(order(), 200, "text/html"),
    () => json([order()]), () => new Response("{", { headers: { "Content-Type": "application/json" } }),
    () => json(order({ padding: "x".repeat(300 * 1024) })), () => { throw new Error("network"); }]) {
    next = response; expect(await reason(source.readPayableOrder("42", orderKey))).toBe("unavailable");
  }
  const before = seen.length;
  for (const [id, candidate] of [["0", orderKey], ["4x", orderKey], ["9007199254740993", orderKey], ["42", "order_key"], ["42", "wc_order_../x"]]) expect(await reason(source.readPayableOrder(id!, candidate!))).toBe("not_found");
  expect(seen.length).toBe(before); // malformed input never reaches the store
});

test("delivery URLs, redirects and the read budget are enforced", async () => {
  const wrong = createWooCommerceOrderSource({ storeOrigin: store, consumerKey: key, consumerSecret: secret,
    fetch: async () => { const response = json(order()); Object.defineProperty(response, "url", { value: store + "/elsewhere" }); return response; } });
  expect(await reason(wrong.readPayableOrder("42", orderKey))).toBe("unavailable");
  const redirected = createWooCommerceOrderSource({ storeOrigin: store, consumerKey: key, consumerSecret: secret,
    fetch: async () => { const response = json(order()); Object.defineProperty(response, "redirected", { value: true }); return response; } });
  expect(await reason(redirected.readPayableOrder("42", orderKey))).toBe("unavailable");
  const slow = createWooCommerceOrderSource({ storeOrigin: store, consumerKey: key, consumerSecret: secret, timeoutMs: 20,
    fetch: (_url, init) => new Promise((_resolve, reject) => init.signal!.addEventListener("abort", () => reject(new Error("aborted")))) });
  expect(await reason(slow.readPayableOrder("42", orderKey))).toBe("unavailable");
  // Uncooperative transports and bodies that ignore abort are still bounded.
  const started = performance.now();
  const hung = createWooCommerceOrderSource({ storeOrigin: store, consumerKey: key, consumerSecret: secret, timeoutMs: 20, fetch: () => new Promise<Response>(() => {}) });
  expect(await reason(hung.readPayableOrder("42", orderKey))).toBe("unavailable");
  let cancelled = false;
  const stalled = createWooCommerceOrderSource({ storeOrigin: store, consumerKey: key, consumerSecret: secret, timeoutMs: 20,
    fetch: async () => new Response(new ReadableStream({ start(controller) { controller.enqueue(new TextEncoder().encode("{")); }, cancel() { cancelled = true; } }),
      { headers: { "Content-Type": "application/json" } }) });
  expect(await reason(stalled.readPayableOrder("42", orderKey))).toBe("unavailable");
  expect(performance.now() - started).toBeLessThan(1000);
  await Bun.sleep(0); expect(cancelled).toBe(true);
  // A response arriving after the deadline is discarded.
  let release: (response: Response) => void = () => {};
  const late = createWooCommerceOrderSource({ storeOrigin: store, consumerKey: key, consumerSecret: secret, timeoutMs: 20, fetch: () => new Promise<Response>((resolve) => { release = resolve; }) });
  const pending = reason(late.readPayableOrder("42", orderKey));
  expect(await pending).toBe("unavailable");
  let lateCancelled = false;
  release(new Response(new ReadableStream({ cancel() { lateCancelled = true; } }), { headers: { "Content-Type": "application/json" } }));
  await Bun.sleep(0); expect(lateCancelled).toBe(true);
  for (const options of [{ storeOrigin: "http://shop.example" }, { storeOrigin: store + "/shop" }, { storeOrigin: store + "/" }, { consumerKey: "key" }, { consumerSecret: "cs_x" }, { timeoutMs: 0 }, { timeoutMs: 30_001 }]) {
    expect(() => createWooCommerceOrderSource({ storeOrigin: store, consumerKey: key, consumerSecret: secret, ...options })).toThrow();
  }
});

test("only explicitly injected transports may return URL-less responses", async () => {
  let response = json(order());
  const transport = spyOn(globalThis, "fetch").mockImplementation(Object.assign(async () => response, { preconnect: globalThis.fetch.preconnect }));
  try {
    const source = createWooCommerceOrderSource({ storeOrigin: store, consumerKey: key, consumerSecret: secret });
    expect(await reason(source.readPayableOrder("42", orderKey))).toBe("unavailable");
    response = json(order());
    Object.defineProperty(response, "url", { value: store + "/wp-json/wc/v3/orders/42" });
    expect((await source.readPayableOrder("42", orderKey)).amountMsat).toBe("12345000");
  } finally { transport.mockRestore(); }
});

const cleanups: (() => void)[] = []; afterEach(() => { for (const cleanup of cleanups.splice(0)) cleanup(); });
function service(currentOrder: () => Response, setup: { configured?: boolean; consumer?: boolean; origin?: string; bindVerifiedOrders?: boolean; source?: WooCommerceOrderSource } = {}) {
  mkdirSync("tmp", { recursive: true }); const directory = mkdtempSync(resolve("tmp/woocommerce-"));
  const identity = { origin: "https://merchant.example", receiver, network: "regtest" as const, issuerId: "fixture" };
  let ledger = MerchantLedger.provision(directory + "/ledger", identity);
  const handles: { close(): void }[] = [ledger];
  cleanups.push(() => { for (const handle of handles) handle.close(); rmSync(directory, { recursive: true, force: true }); });
  const state = { now: 1200, issued: 0, failIssue: false, health: 0, paid: false, paidAmount: "12345000", onHealth: undefined as (() => void) | undefined, operations: [] as string[] };
  const issuer = { identity: async () => { state.health++; state.onHealth?.(); return identity; }, create: async (op: { operationId: string; amountMsat: string }) => {
    state.operations.push(op.operationId); if (state.failIssue) throw new Error("ambiguous"); state.issued++; return testInvoice(op.operationId, op.amountMsat); } };
  const observer = { identity: async () => identity, lookup: async (paymentHash: string): Promise<ReceiptObservation> => ({ receiver, network: "regtest", paymentHash,
    invoiceAmountMsat: "12345000", paidMsat: state.paid ? state.paidAmount : "0", state: state.paid ? "SETTLED" : "OPEN", settledAt: state.paid ? state.now : null }) };
  const build = (origin: string) => createWooCommerceOrderSource({ storeOrigin: origin, consumerKey: key, consumerSecret: secret, fetch: async () => currentOrder() });
  const eventKey = new Uint8Array(32).fill(3);
  let consumer = setup.consumer ? LightningAcceptanceConsumer.provision(directory + "/consumer", { merchantOrigin: identity.origin, receiver, network: identity.network,
    merchantPublicKey: bytesToHex(ed25519.getPublicKey(eventKey)) }) : undefined;
  if (consumer) handles.push(consumer);
  let bindVerifiedOrders = setup.bindVerifiedOrders;
  const make = (origin: string) => createMerchantService({ ledger, issuer, observer, adminToken: "a".repeat(43), statusKey: new Uint8Array(32).fill(2), eventSigningKey: eventKey,
    now: () => state.now, ...(consumer ? { acceptanceConsumer: consumer } : {}),
    ...(setup.configured === false ? {} : { wooCommerce: { source: setup.source ?? build(origin), intentTtlSeconds: 600, orderKeyGrantsStatusAccess: true as const, bindVerifiedOrders } }) });
  let merchant = make(setup.origin ?? store);
  const checkout = (input: unknown, method = "POST", id = "42") => merchant.fetch(new Request(identity.origin + `/v1/woocommerce/orders/${id}/checkout`,
    { method, headers: { "Content-Type": "application/json" }, body: method === "GET" ? undefined : JSON.stringify(input) }));
  const refFor = async (origin: string) => (await build(origin).readPayableOrder("42", orderKey)).orderRef;
  return { get ledger() { return ledger; }, get consumer() { return consumer; }, state, checkout, refFor,
    ledgerPath: directory + "/ledger",
    tick: () => merchant.tick(),
    setBindingPolicy: (enabled: boolean) => { bindVerifiedOrders = enabled; merchant = make(setup.origin ?? store); },
    openPeer: () => MerchantLedger.open(directory + "/ledger", identity),
    restart: () => {
      const index = handles.indexOf(ledger); ledger.close();
      ledger = MerchantLedger.open(directory + "/ledger", identity); handles[index] = ledger;
      if (consumer) {
        const consumerIndex = handles.indexOf(consumer), identity = consumer.identity;
        consumer.close(); consumer = LightningAcceptanceConsumer.open(directory + "/consumer", identity); handles[consumerIndex] = consumer;
      }
      merchant = make(setup.origin ?? store);
    },
    switchStore: (origin: string) => { merchant = make(origin); }, admin: (path: string, method: string, input: unknown) =>
    merchant.fetch(new Request(identity.origin + path, { method, headers: { Authorization: "Bearer " + "a".repeat(43), "Content-Type": "application/json", "Idempotency-Key": "admin-key-000000001" }, body: JSON.stringify(input) })),
    status: (id: string, token: string) => merchant.fetch(new Request(`${identity.origin}/v1/intents/${id}`, { headers: { Authorization: "Bearer " + token } })) };
}
type View = { id: string; status: string; statusToken: string; actionRequired?: string; attempt: { terms: { amountMsat: string; expiresAt: number }; invoice: string } | null };

test("buyer checkout is priced by the store, issues once and replays the same intent", async () => {
  let current = () => json(order());
  const f = service(() => current());
  const first = await f.checkout({ orderKey });
  expect(first.status).toBe(200);
  const view = await first.json() as View;
  expect(view.status).toBe("waiting");
  expect(view.attempt!.terms.amountMsat).toBe("12345000");
  expect(view.attempt!.terms.expiresAt).toBe(1800);
  expect(f.ledger.getIntent(view.id).order_ref).toBe(await f.refFor(store));
  expect(f.ledger.getIntent(view.id).order_ref).toMatch(/^woocommerce:[0-9a-f]{32}:42$/);
  f.state.now = 1250; // later replays keep the original expiry and invoice
  const again = await (await f.checkout({ orderKey })).json() as View;
  expect(again.id).toBe(view.id); expect(again.attempt!.invoice).toBe(view.attempt!.invoice); expect(f.state.issued).toBe(1);
  expect((await f.status(view.id, view.statusToken)).status).toBe(200);
  // A store-side price change can never replace the persisted order terms.
  current = () => json(order({ total: "0.00020000" }));
  expect((await f.checkout({ orderKey })).status).toBe(409);
  current = () => json(order({ status: "cancelled" }));
  expect((await f.checkout({ orderKey })).status).toBe(409);
  expect(f.ledger.getIntent(view.id).amount_msat).toBe("12345000");
});

test("buyer cannot set the price and refusals create no intent or backend work", async () => {
  let current = () => json(order());
  const f = service(() => current()), ref = await f.refFor(store);
  for (const input of [{ orderKey, amountMsat: "1000" }, { orderKey: 1 }, {}, []]) expect((await f.checkout(input)).status).toBe(400);
  expect((await f.checkout({ orderKey }, "GET")).status).toBe(405);
  expect((await f.checkout({ orderKey: "wc_order_wrong" })).status).toBe(404);
  current = () => json(order(), 500);
  expect((await f.checkout({ orderKey })).status).toBe(503);
  current = () => json(order({ currency: "EUR" }));
  expect((await f.checkout({ orderKey })).status).toBe(409);
  expect(f.ledger.intentForOrder(ref)).toBeNull();
  expect(f.state.issued).toBe(0); expect(f.state.health).toBe(0);
});

test("references are store-bound and existing intents are never adopted by reference and amount", async () => {
  const f = service(() => json(order()));
  const ref = await f.refFor(store);
  expect(ref).not.toBe(await f.refFor("https://other-shop.example"));
  // An admin intent with the identical reference and amount is not store provenance.
  expect((await f.admin("/v1/intents", "POST", { orderRef: ref, amountMsat: "12345000", expiresAt: 1800 })).status).toBe(201);
  expect((await f.checkout({ orderKey })).status).toBe(409);
  expect(f.state.issued).toBe(0);
  // A different store on the same ledger gets a separate intent, never the old one.
  const g = service(() => json(order()));
  const original = await (await g.checkout({ orderKey })).json() as View;
  g.switchStore("https://other-shop.example");
  const switched = await (await g.checkout({ orderKey })).json() as View;
  expect(switched.id).not.toBe(original.id);
});

test("a concurrent first request that lost the race reuses the winner's intent", async () => {
  const f = service(() => json(order()));
  const ref = await f.refFor(store);
  const peer = f.openPeer(), create = f.ledger.createIntent.bind(f.ledger);
  let winnerId = "";
  // Insert from another connection between the route's absent-order read and
  // create transaction. Its earlier clock gives a different expiry fingerprint.
  const intercepted = spyOn(f.ledger, "createIntent").mockImplementation((...args) => {
    winnerId = peer.createIntent(ref, "12345000", 1790, "woocommerce-intent:" + ref, 1190).id;
    return create(...args); // actually throws the conflicting-idempotency error
  });
  try {
    const result = await f.checkout({ orderKey }); expect(result.status).toBe(200);
    const view = await result.json() as View;
    expect(intercepted).toHaveBeenCalledTimes(1);
    expect(view.id).toBe(winnerId); expect(view.attempt!.terms.expiresAt).toBe(1790);
    expect(f.ledger.intentIdForKey("woocommerce-intent:" + ref)).toBe(winnerId);
  } finally { intercepted.mockRestore(); peer.close(); }
});

test("ambiguous issuance is retried with the same operation after restart", async () => {
  const f = service(() => json(order()));
  f.state.failIssue = true;
  const pending = await f.checkout({ orderKey });
  expect(pending.status).toBe(202);
  const body = await pending.json() as View;
  expect(body.actionRequired).toBe("issuance_reconciliation"); expect(body.attempt).toBeNull();
  expect(f.ledger.attemptForIntent(body.id)!.state).toBe("unknown");
  const oldLedger = f.ledger, operation = f.ledger.attemptForIntent(body.id)!.operation_id;
  f.restart();
  expect(f.ledger).not.toBe(oldLedger);
  expect(f.ledger.attemptForIntent(body.id)!.operation_id).toBe(operation);
  f.state.failIssue = false;
  const ready = await (await f.checkout({ orderKey })).json() as View;
  expect(ready.id).toBe(body.id); expect(ready.attempt).not.toBeNull();
  expect(new Set(f.state.operations).size).toBe(1);
});

test("the acceptance consumer still hides the invoice until the backend binds the order", async () => {
  const f = service(() => json(order()), { consumer: true });
  const view = await (await f.checkout({ orderKey })).json() as View;
  expect(view.attempt).toBeNull();
  const intent = f.ledger.getIntent(view.id);
  expect((await f.admin(`/v1/intents/${view.id}/order-binding`, "PUT", { orderRef: intent.order_ref, amountMsat: intent.amount_msat })).status).toBe(200);
  expect(((await (await f.checkout({ orderKey })).json()) as View).attempt).not.toBeNull();
});

test("explicit verified-store binding exposes the invoice without a second admin request", async () => {
  const f = service(() => json(order()), { consumer: true, bindVerifiedOrders: true });
  const view = await (await f.checkout({ orderKey })).json() as View;
  expect(view.attempt).not.toBeNull();
  const intent = f.ledger.getIntent(view.id);
  expect(f.consumer!.getOrder(intent.order_ref).state).toBe("waiting");
  const replay = await (await f.checkout({ orderKey })).json() as View;
  expect(replay.id).toBe(view.id); expect(replay.attempt!.invoice).toBe(view.attempt!.invoice);
  expect(f.state.issued).toBe(1); expect(f.ledger.pendingEvents()).toHaveLength(0);
  f.state.paid = true; await f.tick();
  expect(((await (await f.checkout({ orderKey })).json()) as View).status).toBe("paid"); // original binding replay, not historical creation
});

test("verified binding needs a fresh checkout, never startup, tick or status reads", async () => {
  const f = service(() => json(order()), { consumer: true, bindVerifiedOrders: false });
  const original = await (await f.checkout({ orderKey })).json() as View;
  expect(original.attempt).toBeNull();
  const previousConsumer = f.consumer;
  f.setBindingPolicy(true); f.restart();
  expect(f.consumer).not.toBe(previousConsumer);
  const intent = f.ledger.getIntent(original.id), attempt = f.ledger.attemptForIntent(intent.id)!;
  expect(f.consumer!.existingBinding(intent.order_ref, intent.amount_msat, f.ledger.terms(attempt.id))).toBeNull();
  await f.tick();
  expect(((await (await f.status(original.id, original.statusToken)).json()) as View).attempt).toBeNull();
  expect(f.consumer!.existingBinding(intent.order_ref, intent.amount_msat, f.ledger.terms(attempt.id))).toBeNull();
  const admitted = await (await f.checkout({ orderKey })).json() as View;
  expect(admitted.id).toBe(original.id); expect(admitted.attempt).not.toBeNull(); expect(f.state.issued).toBe(1);
});

test("store refusal and ambiguous issuance never create acceptance bindings", async () => {
  let current = () => json(order());
  const f = service(() => current(), { consumer: true, bindVerifiedOrders: true });
  const ref = await f.refFor(store);
  expect((await f.checkout({ orderKey: "wc_order_wrong" })).status).toBe(404);
  current = () => json(order({ status: "cancelled" })); expect((await f.checkout({ orderKey })).status).toBe(409);
  current = () => json(order(), 500); expect((await f.checkout({ orderKey })).status).toBe(503);
  expect(f.ledger.intentForOrder(ref)).toBeNull(); expect(() => f.consumer!.getOrder(ref)).toThrow();
  current = () => json(order()); f.state.failIssue = true;
  const unknown = await (await f.checkout({ orderKey })).json() as View;
  expect(unknown.actionRequired).toBe("issuance_reconciliation"); expect(unknown.attempt).toBeNull();
  expect(() => f.consumer!.getOrder(ref)).toThrow();
  f.state.failIssue = false; f.restart();
  current = () => json(order({ total: "0.00020000" })); expect((await f.checkout({ orderKey })).status).toBe(409);
  expect(() => f.consumer!.getOrder(ref)).toThrow();
  current = () => json(order()); const ready = await (await f.checkout({ orderKey })).json() as View;
  expect(ready.id).toBe(unknown.id); expect(ready.attempt).not.toBeNull();
  expect(new Set(f.state.operations).size).toBe(1);
});

test("new bindings refuse expired, already paid and reconciled unbound invoices", async () => {
  for (const condition of ["expired", "paid", "reconciliation"]) {
    const f = service(() => json(order()), { consumer: true });
    const original = await (await f.checkout({ orderKey })).json() as View;
    const ref = f.ledger.getIntent(original.id).order_ref;
    if (condition === "expired") f.state.now = 1800;
    else { f.state.paid = true; if (condition === "reconciliation") f.state.paidAmount = "1000"; await f.tick(); }
    f.setBindingPolicy(true);
    expect((await f.checkout({ orderKey })).status).toBe(409);
    expect(() => f.consumer!.getOrder(ref)).toThrow();
  }
});

test("binding conflicts fail closed and never replace original consumer terms", async () => {
  const f = service(() => json(order()), { consumer: true });
  const original = await (await f.checkout({ orderKey })).json() as View;
  const intent = f.ledger.getIntent(original.id), attempt = f.ledger.attemptForIntent(intent.id)!;
  const terms = f.ledger.terms(attempt.id);
  f.consumer!.bindOrder(intent.order_ref, intent.amount_msat, { ...terms, expiresAt: terms.expiresAt - 1 });
  f.setBindingPolicy(true);
  expect((await f.checkout({ orderKey })).status).toBe(503);
  expect(f.consumer!.existingBinding(intent.order_ref, intent.amount_msat, { ...terms, expiresAt: terms.expiresAt - 1 })!.state).toBe("waiting");
  expect(f.ledger.getIntent(intent.id).status).toBe("waiting");
});

test("custom-source price objects are captured before backend awaits", async () => {
  const raw = { orderRef: "custom-store-order", amountMsat: "12345000" };
  const source = { storeOrigin: store, readPayableOrder: async () => raw };
  const f = service(() => json(order()), { consumer: true, bindVerifiedOrders: true, source });
  source.readPayableOrder = async () => { throw new Error("Replaced source method must not run"); };
  f.state.onHealth = () => { raw.orderRef = "mutated-order"; raw.amountMsat = "1000"; };
  const result = await f.checkout({ orderKey }); expect(result.status).toBe(200);
  const view = await result.json() as View;
  expect(f.ledger.getIntent(view.id).order_ref).toBe("custom-store-order");
  expect(view.attempt!.terms.amountMsat).toBe("12345000");
  expect(f.consumer!.getOrder("custom-store-order").state).toBe("waiting");
  expect(() => f.consumer!.getOrder("mutated-order")).toThrow();
});

test("configuration mutation cannot enable bindings or change captured invoice lifetime", async () => {
  const f = service(() => json(order()), { consumer: true });
  const source = { storeOrigin: store, readPayableOrder: async () => ({ orderRef: "configuration-order", amountMsat: "12345000" }) };
  const commerce = { source, intentTtlSeconds: 600, orderKeyGrantsStatusAccess: true as const, bindVerifiedOrders: false };
  const identity = f.ledger.identity;
  const merchant = createMerchantService({ ledger: f.ledger, acceptanceConsumer: f.consumer, wooCommerce: commerce,
    issuer: { identity: async () => identity, create: async (operation) => testInvoice(operation.operationId, operation.amountMsat) },
    observer: { identity: async () => identity, lookup: async () => { throw new Error("unused"); } },
    adminToken: "a".repeat(43), statusKey: new Uint8Array(32).fill(2), eventSigningKey: new Uint8Array(32).fill(3), now: () => 1200 });
  commerce.bindVerifiedOrders = true; commerce.intentTtlSeconds = 60;
  source.readPayableOrder = async () => { throw new Error("Replaced source must not run"); };
  const result = await merchant.fetch(new Request("https://merchant.example/v1/woocommerce/orders/42/checkout", {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ orderKey }),
  }));
  expect(result.status).toBe(200); const view = await result.json() as View;
  expect(view.attempt).toBeNull();
  expect(f.ledger.getIntent(view.id).expires_at).toBe(1800);
  expect(() => f.consumer!.getOrder("configuration-order")).toThrow();
});

test("malformed custom-source prices refuse before backend work or persistence", async () => {
  for (const raw of [null, {}, { orderRef: "", amountMsat: "1000" }, { orderRef: "bad\nreference", amountMsat: "1000" },
    { orderRef: "order", amountMsat: 1000 }, { orderRef: "order", amountMsat: "0" }, { orderRef: "order", amountMsat: "1001" },
    { orderRef: "order", amountMsat: "2100000000000001000" }]) {
    const source = { storeOrigin: store, readPayableOrder: async () => raw as never };
    const f = service(() => json(order()), { consumer: true, bindVerifiedOrders: true, source });
    expect((await f.checkout({ orderKey })).status).toBe(503);
    expect(f.state.health).toBe(0); expect(f.ledger.pendingAttempts()).toHaveLength(0);
    expect(f.ledger.intentForOrder("order")).toBeNull();
  }
});

test("stored invoice amount is reverified before creating a consumer binding", async () => {
  const f = service(() => json(order()), { consumer: true });
  const original = await (await f.checkout({ orderKey })).json() as View;
  const attempt = f.ledger.attemptForIntent(original.id)!;
  const db = new Database(f.ledgerPath, { readwrite: true, create: false });
  try { db.query("UPDATE attempts SET invoice=? WHERE id=?").run(testInvoice(attempt.operation_id, "1000", 1000, 2000, "bcrt", attempt.payment_hash!), attempt.id); }
  finally { db.close(); }
  f.setBindingPolicy(true);
  expect((await f.checkout({ orderKey })).status).toBe(503);
  expect(() => f.consumer!.getOrder(f.ledger.getIntent(original.id).order_ref)).toThrow();
});

test("simultaneous verified checkouts replay the same binding and issuer operation", async () => {
  const f = service(() => json(order()), { consumer: true, bindVerifiedOrders: true });
  const responses = await Promise.all([f.checkout({ orderKey }), f.checkout({ orderKey })]);
  expect(responses.map((response) => response.status)).toEqual([200, 200]);
  const views = await Promise.all(responses.map((response) => response.json() as Promise<View>));
  expect(views[0]!.id).toBe(views[1]!.id); expect(views[0]!.attempt!.invoice).toBe(views[1]!.attempt!.invoice);
  const intent = f.ledger.getIntent(views[0]!.id);
  expect(f.consumer!.getOrder(intent.order_ref).state).toBe("waiting"); expect(new Set(f.state.operations).size).toBe(1);
});

test("unconfigured services keep the route absent and reject invalid options", async () => {
  const f = service(() => json(order()), { configured: false });
  expect((await f.checkout({ orderKey })).status).toBe(404);
  expect(f.ledger.intentForOrder(await f.refFor(store))).toBeNull();
  const base = { ledger: f.ledger, issuer: { identity: async () => f.ledger.identity, create: async () => "" },
    observer: { identity: async () => f.ledger.identity, lookup: async () => { throw new Error("unused"); } },
    adminToken: "a".repeat(43), statusKey: new Uint8Array(32).fill(2), eventSigningKey: new Uint8Array(32).fill(3) };
  const source = createWooCommerceOrderSource({ storeOrigin: store, consumerKey: key, consumerSecret: secret });
  for (const wooCommerce of [{ source, intentTtlSeconds: 59, orderKeyGrantsStatusAccess: true }, { source, intentTtlSeconds: 86_401, orderKeyGrantsStatusAccess: true },
    { source, intentTtlSeconds: 1.5, orderKeyGrantsStatusAccess: true }, { source: {}, intentTtlSeconds: 600, orderKeyGrantsStatusAccess: true },
    { source, intentTtlSeconds: 600 }, { source, intentTtlSeconds: 600, orderKeyGrantsStatusAccess: "yes" }, null]) {
    expect(() => createMerchantService({ ...base, wooCommerce } as never)).toThrow("Invalid WooCommerce checkout options");
  }
  for (const flag of [true, "yes", 1, null]) {
    expect(() => createMerchantService({ ...base, wooCommerce: { source, intentTtlSeconds: 600, orderKeyGrantsStatusAccess: true, bindVerifiedOrders: flag } } as never)).toThrow("Invalid WooCommerce checkout options");
  }
});
