import { expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { createWooCommerceFulfillment, type AcceptedOrderSource } from "../src/woocommerce";

const store = "https://shop.example", key = "ck_" + "a".repeat(40), secret = "cs_" + "b".repeat(40);
const tag = createHash("sha256").update("woocommerce-store/1:" + store).digest("hex").slice(0, 32);
const ref = `woocommerce:${tag}:42`, hash = "ab".repeat(32), url = store + "/wp-json/wc/v3/orders/42";
const pending = { id: 42, status: "pending", currency: "BTC", total: "0.00012345", transaction_id: "", date_paid_gmt: null };
const paid = { ...pending, status: "processing", transaction_id: hash, date_paid_gmt: "2026-10-06T12:00:00" };
const json = (value: unknown, status = 200) => new Response(JSON.stringify(value), { status, headers: { "Content-Type": "application/json" } });
const accepted = (value: ReturnType<AcceptedOrderSource["acceptedOrder"]> = { orderRef: ref, amountMsat: "12345000", paymentHash: hash, eventId: "event_1" }): AcceptedOrderSource => ({ acceptedOrder: () => value });

/** Fake store applying WooCommerce's REST set_paid semantics to one order. */
function fakeStore(initial: Record<string, unknown>, hooks: { onPut?: (order: Record<string, unknown>) => void; failPut?: boolean; failGetAfterPut?: boolean } = {}) {
  let order = { ...initial }; const calls: { method: string; body?: unknown }[] = []; let wrote = false;
  const fetch = async (input: string, init: RequestInit) => {
    expect(input).toBe(url); expect(init.redirect).toBe("error");
    expect((init.headers as Record<string, string>).Authorization).toBe("Basic " + Buffer.from(key + ":" + secret).toString("base64"));
    calls.push({ method: init.method!, body: init.body ? JSON.parse(init.body as string) : undefined });
    if (init.method === "GET") { if (wrote && hooks.failGetAfterPut) return json({}, 500); return json(order); }
    hooks.onPut?.(order); order = { ...order };
    const body = JSON.parse(init.body as string) as { set_paid: boolean; transaction_id: string };
    order.transaction_id = body.transaction_id; wrote = true;
    if (body.set_paid && ["pending", "failed"].includes(order.status as string)) { order.status = "processing"; order.date_paid_gmt = "2026-10-06T12:00:00"; }
    if (hooks.failPut) throw new Error("connection reset after dispatch");
    return json(order);
  };
  return { fetch, calls, get order() { return order; }, set order(value) { order = value; } };
}
const build = (s: ReturnType<typeof fakeStore>, acceptances = accepted()) =>
  createWooCommerceFulfillment({ storeOrigin: store, consumerKey: key, consumerSecret: secret, fetch: s.fetch, acceptances, testStoreOnly: true });

test("a pending exact-price order is marked paid once with the payment hash, then replays without writing", async () => {
  const s = fakeStore(pending), f = build(s);
  expect(await f.fulfill(ref)).toEqual({ outcome: "fulfilled", orderRef: ref, transactionId: hash, wrote: true });
  expect(s.calls.map((c) => c.method)).toEqual(["GET", "PUT", "GET"]);
  expect(s.calls[1]!.body).toEqual({ set_paid: true, transaction_id: hash }); // never a status field
  expect(await f.fulfill(ref)).toEqual({ outcome: "fulfilled", orderRef: ref, transactionId: hash, wrote: false });
  expect(s.calls).toHaveLength(4);
});

test("store state differing from the acceptance is never written", async () => {
  for (const [order, reason] of [
    [{ ...pending, status: "cancelled" }, "status"], [{ ...pending, status: "failed" }, "status"], [{ ...pending, status: "on-hold" }, "status"],
    [{ ...paid, transaction_id: "cd".repeat(32) }, "status"], [{ ...pending, total: "0.00012346" }, "price"], [{ ...pending, currency: "USD" }, "price"],
    [{ ...pending, transaction_id: "other" }, "transaction"], [{ ...paid, total: "0.0002" }, "status"],
  ] as const) {
    const s = fakeStore(order);
    expect(await build(s).fulfill(ref)).toEqual({ outcome: "reconciliation_required", orderRef: ref, reason });
    expect(s.calls.map((c) => c.method)).toEqual(["GET"]);
  }
  const missing = fakeStore(pending); missing.order = {};
  const f = createWooCommerceFulfillment({ storeOrigin: store, consumerKey: key, consumerSecret: secret, acceptances: accepted(), testStoreOnly: true,
    fetch: async () => json({ code: "woocommerce_rest_shop_order_invalid_id" }, 404) });
  expect(await f.fulfill(ref)).toEqual({ outcome: "reconciliation_required", orderRef: ref, reason: "missing" });
});

test("paid evidence requires processing/completed, our transaction ID, exact total and a valid paid time", async () => {
  for (const order of [{ ...paid, date_paid_gmt: null }, { ...paid, date_paid_gmt: "yesterday" }, { ...paid, date_paid_gmt: "2026-13-45T99:99:99" }]) {
    const s = fakeStore(order); const result = await build(s).fulfill(ref);
    expect(result.outcome).toBe("reconciliation_required"); expect(s.calls).toHaveLength(1);
  }
  const done = fakeStore({ ...paid, status: "completed" });
  expect((await build(done).fulfill(ref)).outcome).toBe("fulfilled");
});

test("unaccepted orders and foreign references never reach the store", async () => {
  const s = fakeStore(pending);
  expect(await build(s, accepted(null)).fulfill(ref)).toEqual({ outcome: "not_accepted", orderRef: ref });
  for (const bad of [`woocommerce:${"0".repeat(32)}:42`, `woocommerce:${tag}:0`, `woocommerce:${tag}:4x`, `woocommerce:${tag}:9007199254740993`, "order-1", 42]) {
    await expect(build(s).fulfill(bad as string)).rejects.toThrow("does not belong");
  }
  await expect(build(s, accepted({ orderRef: ref, amountMsat: "12345000", paymentHash: "not-a-hash", eventId: "e" })).fulfill(ref)).rejects.toThrow("Invalid accepted order");
  expect(s.calls).toHaveLength(0);
});

test("read failures write nothing; failures after dispatch are unknown; failed read-back is unconfirmed", async () => {
  const down = createWooCommerceFulfillment({ storeOrigin: store, consumerKey: key, consumerSecret: secret, acceptances: accepted(), testStoreOnly: true, fetch: async () => json({}, 503) });
  expect(await down.fulfill(ref)).toEqual({ outcome: "unavailable", orderRef: ref });
  const lost = fakeStore(pending, { failPut: true });
  expect(await build(lost).fulfill(ref)).toEqual({ outcome: "unknown", orderRef: ref });
  expect(lost.order.status).toBe("processing"); // the write committed despite the lost response
  const blind = fakeStore(pending, { failGetAfterPut: true });
  expect(await build(blind).fulfill(ref)).toEqual({ outcome: "unknown", orderRef: ref });
  // Store cancels between our read and write: completion is skipped, our ID lands.
  const raced = fakeStore(pending, { onPut: (order) => { order.status = "cancelled"; } });
  expect(await build(raced).fulfill(ref)).toEqual({ outcome: "write_unconfirmed", orderRef: ref });
  expect(raced.order.status).toBe("cancelled");
});

test("a write that outlives the deadline is unknown even though the store changes later", async () => {
  let order: Record<string, unknown> = { ...pending }, release!: () => void;
  const landed = new Promise<void>((resolve) => { release = resolve; });
  const f = createWooCommerceFulfillment({ storeOrigin: store, consumerKey: key, consumerSecret: secret, acceptances: accepted(), testStoreOnly: true, timeoutMs: 50,
    fetch: async (_input, init) => {
      if (init.method === "GET") return json(order);
      // The store keeps executing after the client gave up.
      setTimeout(() => { order = { ...order, status: "processing", transaction_id: hash, date_paid_gmt: "2026-10-06T12:00:00" }; release(); }, 120);
      return new Promise<Response>(() => {});
    } });
  expect(await f.fulfill(ref)).toEqual({ outcome: "unknown", orderRef: ref });
  expect(order.status).toBe("pending"); // a read now would still look unwritten
  await landed;
  expect(order.status).toBe("processing");
  expect(await f.fulfill(ref)).toEqual({ outcome: "fulfilled", orderRef: ref, transactionId: hash, wrote: false });
});

test("concurrent calls on one adapter instance share a single write", async () => {
  const s = fakeStore(pending), f = build(s);
  const [a, b] = await Promise.all([f.fulfill(ref), f.fulfill(ref)]);
  expect(a).toEqual(b); expect(s.calls.filter((c) => c.method === "PUT")).toHaveLength(1);
});

test("construction requires the test-store acknowledgment, acceptances and valid credentials", () => {
  const base = { storeOrigin: store, consumerKey: key, consumerSecret: secret, acceptances: accepted(), testStoreOnly: true as const };
  for (const bad of [{ ...base, testStoreOnly: "yes" }, { ...base, testStoreOnly: undefined }, { ...base, acceptances: {} }, null]) {
    expect(() => createWooCommerceFulfillment(bad as never)).toThrow("Invalid WooCommerce fulfillment options");
  }
  expect(() => createWooCommerceFulfillment({ ...base, storeOrigin: "http://shop.example" })).toThrow("origin");
  expect(() => createWooCommerceFulfillment({ ...base, consumerSecret: "bad" })).toThrow("credentials");
});
