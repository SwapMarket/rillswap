import { expect, test } from "bun:test";
import { createCheckout, type CheckoutCheckpoint, type CheckoutOptions, type IntentView } from "../src/sdk";
import { invoiceBinding } from "../src/bolt11";
import { receiver, testInvoice } from "./helpers";

const origin = "https://merchant.example", id = "bounded_intent_001", url = origin + "/v1/intents/" + id;
const view: IntentView = { version: "checkout-view/1", id, status: "waiting", attempt: {
  invoice: testInvoice("bounded-read", "1000000", 1000, 1100), terms: { version: "checkout/0.1", policyVersion: "native-lightning/1", merchantOrigin: origin,
    intentId: id, attemptId: "bounded_attempt_001", network: "regtest", amountMsat: "1000000", paymentHash: "", receiver, expiresAt: 1100, buyerExtraMsat: "0" } } };
// Derive the independent fixture hash, never adopt a remote view's pins.
const validView: IntentView = { ...view, attempt: { ...view.attempt!, terms: { ...view.attempt!.terms, paymentHash: invoiceBinding(view.attempt!.invoice, "regtest").payment_hash } } };
const fresh = () => Response.json(validView);
function fixture(fetch?: CheckoutOptions["fetch"], merchantReadTimeoutMs?: number) {
  const calls = { wallet: 0, begin: 0, update: 0, load: 0 }; let record: CheckoutCheckpoint | null = null;
  const options: CheckoutOptions = { intentUrl: url, statusToken: "bounded_status_token_0000000000001",
    policy: { version: "native-lightning/1", merchantOrigin: origin, receiver, network: "regtest", maxBuyerExtraMsat: "0", maxBuyerExtraBps: 0 },
    wallet: { canLimitFees: true, payInvoice: async () => { calls.wallet++; } },
    recoveryStore: { load: async () => { calls.load++; return record; }, begin: async (next) => { calls.begin++; if (record) return false; record = next; return true; },
      update: async (next) => { calls.update++; record = next; } }, now: () => 1000,
    ...(fetch ? { fetch } : {}), ...(merchantReadTimeoutMs !== undefined ? { merchantReadTimeoutMs } : {}) };
  return { options, calls, record: () => record };
}
function deferred<T>() { let resolve!: (value: T) => void; const promise = new Promise<T>((done) => { resolve = done; }); return { promise, resolve }; }
const delay = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

test("trusted URL-less transport retains canonical views and receives bounded private GET policy", async () => {
  let requests = 0, signal: AbortSignal | undefined;
  const f = fixture(async (input, init) => {
    requests++; expect(String(input)).toBe(url); expect(init?.redirect).toBe("error"); expect(init?.cache).toBe("no-store");
    expect(init?.credentials).toBe("omit"); expect(init?.referrerPolicy).toBe("no-referrer");
    expect(new Headers(init?.headers).get("Accept")).toBe("application/json");
    expect(new Headers(init?.headers).get("Authorization")).toBe("Bearer " + f.options.statusToken);
    signal = init?.signal as AbortSignal; expect(signal).toBeInstanceOf(AbortSignal);
    return Response.json(validView, { headers: { "Content-Type": "Application/JSON ; charset=utf-8" } });
  });
  expect(await createCheckout(f.options).open()).toEqual(validView); expect(requests).toBe(1); expect(signal?.aborted).toBe(false);
  expect(f.calls).toEqual({ wallet: 0, begin: 0, update: 0, load: 1 }); expect(f.record()).toBeNull();
});

test("invalid read budgets and transports refuse before acquisition, storage or wallet work", () => {
  let requests = 0; const f = fixture(async () => { requests++; return fresh(); });
  for (const value of [0, -1, 30_001, 1.5, NaN, Infinity, null, "1000", true]) {
    expect(() => createCheckout({ ...f.options, merchantReadTimeoutMs: value } as unknown as CheckoutOptions)).toThrow("read budget");
  }
  for (const fetch of [null, 1, {}]) expect(() => createCheckout({ ...f.options, fetch } as unknown as CheckoutOptions)).toThrow("merchant transport");
  expect(requests).toBe(0); expect(f.calls).toEqual({ wallet: 0, begin: 0, update: 0, load: 0 });
});

test("timeout releases only the acquisition gate, late headers never consume a body or grant dispatch", async () => {
  const late = deferred<Response>(); let requests = 0, signal: AbortSignal | undefined, pulls = 0, canceled = 0;
  const f = fixture(async (_input, init) => { requests++; signal = init?.signal as AbortSignal; return requests === 1 ? late.promise : fresh(); }, 20);
  const checkout = createCheckout(f.options), events: string[] = []; checkout.on("progress", (event) => events.push(event.state));
  await expect(checkout.pay()).rejects.toThrow("Merchant status unavailable");
  expect(signal?.aborted).toBe(true); expect(f.calls).toEqual({ wallet: 0, begin: 0, update: 0, load: 0 }); expect(f.record()).toBeNull();
  late.resolve(new Response(new ReadableStream<Uint8Array>({ pull() { pulls++; }, cancel() { canceled++; } }, { highWaterMark: 0 }), { headers: { "Content-Type": "application/json" } }));
  await delay(10); expect(pulls).toBe(0); expect(canceled).toBe(1); expect(events).toEqual([]); expect(f.record()).toBeNull();
  await checkout.pay(); expect(f.calls.wallet).toBe(1); expect(f.record()?.stage).toBe("observing");
  await expect(checkout.pay()).rejects.toThrow("already dispatched"); expect(f.calls.wallet).toBe(1);
});

test("body stall and never-finishing cancellation cannot hold payment acquisition indefinitely", async () => {
  let canceled = 0; const f = fixture(async () => new Response(new ReadableStream<Uint8Array>({ cancel() { canceled++; return new Promise<void>(() => {}); } }, { highWaterMark: 0 }),
    { headers: { "Content-Type": "application/json" } }), 20);
  const checkout = createCheckout(f.options), started = performance.now();
  await expect(checkout.pay()).rejects.toThrow("Merchant status unavailable");
  expect(performance.now() - started).toBeLessThan(1000); expect(canceled).toBe(1); expect(f.record()).toBeNull(); expect(f.calls.wallet).toBe(0); expect(f.calls.begin).toBe(0);
});

test("monotonic admission rejects a blocked-event-loop response before a timer can fire", async () => {
  const f = fixture(async () => { const until = performance.now() + 25; while (performance.now() < until) {} return fresh(); }, 10);
  await expect(createCheckout(f.options).pay()).rejects.toThrow("Merchant status unavailable"); expect(f.record()).toBeNull(); expect(f.calls.wallet).toBe(0);
});

test("redirected, foreign-delivery, non-200, non-JSON and invalid UTF-8 responses fail before dispatch", async () => {
  const responses = [
    () => { const response = fresh(); Object.defineProperty(response, "redirected", { value: true }); return response; },
    () => { const response = fresh(); Object.defineProperty(response, "url", { value: "https://foreign.example/v1/intents/" + id }); return response; },
    () => { const response = fresh(); Object.defineProperty(response, "url", { value: url + "?unexpected=1" }); return response; },
    () => Response.json(validView, { status: 202 }),
    () => new Response(JSON.stringify(validView)),
    () => new Response(new Uint8Array([0xff]), { headers: { "Content-Type": "application/json" } }),
  ];
  for (const response of responses) {
    const f = fixture(async () => response()); await expect(createCheckout(f.options).pay()).rejects.toThrow("Merchant status unavailable");
    expect(f.record()).toBeNull(); expect(f.calls.wallet).toBe(0); expect(f.calls.begin).toBe(0);
  }
});

test("actual body bytes, not declared length or characters, enforce the response cap", async () => {
  let canceled = 0;
  const f = fixture(async () => new Response(new ReadableStream<Uint8Array>({ start(controller) { controller.enqueue(new TextEncoder().encode(JSON.stringify({ ...validView, padding: "é".repeat(4096) }))); },
    cancel() { canceled++; } }), { headers: { "Content-Type": "application/json", "Content-Length": "1" } }));
  await expect(createCheckout(f.options).pay()).rejects.toThrow("Merchant status unavailable"); expect(canceled).toBe(1); expect(f.record()).toBeNull(); expect(f.calls.wallet).toBe(0);
  const base = JSON.stringify({ ...validView, padding: "" }), exact = JSON.stringify({ ...validView, padding: "x".repeat(8192 - new TextEncoder().encode(base).byteLength) });
  expect(new TextEncoder().encode(exact).byteLength).toBe(8192);
  const bounded = fixture(async () => new Response(exact, { headers: { "Content-Type": "application/json", "Content-Length": "999999" } }));
  expect(await createCheckout(bounded.options).open()).toEqual(validView);
});

test("the default fetch requires actual matching delivery URLs, unlike explicitly injected fixtures", async () => {
  const original = globalThis.fetch; let matching = false;
  try {
    globalThis.fetch = (async () => { const response = fresh(); if (matching) Object.defineProperty(response, "url", { value: url }); return response; }) as unknown as typeof fetch;
    const f = fixture(); await expect(createCheckout(f.options).open()).rejects.toThrow("Merchant status unavailable");
    matching = true; expect(await createCheckout(f.options).open()).toEqual(validView); expect(f.record()).toBeNull(); expect(f.calls.wallet).toBe(0);
  } finally { globalThis.fetch = original; }
});

test("the timeout is captured once and no late acquisition emits merchant-paid progress", async () => {
  const late = deferred<Response>(), f = fixture(async () => late.promise); let reads = 0;
  const checkout = createCheckout({ ...f.options, get merchantReadTimeoutMs() { reads++; return reads === 1 ? 20 : 30_000; } });
  const events: string[] = []; checkout.on("progress", (event) => events.push(event.state));
  await expect(checkout.open()).rejects.toThrow("Merchant status unavailable");
  late.resolve(Response.json({ version: "checkout-view/1", id, status: "paid", attempt: null })); await delay(10);
  expect(reads).toBe(1); expect(events).toEqual([]); expect(f.calls).toEqual({ wallet: 0, begin: 0, update: 0, load: 0 });
});

test("failed status refresh retains an older dispatched checkpoint and duplicate-payment refusal", async () => {
  let reads = 0; const f = fixture(async () => ++reads === 2 ? new Promise<Response>(() => {}) : fresh(), 20);
  const checkout = createCheckout(f.options); await checkout.pay(); const original = JSON.stringify(f.record());
  await expect(checkout.open()).rejects.toThrow("Merchant status unavailable");
  expect(JSON.stringify(f.record())).toBe(original); expect(f.record()?.stage).toBe("observing"); expect(f.calls.wallet).toBe(1);
  await expect(checkout.pay()).rejects.toThrow("already dispatched"); expect(f.calls.wallet).toBe(1); expect(JSON.stringify(f.record())).toBe(original);
});

test("transport and body errors are sanitized without changing dispatch state", async () => {
  for (const transport of [async () => { throw new Error("PRIVATE_TRANSPORT_CAPABILITY"); },
    async () => new Response(new ReadableStream<Uint8Array>({ start(controller) { controller.error(new Error("PRIVATE_BODY_PAYLOAD")); } }), { headers: { "Content-Type": "application/json" } })]) {
    const f = fixture(transport); await expect(createCheckout(f.options).pay()).rejects.toThrow("Merchant status unavailable");
    expect(f.record()).toBeNull(); expect(f.calls.wallet).toBe(0); expect(f.calls.begin).toBe(0);
  }
});

test("empty stream chunks are ignored while bounded JSON data is retained", async () => {
  const f = fixture(async () => new Response(new ReadableStream<Uint8Array>({ start(controller) {
    for (let i = 0; i < 64; i++) controller.enqueue(new Uint8Array());
    controller.enqueue(new TextEncoder().encode(JSON.stringify(validView))); controller.close();
  } }), { headers: { "Content-Type": "application/json" } }));
  expect(await createCheckout(f.options).open()).toEqual(validView); expect(f.record()).toBeNull(); expect(f.calls.wallet).toBe(0);
});
