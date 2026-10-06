import { expect, test } from "bun:test";
import { LnurlInvoiceAcquisitionError, requestLnurlPayInvoice, type LnurlInvoiceExpectation, type LnurlPayDescriptor, type LnurlPayTransport } from "../src/lnurlPay";
import { receiver, testInvoice } from "./helpers";

const origin = "https://receiver.example", secret = "PRIVATE_CALLBACK_CAPABILITY";
function fixture() {
  const metadata = '[["text/plain","Receiver"],["text/identifier","buyer@receiver.example"]]';
  const descriptor: LnurlPayDescriptor = { version: "lnurl-pay-request/1", lightningAddress: "buyer@receiver.example", receiverOrigin: origin,
    callback: origin + "/invoice?k1=" + secret, metadata, description: "Receiver", minSendableMsat: "1", maxSendableMsat: "1000000" };
  const expected: Omit<LnurlInvoiceExpectation, "now"> = { networkName: "regtest", amountMsat: "1000000", payee: receiver, minExpiresAt: 2000, metadataHashPolicy: "not_required" };
  const invoice = testInvoice("callback"), calls: { url: string; init: RequestInit | undefined }[] = [];
  const state = { before: 1000, after: 1001, response: () => Response.json({ pr: invoice, routes: [] }), onInvoke: () => {} };
  let samples = 0;
  const transport: LnurlPayTransport = async (url, init) => {
    calls.push({ url: String(url), init }); state.onInvoke(); return state.response();
  };
  const clock = () => samples++ === 0 ? state.before : state.after;
  return { descriptor, expected, invoice, calls, state, transport, clock,
    acquire: () => requestLnurlPayInvoice(descriptor, expected, [origin], clock, transport) };
}
async function refusal(promise: Promise<unknown>, state: LnurlInvoiceAcquisitionError["state"]) {
  try { await promise; throw new Error("must refuse"); }
  catch (error) {
    expect(error).toBeInstanceOf(LnurlInvoiceAcquisitionError);
    expect((error as LnurlInvoiceAcquisitionError).state).toBe(state);
    expect((error as Error).message).toBe(state === "not_requested" ? "LNURL invoice request was not invoked" : "LNURL invoice issuance is unknown");
    expect((error as Error).cause).toBeUndefined(); expect(JSON.stringify(error)).not.toContain(secret);
  }
}

test("one explicit callback GET preserves capabilities and adds only the original pinned amount", async () => {
  const f = fixture(), result = await f.acquire();
  expect(result.invoice).toBe(f.invoice); expect(result.binding.payee_compressed_pubkey).toBe(receiver);
  expect(Object.isFrozen(result) && Object.isFrozen(result.binding)).toBe(true);
  expect(f.calls.length).toBe(1);
  const url = new URL(f.calls[0]!.url); expect(url.pathname).toBe("/invoice"); expect(url.searchParams.get("k1")).toBe(secret);
  expect([...url.searchParams.entries()]).toEqual([["k1", secret], ["amount", "1000000"]]);
  expect(f.calls[0]!.init).toMatchObject({ method: "GET", credentials: "omit", referrerPolicy: "no-referrer", redirect: "error", cache: "no-store" });
  expect(JSON.stringify(result)).not.toContain(secret);
});

test("explicit strict metadata mode validates the returned signed hash without changing ordinary mode", async () => {
  const f = fixture(); Object.assign(f.expected, { metadataHashPolicy: "strict_hash" });
  f.state.response = () => Response.json({ pr: testInvoice("hashed", "1000000", 1000, 2000, "bcrt", undefined, f.descriptor.metadata), routes: [] });
  expect((await f.acquire()).metadataHashPolicy).toBe("strict_hash"); expect(f.calls.length).toBe(1);
});

test("adding the amount retains existing escaped capability query bytes and duplicate values", async () => {
  const f = fixture(), callback = origin + "/invoice?k1=A%20B+C%2b%2B%2f%2F&token=x%26y%3dz&empty=&repeat=a&repeat=b";
  Object.assign(f.descriptor, { callback }); await f.acquire();
  expect(f.calls[0]!.url).toBe(callback + "&amount=1000000"); expect(f.calls.length).toBe(1);
});

test("invalid preflight does not invoke transport and cannot leak a callback capability", async () => {
  for (const changed of [{ amountMsat: "01" }, { amountMsat: "1000001" }, { payee: "not-key" }, { minExpiresAt: 1000 },
    { metadataHashPolicy: undefined }, { networkName: "not-network" }]) {
    const f = fixture(); Object.assign(f.expected, changed); await refusal(f.acquire(), "not_requested"); expect(f.calls.length).toBe(0);
  }
  for (const changed of [{ callback: origin + "/invoice?amount=1&k1=" + secret }, { callback: "https://delegated.example/invoice" },
    { receiverOrigin: origin + "/path" }, { callback: "http://receiver.example/" }, { maxSendableMsat: "999000" }, { metadata: "\ud800" }]) {
    const f = fixture(); Object.assign(f.descriptor, changed); await refusal(f.acquire(), "not_requested"); expect(f.calls.length).toBe(0);
  }
  for (const before of [-1, NaN, 1000.5]) {
    const f = fixture(); f.state.before = before; await refusal(f.acquire(), "not_requested"); expect(f.calls.length).toBe(0);
  }
  const f = fixture(); await refusal(requestLnurlPayInvoice(f.descriptor, f.expected, [origin], () => 1000), "not_requested");
});

test("every failed response after invocation is unknown issuance with no retry or lookup", async () => {
  const redirected = () => { const value = Response.json({}); Object.defineProperty(value, "redirected", { value: true }); return value; };
  const moved = () => { const value = Response.json({}); Object.defineProperty(value, "url", { value: "https://other.example/private" }); return value; };
  const responses = [
    () => { throw new Error("PRIVATE_UPSTREAM_REASON " + secret); },
    () => new Response("private", { status: 500 }), () => Response.json({ status: "ERROR", reason: secret }),
    () => new Response("not-json", { headers: { "Content-Type": "application/json" } }),
    () => new Response('{"pr":"x","pr":"y","routes":[]}', { headers: { "Content-Type": "application/json" } }),
    () => Response.json({ pr: testInvoice("wrong-amount", "999000"), routes: [] }),
    () => Response.json({ pr: "bad-invoice " + secret, routes: [] }),
    () => new Response(new Uint8Array(65537), { headers: { "Content-Type": "application/json" } }),
    redirected, moved,
  ];
  for (const response of responses) {
    const f = fixture(); f.state.response = response; await refusal(f.acquire(), "issuance_unknown"); expect(f.calls.length).toBe(1);
  }
  const strict = fixture(); Object.assign(strict.expected, { metadataHashPolicy: "strict_hash" });
  await refusal(strict.acquire(), "issuance_unknown"); expect(strict.calls.length).toBe(1);
});

test("completed fresh time rejects expired, future-created or insufficient-lifetime invoices", async () => {
  for (const after of [999, NaN, 2000]) {
    const f = fixture(); f.state.after = after; await refusal(f.acquire(), "issuance_unknown"); expect(f.calls.length).toBe(1);
  }
  const f = fixture(); f.state.response = () => Response.json({ pr: testInvoice("future", "1000000", 1002), routes: [] });
  await refusal(f.acquire(), "issuance_unknown"); expect(f.calls.length).toBe(1);
  const expired = fixture(); Object.assign(expired.expected, { minExpiresAt: 1001 }); expired.state.after = 1002;
  expired.state.response = () => Response.json({ pr: testInvoice("expired", "1000000", 1000, 1001), routes: [] });
  await refusal(expired.acquire(), "issuance_unknown"); expect(expired.calls.length).toBe(1);
});

test("caller mutation after invocation cannot change the original payee, amount, metadata or policy", async () => {
  const f = fixture(); f.state.onInvoke = () => {
    Object.assign(f.expected, { amountMsat: "999000", payee: "03" + "ab".repeat(32), metadataHashPolicy: "strict_hash", minExpiresAt: 9999 });
    Object.assign(f.descriptor, { metadata: "changed", maxSendableMsat: "1", callback: "https://unapproved.example" });
  };
  const result = await f.acquire(); expect(result.binding.amount_msat).toBe("1000000"); expect(result.metadataHashPolicy).toBe("not_required");
  expect(result.binding.payee_compressed_pubkey).toBe(receiver); expect(f.calls.length).toBe(1);
});

test("transport abort after invocation remains unknown, including aborted body cleanup", async () => {
  const previous = AbortSignal.timeout, controller = new AbortController();
  AbortSignal.timeout = () => controller.signal;
  const f = fixture(); let canceled = false;
  const stream = new ReadableStream<Uint8Array>({ cancel() { canceled = true; return new Promise<void>(() => {}); } });
  f.state.response = () => new Response(stream, { headers: { "Content-Type": "application/json" } });
  try {
    const pending = f.acquire(); await Promise.resolve(); await Promise.resolve(); controller.abort();
    await refusal(pending, "issuance_unknown"); expect(f.calls.length).toBe(1); expect(canceled).toBe(true); expect(stream.locked).toBe(false);
  } finally { AbortSignal.timeout = previous; }
});

test("elapsed budget guards results even if the abort event has not been delivered", async () => {
  const own = Object.getOwnPropertyDescriptor(performance, "now");
  try {
    for (const end of [10000, 10001, -1, NaN]) {
      const f = fixture(); let samples = 0;
      Object.defineProperty(performance, "now", { configurable: true, value: () => samples++ === 0 ? 0 : end });
      await refusal(f.acquire(), "issuance_unknown"); expect(f.calls.length).toBe(1);
    }
    const f = fixture(); Object.defineProperty(performance, "now", { configurable: true, value: () => NaN });
    await refusal(f.acquire(), "not_requested"); expect(f.calls.length).toBe(0);
  } finally {
    if (own) Object.defineProperty(performance, "now", own); else Reflect.deleteProperty(performance, "now");
  }
});
