import { expect, test } from "bun:test";
import { discoverLightningAddress, type LnurlPayTransport } from "../src/lnurlPay";

const origin = "https://receiver.example", address = "buyer+tag@receiver.example";
const metadata = '[ ["text/plain", "Receiver description"], ["text/identifier", "buyer@receiver.example"], ["unknown", {"a":["{\\\"key\\\":1}"]}] ]';
const descriptor = () => ({ tag: "payRequest", minSendable: 1, maxSendable: 1000000, metadata, callback: origin + "/invoice?k1=opaque-capability" });
const response = (body: string, status = 200, contentType = "application/json") => new Response(body, { status, headers: { "Content-Type": contentType } });
const good = () => response(JSON.stringify(descriptor()));

test("one pinned discovery GET preserves raw metadata and never invokes invoice callback", async () => {
  const calls: [string, RequestInit | undefined][] = [];
  const transport: LnurlPayTransport = async (url, init) => { calls.push([String(url), init]); return good(); };
  const result = await discoverLightningAddress(address, [origin], transport);
  expect(calls.length).toBe(1); expect(calls[0]![0]).toBe(origin + "/.well-known/lnurlp/buyer%2Btag");
  expect(calls[0]![1]).toMatchObject({ method: "GET", redirect: "error", credentials: "omit", referrerPolicy: "no-referrer", cache: "no-store", headers: { Accept: "application/json" } });
  expect(calls[0]![1]!.signal).toBeInstanceOf(AbortSignal);
  expect(result).toEqual({ version: "lnurl-pay-request/1", lightningAddress: address, receiverOrigin: origin,
    callback: descriptor().callback, metadata, description: "Receiver description", minSendableMsat: "1", maxSendableMsat: "1000000" });
  expect(Object.isFrozen(result)).toBe(true);
  expect(Object.keys(result)).not.toContain("invoice"); expect(Object.keys(result)).not.toContain("paymentHash");
});

test("server default transport refuses and invalid local/address/origin profiles perform no fetch", async () => {
  let calls = 0;
  const transport = async () => { calls++; return good(); };
  await expect(discoverLightningAddress(address, [origin])).rejects.toThrow("trusted server transport");
  for (const invalid of ["Buyer@receiver.example", "buyer@LOCALHOST", "buyer@127.0.0.1", "buyer@[::1]", "buyer@receiver.local", "buyer@receiver.onion",
    "buyer@receiver.example:443", "buyer@receiver.example/path", "buyer@receiver.example\n", "buyer@receiver.example.", "a".repeat(65) + "@receiver.example"]) {
    await expect(discoverLightningAddress(invalid, [origin], transport)).rejects.toThrow();
  }
  for (const origins of [[], ["http://receiver.example"], [origin + "/"], ["https://user:secret@receiver.example"], ["https://receiver.example:8443"], ["https://other.example"]]) {
    await expect(discoverLightningAddress(address, origins, transport)).rejects.toThrow();
  }
  expect(calls).toBe(0);
  try { await discoverLightningAddress(address, ["PRIVATE_INVALID_ORIGIN_CANARY"], transport); throw new Error("must refuse"); }
  catch (error) { expect((error as Error).message).toBe("Invalid approved LNURL origin"); expect((error as Error).cause).toBeUndefined(); }
});

test("delegated callback origin needs independent approval and never performs another GET", async () => {
  const other = "https://delegated.example", data = { ...descriptor(), callback: other + "/invoice" };
  let calls = 0; const transport = async () => { calls++; return response(JSON.stringify(data)); };
  await expect(discoverLightningAddress(address, [origin], transport)).rejects.toThrow("unresolved");
  expect((await discoverLightningAddress(address, [origin, other], transport)).callback).toBe(data.callback);
  expect(calls).toBe(2); // One per explicit discovery, never callback retrieval or automatic retry.
});

test("callback credentials, fragments, amount aliases and host/port changes refuse", async () => {
  for (const callback of ["http://receiver.example/invoice", "https://user:secret@receiver.example/invoice", origin + "/invoice#",
    origin + "/invoice?amount=1", origin + "/invoice?am%6funt=1&amount=2", origin + ":8443/invoice", "https://127.0.0.1/invoice", origin + "/invo\nice", "https:\\receiver.example/invoice"]) {
    const transport = async () => response(JSON.stringify({ ...descriptor(), callback }));
    await expect(discoverLightningAddress(address, [origin], transport)).rejects.toThrow("unresolved");
  }
});

test("HTTP errors, media types, redirect evidence and private reasons remain unresolved", async () => {
  const redirected = good(); Object.defineProperty(redirected, "redirected", { value: true });
  const moved = good(); Object.defineProperty(moved, "url", { value: "https://other.example/" });
  const choices = [response(JSON.stringify(descriptor()), 500), response(JSON.stringify(descriptor()), 200, "text/plain"), redirected, moved,
    response(JSON.stringify({ status: "ERROR", reason: "PRIVATE_RESPONSE_CANARY" })), response("null")];
  for (const choice of choices) await expect(discoverLightningAddress(address, [origin], async () => choice)).rejects.toThrow("unresolved");
  const transport = async () => { throw new Error("PRIVATE_FETCH_CANARY"); };
  try { await discoverLightningAddress(address, [origin], transport); throw new Error("must refuse"); }
  catch (error) { expect((error as Error).message).toBe("LNURL discovery is unresolved"); expect((error as Error).cause).toBeUndefined(); }
});

test("ambiguous escaped/nested JSON keys refuse without misreading punctuation in strings", async () => {
  const valid = JSON.stringify(descriptor());
  for (const body of [valid.slice(0, -1) + ',"minSendable":2}', valid.slice(0, -1) + ',"min\\u0053endable":2}',
    valid.slice(0, -1) + ',"extension":[{"a":1,"a":2}]}', valid.slice(0, -1) + ',"extension":{"a":{"b":1,"b":2}}}']) {
    await expect(discoverLightningAddress(address, [origin], async () => response(body))).rejects.toThrow("unresolved");
  }
  const nested = "[".repeat(1000) + "0" + "]".repeat(1000);
  const data = valid.slice(0, -1) + ',"deep":' + nested + '}';
  expect((await discoverLightningAddress(address, [origin], async () => response(data))).metadata).toBe(metadata);
  const duplicateMetadata = { ...descriptor(), metadata: '[["text/plain","x"],["text/email","x"],["unknown",{"a":1,"\\u0061":2}]]' };
  await expect(discoverLightningAddress(address, [origin], async () => response(JSON.stringify(duplicateMetadata)))).rejects.toThrow("unresolved");
});

test("unsafe numeric ranges and invalid metadata profiles refuse", async () => {
  for (const change of [{ minSendable: 0 }, { minSendable: 1.5 }, { maxSendable: 0 }, { minSendable: 1000001 }, { maxSendable: 2 ** 53 },
    { maxSendable: "1000000" }, { tag: "withdrawRequest" }, { metadata: "[]" }, { metadata: '[["text/plain","x"]]' },
    { metadata: '[["text/plain",2],["text/email","x"]]' }, { metadata: '[["text/plain","x"],["text/plain","y"],["text/email","x"]]' },
    { metadata: '[["text/plain","x"],["text/email",null]]' }, { metadata: '[["text/plain","\\ud800"],["text/email","x"]]' },
    { metadata: '[["text/plain","x"],["text/email","x"],["unknown",0,1]]' }, { metadata: "x".repeat(16385) }]) {
    await expect(discoverLightningAddress(address, [origin], async () => response(JSON.stringify({ ...descriptor(), ...change })))).rejects.toThrow("unresolved");
  }
});

test("invalid UTF-8 and oversized streamed bodies cancel without waiting on cancellation", async () => {
  for (const bytes of [new Uint8Array([0xff]), new Uint8Array(65537)]) {
    let canceled = false;
    const stream = new ReadableStream<Uint8Array>({ start(controller) { controller.enqueue(bytes); }, cancel() { canceled = true; return new Promise<void>(() => {}); } });
    const supplied = new Response(stream, { headers: { "Content-Type": "application/json" } });
    // Invalid UTF-8 needs EOF; the oversized case must cancel before EOF.
    if (bytes.length === 1) {
      const completed = new Response(bytes, { headers: { "Content-Type": "application/json" } });
      await expect(discoverLightningAddress(address, [origin], async () => completed)).rejects.toThrow("unresolved");
    } else {
      await expect(discoverLightningAddress(address, [origin], async () => supplied)).rejects.toThrow("unresolved");
      expect(canceled).toBe(true); expect(stream.locked).toBe(false);
    }
    if (!canceled) void stream.cancel();
  }
});

test("abort remains active during body reads and releases the reader despite pending cancellation", async () => {
  const previous = AbortSignal.timeout;
  const controller = new AbortController(); let canceled = false;
  AbortSignal.timeout = () => controller.signal;
  const stream = new ReadableStream<Uint8Array>({ cancel() { canceled = true; return new Promise<void>(() => {}); } });
  try {
    const pending = discoverLightningAddress(address, [origin], async () => new Response(stream, { headers: { "Content-Type": "application/json" } }));
    // Yield to reader admission, not a timing-dependent polling loop.
    await Promise.resolve(); await Promise.resolve(); controller.abort();
    await expect(pending).rejects.toThrow("unresolved"); expect(canceled).toBe(true); expect(stream.locked).toBe(false);
  } finally { AbortSignal.timeout = previous; }
});

test("trailing-hyphen final DNS labels refuse before any discovery request", async () => {
  let calls = 0;
  const origin = "https://receiver.exam-";
  const transport = async () => { calls++; return Response.json({ tag: "payRequest", minSendable: 1, maxSendable: 1000000,
    callback: origin + "/invoice", metadata: '[["text/plain","Receiver"],["text/identifier","buyer@receiver.exam-"]]' }); };
  await expect(discoverLightningAddress("buyer@receiver.exam-", [origin], transport)).rejects.toThrow("profile");
  expect(calls).toBe(0);
});
