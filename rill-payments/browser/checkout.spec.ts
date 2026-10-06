import { expect, test } from "@playwright/test";

test("IndexedDB reserves one cross-tab dispatch and restores tracking after closure", async ({ context }, info) => {
  const requests: string[] = []; context.on("request", (request) => requests.push(request.url()));
  const url = "/?case=" + encodeURIComponent(info.testId);
  const first = await context.newPage(), second = await context.newPage();
  for (const page of [first, second]) { await page.goto(url); await page.waitForFunction(() => window.checkoutReady); }
  const results = await Promise.all([first.evaluate(() => window.checkoutPay()), second.evaluate(() => window.checkoutPay())]);
  expect(results.sort()).toEqual(["refused", "sent"]);
  const calls = await first.evaluate(() => window.checkoutCalls()) + await second.evaluate(() => window.checkoutCalls()); expect(calls).toBe(1);
  await first.close(); await second.close(); const reopened = await context.newPage(); await reopened.goto(url);
  await expect(reopened.getByRole("status")).toHaveText("Payment sent, waiting for merchant receipt");
  expect(await reopened.evaluate(() => window.checkoutPay())).toBe("refused");
  expect(await reopened.evaluate(() => window.checkoutCalls())).toBe(0);
  expect(requests.every((request) => new URL(request).origin === "http://127.0.0.1:8798")).toBe(true);
});
test("native checkpoint reserves one cross-tab dispatch and reopens as observation only", async ({ context }, info) => {
  const url = "/?kind=native&case=" + encodeURIComponent(info.testId), first = await context.newPage(), second = await context.newPage();
  for (const page of [first, second]) { await page.goto(url); await page.waitForFunction(() => window.checkoutReady); }
  expect((await Promise.all([first.evaluate(() => window.checkoutPay()), second.evaluate(() => window.checkoutPay())])).sort()).toEqual(["refused", "sent"]);
  expect(await first.evaluate(() => window.checkoutCalls()) + await second.evaluate(() => window.checkoutCalls())).toBe(1);
  await first.close(); await second.close(); const reopened = await context.newPage(); await reopened.goto(url); await reopened.waitForFunction(() => window.checkoutReady);
  await expect(reopened.getByRole("status")).toHaveText("Native receipt observation only"); expect(await reopened.evaluate(() => window.checkoutPay())).toBe("refused"); expect(await reopened.evaluate(() => window.checkoutCalls())).toBe(0);
});
test("native and Lightning consumers share the same attempt reservation without a database upgrade", async ({ context }, info) => {
  const first = await context.newPage(), second = await context.newPage(), suffix = "case=" + encodeURIComponent(info.testId);
  await first.goto("/?" + suffix); await second.goto("/?kind=native&" + suffix);
  for (const page of [first, second]) await page.waitForFunction(() => window.checkoutReady);
  expect((await Promise.all([first.evaluate(() => window.checkoutPay()), second.evaluate(() => window.checkoutPay())])).sort()).toEqual(["refused", "sent"]);
  expect(await first.evaluate(() => window.checkoutCalls()) + await second.evaluate(() => window.checkoutCalls())).toBe(1);
});

test("browser LNURL discovery omits capabilities and never retrieves an invoice", async ({ context }, info) => {
  const origin = "https://receiver.example", requests: { url: string; method: string; headers: Record<string, string> }[] = [];
  await context.addCookies([{ name: "receiverCapability", value: "PRIVATE_TEST_COOKIE", url: origin, secure: true, sameSite: "None" }]);
  expect((await context.cookies(origin)).length).toBe(1);
  await context.route(origin + "/**", async (route) => {
    const request = route.request(); requests.push({ url: request.url(), method: request.method(), headers: await request.allHeaders() });
    expect(new URL(request.url()).pathname).toBe("/.well-known/lnurlp/buyer");
    await route.fulfill({ status: 200, contentType: "application/json", headers: { "Access-Control-Allow-Origin": "*" }, body: JSON.stringify({
      tag: "payRequest", callback: origin + "/invoice?k1=opaque", minSendable: 1, maxSendable: 1000000,
      metadata: '[["text/plain","Receiver"],["text/identifier","buyer@receiver.example"]]',
    }) });
  });
  const page = await context.newPage(); await page.goto("/?lnurl=1&case=" + encodeURIComponent(info.testId)); await page.waitForFunction(() => window.checkoutReady);
  const result = await page.evaluate((origin) => window.discoverLightningAddress("buyer@receiver.example", [origin]), origin);
  expect(result.version).toBe("lnurl-pay-request/1"); expect(result.description).toBe("Receiver");
  expect(requests.length).toBe(1); expect(requests[0]!.method).toBe("GET");
  for (const name of ["cookie", "authorization", "referer"]) expect(requests[0]!.headers[name]).toBeUndefined();
  expect(await page.evaluate(() => window.checkoutCalls())).toBe(0);
  const emptyUrl = await page.evaluate(async (origin) => {
    const original = globalThis.fetch;
    // Only explicitly trusted transports may return synthetic URL-less responses.
    globalThis.fetch = new Proxy(original, { apply: async () => Response.json({
      tag: "payRequest", callback: origin + "/invoice", minSendable: 1, maxSendable: 1000000,
      metadata: '[["text/plain","Receiver"],["text/identifier","buyer@receiver.example"]]',
    }) });
    try { await window.discoverLightningAddress("buyer@receiver.example", [origin]); return "accepted"; }
    catch (error) { return (error as Error).message; }
    finally { globalThis.fetch = original; }
  }, origin);
  expect(emptyUrl).toBe("LNURL discovery is unresolved");
});

test("browser LNURL validation pins signed contents without invoice retrieval or payment", async ({ context }, info) => {
  const requests: string[] = []; context.on("request", (request) => requests.push(request.url()));
  const page = await context.newPage(); await page.goto("/?case=" + encodeURIComponent(info.testId)); await page.waitForFunction(() => window.checkoutReady);
  const result = await page.evaluate(() => {
    const fixture = window.lnurlFixture;
    const descriptor = { version: "lnurl-pay-request/1" as const, lightningAddress: "buyer@receiver.example", receiverOrigin: "https://receiver.example",
      callback: "https://receiver.example/invoice", metadata: fixture.metadata, description: "Receiver", minSendableMsat: "1", maxSendableMsat: "1000000" };
    const expected = { networkName: "regtest", amountMsat: "1000000", payee: fixture.receiver, now: 1000, minExpiresAt: 2000, metadataHashPolicy: "not_required" as const };
    const modern = window.validateLnurlPayInvoice(descriptor, { pr: fixture.invoice, routes: [] }, expected);
    const strict = window.validateLnurlPayInvoice(descriptor, { pr: fixture.hashedInvoice, routes: [] }, { ...expected, metadataHashPolicy: "strict_hash" });
    let mismatch = "accepted";
    try { window.validateLnurlPayInvoice(descriptor, { pr: fixture.invoice, routes: [] }, { ...expected, amountMsat: "999000" }); }
    catch (error) { mismatch = (error as Error).message; }
    return { modernPolicy: modern.metadataHashPolicy, strictPolicy: strict.metadataHashPolicy, mismatch,
      frozen: Object.isFrozen(modern) && Object.isFrozen(modern.binding) && Object.isFrozen(strict.binding),
      original: modern.invoice === fixture.invoice && strict.invoice === fixture.hashedInvoice, fields: Object.keys(modern.binding).length };
  });
  expect(result).toEqual({ modernPolicy: "not_required", strictPolicy: "strict_hash", mismatch: "LNURL invoice response is unresolved", frozen: true, original: true, fields: 7 });
  expect(await page.evaluate(() => window.checkoutCalls())).toBe(0);
  expect(requests.every((url) => new URL(url).origin === "http://127.0.0.1:8798")).toBe(true);
});

test("explicit browser acquisition makes one invoice request without payment or automatic retry", async ({ context }, info) => {
  const origin = "https://receiver.example", seen: { url: string; headers: Record<string, string> }[] = [];
  await context.addCookies([{ name: "callbackSecret", value: "PRIVATE_COOKIE", url: origin, secure: true, sameSite: "None" }]);
  const page = await context.newPage(); await page.goto("/?lnurl=1&case=" + encodeURIComponent(info.testId)); await page.waitForFunction(() => window.checkoutReady);
  const fixture = await page.evaluate(() => window.lnurlFixture);
  await context.route(origin + "/**", async (route) => {
    const request = route.request(); seen.push({ url: request.url(), headers: await request.allHeaders() });
    expect(request.method()).toBe("GET"); expect(new URL(request.url()).pathname).toBe("/invoice");
    expect(new URL(request.url()).searchParams.get("amount")).toBe("1000000");
    await route.fulfill({ status: 200, contentType: "application/json", headers: { "Access-Control-Allow-Origin": "*" },
      body: seen.length === 1 ? JSON.stringify({ pr: fixture.invoice, routes: [] }) : JSON.stringify({ status: "ERROR", reason: "PRIVATE_REASON" }) });
  });
  const result = await page.evaluate(async (origin) => {
    const fixture = window.lnurlFixture;
    const descriptor = { version: "lnurl-pay-request/1" as const, lightningAddress: "buyer@receiver.example", receiverOrigin: origin,
      callback: origin + "/invoice?k1=PRIVATE_CALLBACK", metadata: fixture.metadata, description: "Receiver", minSendableMsat: "1", maxSendableMsat: "1000000" };
    const pins = { networkName: "regtest", amountMsat: "1000000", payee: fixture.receiver, minExpiresAt: 2000, metadataHashPolicy: "not_required" as const };
    const invoice = await window.requestLnurlPayInvoice(descriptor, pins, [origin], () => 1000);
    // This second explicit call is intentionally separate, never a library retry.
    let state = "accepted";
    try { await window.requestLnurlPayInvoice(descriptor, pins, [origin], () => 1000); }
    catch (error) { state = (error as Error & { state: string }).state; }
    return { original: invoice.invoice === fixture.invoice, state, publicFields: Object.keys(invoice) };
  }, origin);
  expect(result).toEqual({ original: true, state: "issuance_unknown", publicFields: ["invoice", "binding", "metadataHashPolicy"] });
  expect(seen.length).toBe(2);
  for (const request of seen) for (const name of ["cookie", "authorization", "referer"]) expect(request.headers[name]).toBeUndefined();
  expect(await page.evaluate(() => window.checkoutCalls())).toBe(0);
});
