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
