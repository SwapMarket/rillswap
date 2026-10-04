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
