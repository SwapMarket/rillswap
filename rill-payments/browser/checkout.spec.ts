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
