import { expect, test } from "@playwright/test";

test("RillPay shows all prices, unavailable reasons and explicit unknown costs without side effects", async ({ page }) => {
  const requests: string[] = []; page.on("request", (request) => requests.push(request.url()));
  await page.goto("/rillpay"); await page.waitForFunction(() => window.rillPayReady);
  await expect(page.getByRole("region", { name: "RillPay checkout" })).toBeVisible();
  await expect(page.locator(".rillpay-method")).toHaveCount(3);
  await expect(page.locator('input[value="offline"]')).toBeDisabled();
  await expect(page.getByText("Below the merchant minimum of 5,000 sat")).toBeVisible();
  await expect(page.locator('input[value="ln"]')).toBeChecked();
  await expect(page.getByText("Quote required")).toBeVisible();
  await expect(page.getByText("Wallet/network fee: unknown, set by your wallet")).toHaveCount(3);
  expect(await page.evaluate(() => window.rillPayCalls)).toEqual([]);
  expect(await page.locator(".rillpay img").count()).toBe(0); expect(await page.evaluate(() => "bad" in window)).toBe(false);
  for (const url of requests) expect(new URL(url).origin).toBe("http://127.0.0.1:8798");
});

test("no eligible methods means no payment action, with every reason still visible", async ({ page }) => {
  await page.goto("/rillpay?all-unavailable=1"); await page.waitForFunction(() => window.rillPayReady);
  await expect(page.getByRole("button", { name: "Continue to payment" })).toBeDisabled();
  expect(await page.evaluate(() => window.rillPayCalls)).toEqual([]);
});

test("one explicit payment preparation remains pinned while pending and redacts host errors", async ({ page }) => {
  await page.goto("/rillpay?hold=1&error=1"); await page.waitForFunction(() => window.rillPayReady);
  await page.getByRole("button", { name: "Continue to payment" }).click();
  await expect(page.getByRole("button", { name: "Preparing payment..." })).toBeDisabled();
  await expect(page.locator('input[value="ln"]')).toBeDisabled();
  await page.waitForFunction(() => Boolean(window.rillPayRelease)); await page.evaluate(() => window.rillPayRelease());
  await expect(page.getByRole("status")).toContainText("Could not prepare payment");
  await expect(page.getByRole("status")).not.toContainText("private-error");
  expect(await page.evaluate(() => window.rillPayCalls)).toEqual(["ln"]);
  await expect(page.getByRole("button", { name: "Continue to payment" })).toBeEnabled();
});

test("the demo uses reusable checkout and creates only the selected merchant order", async ({ page }) => {
  const methods = [
    { id: "lightning", label: "Lightning", network: "Bitcoin regtest", available: true, unavailableReason: null, price: "2,000 sat", merchantFee: "0", providerFee: "0", walletFee: null, confirmationTime: "Usually seconds" },
    { id: "btc-swap", label: "Bitcoin", network: "Bitcoin regtest", available: true, unavailableReason: null, price: "2,000 sat + quote", merchantFee: "0", providerFee: null, walletFee: null, confirmationTime: null },
  ];
  const orders: unknown[] = [];
  await page.route("**/api/catalog", (route) => route.fulfill({ json: { products: [{ id: "stickers", name: "Stickers", usdCents: 200, sat: 2000, methods }], rails: { lightning: { label: "Lightning" }, "btc-swap": { label: "Bitcoin" } },
    demoUsdPerBtc: 100000, demoUsdPerXmr: 100, acceptanceKey: "0".repeat(64), swapPage: "http://127.0.0.1:5273/swap.html" } }));
  await page.route("**/api/orders", (route) => {
    if (route.request().method() !== "POST") return route.fulfill({ json: [] });
    orders.push(route.request().postDataJSON());
    return route.fulfill({ json: { id: "123", productName: "Stickers", usdCents: 200, rail: "btc-swap", amountLabel: "2,000 sat", invoice: "lnbcrt-test", status: "waiting" } });
  });
  await page.goto("/shop"); await page.getByRole("button", { name: "Buy" }).click();
  await expect(page.getByRole("region", { name: "RillPay checkout" })).toBeVisible();
  await page.locator('input[value="btc-swap"]').check(); await page.getByRole("button", { name: "Continue to payment" }).click();
  await expect(page.getByRole("link", { name: "Continue in RillSwap" })).toHaveAttribute("href", "http://127.0.0.1:5273/swap.html#invoice=lnbcrt-test");
  expect(orders).toEqual([{ productId: "stickers", rail: "btc-swap" }]);
  await expect(page.getByText("take the other fields from")).toHaveCount(0);
});

for (const success of [true, false]) {
  test(`pending demo order pins product selection and restores controls after ${success ? "success" : "failure"}`, async ({ page }) => {
    const method = { id: "lightning", label: "Lightning", network: "Regtest", available: true, unavailableReason: null, price: "2,000 sat", merchantFee: "0", providerFee: "0", walletFee: null, confirmationTime: null };
    await page.route("**/api/catalog", (route) => route.fulfill({ json: {
      products: ["First", "Second"].map((name) => ({ id: name, name, usdCents: 200, sat: 2000, methods: [method] })),
      rails: { lightning: { label: "Lightning" } }, demoUsdPerBtc: 100000, demoUsdPerXmr: 100, acceptanceKey: "0".repeat(64),
    } }));
    let release!: () => void;
    const gate = new Promise<void>((resolve) => { release = resolve; });
    const posted: unknown[] = [];
    await page.route("**/api/orders", async (route) => {
      if (route.request().method() !== "POST") return route.fulfill({ json: [] });
      posted.push(route.request().postDataJSON()); await gate;
      await route.fulfill({ status: success ? 200 : 503, json: success ? { id: "123", productName: "First", usdCents: 200, rail: "lightning", invoice: "lnbcrt-test", amountLabel: "2,000 sat", status: "waiting" } : { error: "unavailable" } });
    });
    await page.goto("/shop"); await page.getByRole("button", { name: "Buy", exact: true }).first().click();
    await page.getByRole("button", { name: "Continue to payment" }).click();
    await expect(page.getByRole("button", { name: "Buy", exact: true }).nth(1)).toBeDisabled();
    await page.getByRole("button", { name: "Buy", exact: true }).nth(1).evaluate((button: HTMLButtonElement) => button.click());
    await expect(page.locator(".rillpay-item")).toHaveText("First");
    expect(posted).toEqual([{ productId: "First", rail: "lightning" }]);
    release();
    if (success) await expect(page.locator("#order-summary")).toContainText("First");
    else await expect(page.getByRole("status")).toContainText("Could not prepare payment");
    await expect(page.getByRole("button", { name: "Buy", exact: true }).nth(1)).toBeEnabled();
    await page.getByRole("button", { name: "Buy", exact: true }).nth(1).click();
    await expect(page.locator(".rillpay-item")).toHaveText("Second");
    expect(posted).toHaveLength(1);
  });
}
