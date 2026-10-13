import { test, expect } from "@playwright/test";
import { assertDisposableStack, command, compose, composeEnabled, run, shopURL } from "./stack";
import { fundBitcoinQuote } from "./bitcoinFlow";

const methods = [
  { rail: "lightning", label: "Lightning" }, { rail: "btc-swap", label: "Bitcoin" },
  { rail: "fusdc", label: "USDC" }, { rail: "fusdt", label: "USDT" },
  { rail: "monero", label: "Monero" }, { rail: "monero", label: "Monero", parts: 2 },
];

for (const { rail, label, parts } of methods) {
  test(`storefront accepts a real ${label} payment${parts ? " split across two transactions" : ""} and keeps its verified receipt`, async ({ page, request }) => {
    test.skip(!composeEnabled, "Explicit disposable Compose opt-in required");
    test.setTimeout(300000); assertDisposableStack();
    const errors: string[] = []; page.on("pageerror", (error) => errors.push(error.message));
    await page.goto(shopURL());
    await page.locator("#products .card").filter({ hasText: "Sticker" }).getByRole("button", { name: "Buy" }).click();
    await page.getByRole("radio", { name: new RegExp(`^${label}\\b`) }).check();
    await page.getByRole("button", { name: "Continue to payment", exact: true }).click();
    await expect(page.locator("#order-status")).toHaveText("waiting");
    const id = (await page.locator("#order-id").textContent())!;
    const before = await (await request.get(`${shopURL()}/api/orders/${id}`)).json();
    expect(before.rail).toBe(rail); expect(before.acceptance).toBeNull();
    if (rail === "lightning") expect(await run("pay", before.invoice)).toContain("paid, preimage");
    else if (rail === "btc-swap") {
      const link = page.getByRole("link", { name: "Continue in RillSwap" });
      expect(new URL((await link.getAttribute("href"))!).hash).toContain(encodeURIComponent(before.invoice));
      const opened = page.waitForEvent("popup"); await link.click(); const swap = await opened;
      swap.on("pageerror", (error) => errors.push(error.message));
      await expect(swap.locator("#swap-invoice")).toHaveValue(before.invoice);
      await swap.locator("#swap-start").click();
      await expect(swap.locator("#swap-quote-accept")).toBeEnabled({ timeout: 60000 });
      await swap.locator("#swap-quote-accept").click();
      await fundBitcoinQuote(swap);
      await swap.close();
    } else if (rail === "monero") await run("pay-xmr", id, "--parts", String(parts ?? 1));
    else await run("pay-token", id);
    await expect(page.locator("#order-status")).toHaveText("paid", { timeout: 180000 });
    await expect(page.locator("#order-acceptance")).toContainText("Merchant signature verified");
    const accepted = await (await request.get(`${shopURL()}/api/orders/${id}`)).json();
    expect(accepted.acceptance.eventId).toBeTruthy(); expect(accepted.acceptance.publicKey).toMatch(/^[0-9a-f]{64}$/);
    expect(accepted.acceptance.detail).toBeTruthy(); expect(accepted.acceptance.acceptedAt).toBeGreaterThan(0);
    if (rail === "lightning" || rail === "btc-swap") {
      const hash = JSON.parse(command("lncli", "user", "decodepayreq", before.invoice)).payment_hash;
      expect(JSON.parse(command("lncli", "merchant", "lookupinvoice", hash)).state).toBe("SETTLED");
    }
    // Reload reopens the existing order, rather than initiating a new payment.
    await page.reload(); await page.locator(`#history tr[data-id="${id}"] a`).click();
    await expect(page.locator("#order-status")).toHaveText("paid");
    await expect(page.locator("#order-acceptance")).toContainText(accepted.acceptance.eventId);
    if (rail === "lightning") {
      // Restart only our disposable applications. The original accepted order/receipt must survive.
      compose("restart", "merchant", "shop");
      await expect(async () => {
        const response = await request.get(`${shopURL()}/api/orders/${id}`);
        expect(response.ok()).toBe(true);
        const restored = await response.json(); expect(restored.status).toBe("paid");
        expect(restored.acceptance).toEqual(accepted.acceptance);
      }).toPass({ timeout: 90000 });
    }
    expect(errors).toEqual([]);
  });
}
