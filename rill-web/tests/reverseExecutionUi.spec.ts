import { expect, test, type Page } from "@playwright/test";
import regtest from "../src/networks/regtest-rillswap-e2e-v1.json" with { type: "json" };
import { scriptAddress } from "../src/swap/address";

const PAGE = "http://127.0.0.1:18765/test-only/swap.html";
const API = "http://127.0.0.1:8091/api";

async function mountedExecution(page: Page): Promise<void> {
  await page.route(`${API}/**`, async (route) => {
    const path = new URL(route.request().url()).pathname;
    await route.fulfill({ body: path.endsWith("/0") ? regtest.genesis_hash : path.endsWith("/height") ? "100" : "a".repeat(64),
      headers: { "Access-Control-Allow-Origin": "http://127.0.0.1:18765" } });
  });
  await page.goto(PAGE);
  await page.getByRole("button", { name: "Switch direction" }).click();
  await page.locator("#swap-receive-amount").fill("50000");
  await page.locator("#swap-start").click();
  await page.locator("#swap-receive-address").fill(scriptAddress(`0014${"11".repeat(20)}`, "regtest"));
  await page.locator("#swap-reverse-continue").click();
  await expect(page.locator("#swap-reverse-accept")).toHaveText("Accept and show the invoice");
}

test("accepting shows the hold invoice for any wallet, hides the node path, and keeps listening for funding", async ({ page }) => {
  await mountedExecution(page);
  // The node path exists only under Advanced and never connects by itself.
  await expect(page.locator("#swap-reverse-advanced")).not.toHaveAttribute("open");
  await expect(page.locator("#swap-reverse-node-api")).toBeHidden();
  await expect(page.locator("#swap-reverse-invoice")).toHaveCount(0);
  await page.locator("#swap-reverse-accept").click();
  await expect(page.locator("#swap-reverse-invoice")).toHaveText("lnbcrt510010n1fixture");
  await expect(page.locator("#swap-reverse-invoice-uri")).toHaveAttribute("href", "lightning:lnbcrt510010n1fixture");
  await expect(page.locator("#swap-reverse-invoice-notes")).toContainText("Pay it once");
  await expect(page.locator("#swap-reverse-advanced")).toHaveCount(0);
  await expect(page.locator("#swap-status")).toContainText("Pay the invoice from your Lightning wallet");
  await expect(page.locator("#swap-reverse-funding-status")).toContainText("Waiting for the provider to lock the Bitcoin");
  await expect(page.locator("#swap-reverse-funding")).toBeDisabled(); // the page is already listening
  await expect.poll(() => page.evaluate(() => window.uiFixture.reverseEvents!.filter((event) => event === "receive").length)).toBeGreaterThan(1);
  expect(await page.evaluate(() => window.uiFixture.reverseEvents!.slice(0, 2))).toEqual(["accept", "expose"]);
  await page.evaluate(() => { window.uiFixture.reverseFunded = true; });
  await expect(page.locator('#swap-reverse-backups a[download="rillswap-ln-to-btc-funded.age"]')).toBeVisible();
  await expect(page.locator("#swap-reverse-funding-status")).toHaveCount(0);
  await expect(page.locator("#swap-reverse-claim-fee")).toHaveValue("500"); // min(reserve, max claim fee)
  await expect(page.locator("#swap-reverse-prepare-claim")).toBeEnabled();
  await expect(page.locator("#swap-status")).toContainText("Funding authenticated");
  expect(await page.evaluate(() => window.uiFixture.reverseEvents)).not.toContain("plan");
});
