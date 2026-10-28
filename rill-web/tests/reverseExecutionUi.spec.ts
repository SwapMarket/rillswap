import { expect, test } from "./fixtures/swapPage";
import type { Page } from "@playwright/test";
import regtest from "../src/networks/regtest-rillswap-e2e-v1.json" with { type: "json" };
import { scriptAddress } from "../src/swap/address";

const PAGE = "http://127.0.0.1:18765/test-only/swap.html";
const API = "http://127.0.0.1:8091/api";

declare global { interface Window { notificationTest: { requests: number; messages: string[] } } }

async function mountedExecution(page: Page): Promise<void> {
  await page.route(`${API}/**`, async (route) => {
    const path = new URL(route.request().url()).pathname;
    const confirmed = await page.evaluate(() => window.uiFixture?.reverseClaimConfirmed ?? false);
    await route.fulfill({ body: path.endsWith("/status") ? JSON.stringify({ confirmed, block_height: 99, block_hash: "a".repeat(64) }) :
      path.endsWith("/0") ? regtest.genesis_hash : path.endsWith("/height") ? "100"
        : path.endsWith("/v1/fees/recommended") ? JSON.stringify({ fastestFee: 2, halfHourFee: 1, hourFee: 1, economyFee: 1, minimumFee: 1 }) : "a".repeat(64),
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

test("the reverse flow shows one step at a time and automatically claims after the required depth", async ({ page }) => {
  await mountedExecution(page);
  // The node path exists only under Advanced and never connects by itself.
  await expect(page.locator("#swap-reverse-advanced")).not.toHaveAttribute("open");
  await expect(page.locator("#swap-reverse-node-api")).toBeHidden();
  await expect(page.locator("#swap-reverse-invoice")).toHaveCount(0);
  await page.locator("#swap-reverse-accept").click();
  await expect(page.locator("#swap-reverse-invoice")).toHaveText("lnbcrt510010n1fixture");
  await expect(page.locator("#swap-reverse-invoice-uri")).toHaveAttribute("href", "lightning:lnbcrt510010n1fixture");
  await expect(page.locator("#swap-reverse-invoice-notes")).toContainText("Pay it once");
  await expect(page.locator("#swap-reverse-invoice-qr")).toBeVisible();
  await expect(page.locator("#swap-reverse-node-api")).toHaveCount(0);
  await expect(page.locator("#swap-status")).toContainText("Pay the invoice from your Lightning wallet");
  await expect(page.locator("#swap-reverse-message")).toContainText("Waiting for the provider to lock the Bitcoin");
  await expect(page.locator("#swap-reverse-funding")).toBeDisabled(); // the page is already listening
  await expect.poll(() => page.evaluate(() => window.uiFixture.reverseEvents!.filter((event) => event === "receive").length), { timeout: 10000 }).toBeGreaterThan(1);
  expect(await page.evaluate(() => window.uiFixture.reverseEvents!.slice(0, 2))).toEqual(["accept", "expose"]);
  await page.evaluate(() => { window.uiFixture.reverseFunded = true; });
  await expect(page.locator("#swap-reverse-funding-status")).toContainText("0 of 2", { timeout: 10000 });
  await expect(page.locator("#swap-reverse-invoice")).toHaveCount(0);
  await expect(page.locator('#swap-reverse-steps a')).toHaveAttribute("href", `http://127.0.0.1:8091/tx/${"b".repeat(64)}`);
  await page.locator("#swap-reverse-advanced summary").click();
  await expect(page.locator('#swap-reverse-backups a')).toHaveCount(1);
  await expect(page.locator('#swap-reverse-backups a')).toHaveText("Download swap backup");
  await expect(page.locator("#swap-reverse-claim-fee")).toHaveValue("500"); // min(reserve, max claim fee)
  expect(await page.evaluate(() => window.uiFixture.reverseEvents)).not.toContain("prepare");
  await page.evaluate(() => { window.uiFixture.reverseDepth = 2; });
  await page.locator("#swap-reverse-funding").click();
  await expect(page.locator("#swap-status")).toContainText("Claim accepted:");
  await expect(page.locator('#swap-reverse-steps a')).toHaveAttribute("href", `http://127.0.0.1:8091/tx/${"a".repeat(64)}`);
  expect(await page.evaluate(() => window.uiFixture.reverseEvents!.filter((e) => e === "broadcast"))).toHaveLength(1);
  await page.evaluate(() => { window.uiFixture.reverseClaimConfirmed = true; });
  await page.locator("#swap-reverse-funding").click();
  await expect(page.locator("#swap-reverse-steps h2")).toHaveText("Bitcoin received");
  expect(await page.evaluate(() => window.uiFixture.reverseEvents!.filter((e) => e === "broadcast"))).toHaveLength(1);
  expect(await page.evaluate(() => window.uiFixture.reverseEvents)).not.toContain("plan");
});

test("an uncertain automatic claim is watched but never submitted again", async ({ page }) => {
  await mountedExecution(page);
  await page.evaluate(() => { window.uiFixture.reverseFunded = true; window.uiFixture.reverseDepth = 2; window.uiFixture.reverseBroadcastUnknown = true; });
  await page.locator("#swap-reverse-accept").click();
  await expect(page.locator("#swap-status")).toContainText("Claim unknown:");
  await page.locator("#swap-reverse-advanced summary").click();
  await page.locator("#swap-reverse-funding").click();
  await expect(page.locator("#swap-reverse-steps h2")).toHaveText("Confirming your claim");
  expect(await page.evaluate(() => window.uiFixture.reverseEvents!.filter((e) => e === "broadcast"))).toHaveLength(1);
});

test("notifications require an explicit opt-in and report public swap status only", async ({ page }) => {
  await page.addInitScript(() => {
    window.notificationTest = { requests: 0, messages: [] };
    class LocalNotification {
      static permission: NotificationPermission = "default";
      static async requestPermission() { window.notificationTest.requests++; this.permission = "granted"; return "granted"; }
      constructor(_title: string, options: NotificationOptions) { window.notificationTest.messages.push(options.body ?? ""); }
    }
    Object.defineProperty(window, "Notification", { value: LocalNotification, configurable: true });
  });
  await mountedExecution(page);
  expect(await page.evaluate(() => window.notificationTest.requests)).toBe(0);
  await page.locator("#swap-reverse-advanced summary").click();
  await page.locator("#swap-reverse-notifications").click();
  await expect(page.locator("#swap-reverse-notifications")).toHaveText("Notifications enabled");
  await page.evaluate(() => { window.uiFixture.reverseFunded = true; window.uiFixture.reverseDepth = 2; window.uiFixture.reverseClaimConfirmed = true; });
  await page.locator("#swap-reverse-accept").click();
  await expect(page.locator("#swap-reverse-steps h2")).toHaveText("Bitcoin received");
  const notifications = await page.evaluate(() => window.notificationTest);
  expect(notifications.requests).toBe(1);
  expect(notifications.messages).toEqual(["Bitcoin is locked. Waiting for confirmations.", "Your Bitcoin claim was submitted.", "Your Bitcoin claim is confirmed."]);
});

test("Bitcoin confirmation keeps watching a pending node payment until settlement, without paying again", async ({ page }) => {
  const nodeKey = "02" + "11".repeat(32); let settled = false, statusReads = 0;
  await page.route("http://127.0.0.1:8093/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    const value = path === "/v1/getinfo" ? { identity_pubkey: nodeKey, synced_to_chain: true, chains: [{ chain: "bitcoin", network: "regtest" }], block_height: 100 } :
      { result: { payment_hash: "c".repeat(64), value_msat: "51006000", status: settled ? "SUCCEEDED" : "IN_FLIGHT" } };
    if (path.includes("/track/")) statusReads++;
    await route.fulfill({ body: JSON.stringify(value) + "\n", headers: { "Access-Control-Allow-Origin": "*" } });
  });
  await mountedExecution(page);
  await page.evaluate(() => {
    window.uiFixture.reverseNodePayment = window.uiFixture.reverseFunded = window.uiFixture.reverseClaimConfirmed = true;
    window.uiFixture.reverseDepth = 2;
  });
  await page.locator("#swap-reverse-advanced summary").click();
  await page.locator("#swap-reverse-node-api").fill("http://127.0.0.1:8093");
  await page.locator("#swap-reverse-node-identity").fill(nodeKey);
  await page.locator("#swap-reverse-macaroon").fill("00");
  await page.locator("#swap-reverse-connect").click();
  await page.locator("#swap-reverse-pay").click();
  await expect(page.locator("#swap-status")).toHaveText("Bitcoin received. Waiting for Lightning settlement");
  settled = true;
  await page.locator("#swap-reverse-funding").click();
  await expect(page.locator("#swap-status")).toContainText("Swap complete");
  expect(statusReads).toBeGreaterThanOrEqual(2);
  const events = await page.evaluate(() => window.uiFixture.reverseEvents!);
  expect(events.filter((event) => event === "pay")).toHaveLength(1);
  expect(events.filter((event) => event === "broadcast")).toHaveLength(1);
});

test("a transient pre-broadcast chain read keeps auto-claim alive without a second payment", async ({ page }) => {
  await mountedExecution(page);
  await page.evaluate(() => {
    window.uiFixture.reverseFunded = true; window.uiFixture.reverseDepth = 2; window.uiFixture.reverseTransientClaimRead = true;
  });
  await page.locator("#swap-reverse-accept").click();
  await expect(page.locator("#swap-reverse-message")).toContainText("Waiting for fresh Bitcoin funding data");
  await page.locator("#swap-reverse-advanced summary").click();
  await page.locator("#swap-reverse-funding").click();
  await expect(page.locator("#swap-status")).toContainText("Claim accepted:");
  const events = await page.evaluate(() => window.uiFixture.reverseEvents!);
  expect(events.filter((event) => event === "expose")).toHaveLength(1);
  expect(events.filter((event) => event === "prepare")).toHaveLength(1);
  expect(events.filter((event) => event === "broadcast")).toHaveLength(1);
});
