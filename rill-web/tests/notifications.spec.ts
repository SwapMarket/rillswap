import type { Page } from "@playwright/test";
import { testInvoice } from "../../rill-payments/tests/helpers";
import regtest from "../src/networks/regtest-rillswap-e2e-v1.json" with { type: "json" };
import { expect, test } from "./fixtures/swapPage";

const PAGE = "http://127.0.0.1:18765/test-only/swap.html";
const API = "http://127.0.0.1:8091/api";
type PermissionBehavior = "pending" | "dismissed" | "denied" | "granted" | "throws" | "rejects" | "unsupported";

declare global {
  interface Window {
    swapNotificationTest: { requests: number; requestsAtSubmit: number[] };
  }
}

async function notifications(page: Page, behavior: PermissionBehavior = "pending"): Promise<void> {
  await page.addInitScript((behavior) => {
    const state = window.swapNotificationTest = { requests: 0, requestsAtSubmit: [] as number[] };
    // This runs after the form's handler, before any async setup can continue.
    document.addEventListener("submit", () => state.requestsAtSubmit.push(state.requests));
    if (behavior === "unsupported") { Reflect.deleteProperty(window, "Notification"); return; }
    class LocalNotification {
      static permission: NotificationPermission = behavior === "denied" || behavior === "granted" ? behavior : "default";
      static requestPermission(): Promise<NotificationPermission> {
        state.requests++;
        if (behavior === "throws") throw new Error("Notification permission unavailable");
        if (behavior === "rejects") return Promise.reject(new Error("Notification permission unavailable"));
        if (behavior === "pending") return new Promise(() => {});
        return Promise.resolve("default");
      }
    }
    Object.defineProperty(window, "Notification", { value: LocalNotification, configurable: true });
  }, behavior);
  await page.route(`${API}/**`, async (route) => {
    const path = new URL(route.request().url()).pathname;
    await route.fulfill({ body: path.endsWith("/0") ? regtest.genesis_hash : path.endsWith("/height") ? "100" : "a".repeat(64),
      headers: { "Access-Control-Allow-Origin": "http://127.0.0.1:18765" } });
  });
}

async function fillSwap(page: Page, from: string, to: string): Promise<void> {
  await page.locator("#swap-from").selectOption(from);
  await page.locator("#swap-to").selectOption(to);
  if (from === "usdc" || from === "usdt" || to === "usdc" || to === "usdt") {
    await page.locator("#swap-settings-toggle").click();
    await page.locator("#swap-evm-rpc").fill("http://127.0.0.1:8545");
    await page.locator("#swap-settings-close").click();
  }
  if (to === "ln") {
    const now = Math.floor(Date.now() / 1000);
    await page.locator("#swap-invoice").fill(testInvoice("notification_setup", "1000000", now, now + 7200));
  } else {
    await page.locator("#swap-receive-amount").fill(to === "btc" ? "50000" : "1");
  }
}

for (const [from, to] of [["btc", "ln"], ["ln", "btc"], ["usdc", "ln"], ["usdt", "ln"], ["ln", "usdc"], ["ln", "usdt"]] as const) {
  test(`${from} to ${to} requests permission during swap start without waiting for a response`, async ({ page }) => {
    await notifications(page);
    await page.goto(PAGE);
    await fillSwap(page, from, to);
    expect(await page.evaluate(() => window.swapNotificationTest.requests)).toBe(0);
    await page.locator("#swap-start").click();
    expect(await page.evaluate(() => window.swapNotificationTest)).toEqual({ requests: 1, requestsAtSubmit: [1] });
    if (from === "btc" || to === "btc") {
      await expect(page.locator("#swap-quote-review")).toBeVisible();
    } else {
      // The fixture deliberately has no trusted token deployment or EVM providers.
      await expect(page.locator("#swap-status")).toContainText("No trusted");
    }
  });
}

for (const behavior of ["dismissed", "denied", "granted", "throws", "rejects", "unsupported"] as const) {
  test(`${behavior} notification permission does not block swap setup`, async ({ page }) => {
    await notifications(page, behavior);
    await page.goto(PAGE);
    await fillSwap(page, "btc", "ln");
    await page.locator("#swap-start").click();
    await expect(page.locator("#swap-quote-accept")).toBeEnabled();
    const expected = ["dismissed", "throws", "rejects"].includes(behavior) ? 1 : 0;
    expect(await page.evaluate(() => window.swapNotificationTest.requests)).toBe(expected);
  });
}

for (const [from, to] of [["btc", "ln"], ["ln", "btc"], ["usdc", "ln"], ["ln", "usdc"]] as const) {
  test(`invalid ${from} to ${to} input does not request notification permission`, async ({ page }) => {
    await notifications(page);
    await page.goto(PAGE);
    await page.locator("#swap-from").selectOption(from);
    await page.locator("#swap-to").selectOption(to);
    await page.locator("#swap-start").click();
    await expect(page.locator("#swap-log")).toContainText("refused:");
    expect(await page.evaluate(() => window.swapNotificationTest.requests)).toBe(0);
  });
}
