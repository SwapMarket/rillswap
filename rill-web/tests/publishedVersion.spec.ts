import { expect, test } from "./fixtures/swapPage";
import type { Page } from "@playwright/test";
import regtest from "../src/networks/regtest-rillswap-e2e-v1.json" with { type: "json" };
import { testInvoice } from "../../rill-payments/tests/helpers";

const PAGE = "http://127.0.0.1:18765/test-only/swap.html";
const API = "http://127.0.0.1:8091/api";
const MESSAGE = "RillSwap was updated since this page was opened. Reload to start your swap. No payment was started.";

async function setup(page: Page, reverse = false, token = false): Promise<string[]> {
  const requests: string[] = [];
  await page.route(`${API}/**`, async (route) => {
    requests.push(route.request().url());
    const path = new URL(route.request().url()).pathname;
    await route.fulfill({ body: path.endsWith("/0") ? regtest.genesis_hash : path.endsWith("/height") ? "100" : "a".repeat(64),
      headers: { "Access-Control-Allow-Origin": "http://127.0.0.1:18765" } });
  });
  await page.goto(PAGE);
  if (token) {
    await page.locator("#swap-from").selectOption(reverse ? "ln" : "usdc");
    await page.locator("#swap-to").selectOption(reverse ? "usdc" : "ln");
    await page.locator("#swap-settings-toggle").click();
    await page.locator("#swap-evm-rpc").fill("http://127.0.0.1:8545");
    await page.locator("#swap-settings-close").click();
  }
  if (reverse) {
    if (!token) await page.getByRole("button", { name: "Switch direction" }).click();
    await page.locator("#swap-receive-amount").fill(token ? "1" : "50000");
  } else {
    const now = Math.floor(Date.now() / 1000);
    await page.locator("#swap-invoice").fill(testInvoice("published_version", "1000000", now, now + 7200));
  }
  return requests;
}

for (const reverse of [false, true]) {
  const direction = reverse ? "Lightning to Bitcoin" : "Bitcoin to Lightning";
  test(`${direction} blocks a changed entry before quotes and offers an explicit reload`, async ({ page }) => {
    const chainRequests = await setup(page, reverse);
    let checks = 0;
    await page.route(PAGE, async (route) => {
      if (route.request().isNavigationRequest()) { await route.continue(); return; }
      checks++;
      await route.fulfill({ contentType: "text/html", body: '<script type="application/ld+json">{}</script>' +
        '<script crossorigin src="./swap-new.js" type="module"></script>' });
    });
    await page.locator("#swap-start").click();
    await expect(page.locator("#swap-error")).toHaveText(MESSAGE);
    await expect(page.locator("#swap-reload")).toBeEnabled();
    expect(checks).toBe(1);
    expect(chainRequests).toEqual([]);
    expect(await page.evaluate(() => window.uiFixture.requests)).toEqual([]);
    expect(await page.evaluate(() => window.uiFixture.executed)).toBe(0);
    expect(await page.evaluate(() => window.uiFixture.reverseEvents)).toBeUndefined();
    await expect(page.locator("#swap-start")).toBeEnabled();
    await expect(page.locator("#swap-settings-toggle")).toBeEnabled();
    await Promise.all([page.waitForEvent("load"), page.locator("#swap-reload").click()]);
    await expect(page.locator("#swap-error")).toHaveCount(0);
  });

  for (const kind of ["same entry", "unavailable", "offline", "missing entry", "ambiguous entry"]) {
    test(`${direction} proceeds when the version page has ${kind}`, async ({ page }) => {
      await setup(page, reverse);
      await page.route(PAGE, async (route) => {
        if (kind === "offline") { await route.abort(); return; }
        await route.fulfill({ status: kind === "unavailable" ? 503 : 200, contentType: "text/html",
          body: '<title>Changed documentation only</title><script type="application/ld+json">{}</script>' +
            (kind === "missing entry" ? "" : '<script src="./swapUi.js" crossorigin type="module"></script>') +
            (kind === "ambiguous entry" ? '<script type="module" src="./other.js"></script>' : "") });
      });
      await page.locator("#swap-start").click();
      await expect(page.locator(reverse ? "#swap-reverse-continue" : "#swap-quote-accept")).toBeVisible();
      await expect(page.locator("#swap-reload")).toHaveCount(0);
      expect(await page.evaluate(() => window.uiFixture.requests.length)).toBe(1);
    });
  }

  test(`${reverse ? "Lightning to ERC20" : "ERC20 to Lightning"} checks for updates before token discovery or wallet connection`, async ({ page }) => {
    const chainRequests = await setup(page, reverse, true);
    await page.route(PAGE, (route) => route.fulfill({ contentType: "text/html",
      body: '<script type="module" src="./swap-new.js"></script>' }));
    await page.locator("#swap-start").click();
    await expect(page.locator("#swap-error")).toHaveText(MESSAGE);
    await expect(page.locator("#swap-start")).toBeEnabled();
    expect(chainRequests).toEqual([]);
    expect(await page.evaluate(() => window.uiFixture.requests)).toEqual([]);
  });
}

test("a pending version check locks controls and cannot dispatch duplicate swaps", async ({ page }) => {
  await setup(page);
  let checks = 0;
  let release!: () => void;
  const pending = new Promise<void>((resolve) => { release = resolve; });
  await page.route(PAGE, async (route) => {
    checks++;
    await pending;
    await route.fulfill({ contentType: "text/html", body: '<script type="module" src="./swapUi.js"></script>' });
  });
  await page.locator("#swap-start").click();
  await expect(page.locator("#swap-status")).toHaveText("Checking for updates");
  await expect(page.locator("#swap-start")).toBeDisabled();
  await expect(page.locator("#swap-invoice")).toBeDisabled();
  await expect(page.locator("#swap-network-badge")).toBeDisabled();
  await expect(page.locator("#swap-settings-toggle")).toBeDisabled();
  await page.locator("#swap-form").evaluate((form) => {
    form.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
  });
  expect(checks).toBe(1);
  expect(await page.evaluate(() => window.uiFixture.requests)).toEqual([]);
  release();
  await expect(page.locator("#swap-quote-accept")).toBeVisible();
  expect(await page.evaluate(() => window.uiFixture.requests.length)).toBe(1);
});

for (const reverse of [false, true]) {
  test(`canceling a ${reverse ? "reverse" : "forward"} version check cannot show a late reload prompt or start a quote`, async ({ page }) => {
    await setup(page, reverse);
    let checks = 0;
    let release!: () => void;
    const pending = new Promise<void>((resolve) => { release = resolve; });
    await page.route(PAGE, async (route) => {
      const first = ++checks === 1;
      if (first) await pending;
      await route.fulfill({ contentType: "text/html", body: `<script type="module" src="./${first ? "swap-new" : "swapUi"}.js"></script>` });
    });
    await page.locator("#swap-start").click();
    await expect(page.locator("#swap-status")).toHaveText("Checking for updates");
    await page.locator("#swap-edit").click();
    await expect(page.locator("#swap-start")).toBeEnabled();
    await expect(page.locator("#swap-status")).toHaveText("Ready for a new quote");
    expect(await page.evaluate(() => window.uiFixture.requests)).toEqual([]);
    release();
    await page.locator("#swap-start").click();
    await expect(page.locator(reverse ? "#swap-reverse-continue" : "#swap-quote-accept")).toBeVisible();
    await expect(page.locator("#swap-reload")).toHaveCount(0);
    expect(await page.evaluate(() => window.uiFixture.requests.length)).toBe(1);
  });
}
