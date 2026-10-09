import { expect, test, type Page } from "@playwright/test";
import regtest from "../src/networks/regtest-rillswap-e2e-v1.json" with { type: "json" };
import { testInvoice } from "../../rill-payments/tests/helpers";

const PAGE = "http://127.0.0.1:18765/test-only/swap.html";
const API = "http://127.0.0.1:8091/api";

async function verifiedQuote(page: Page): Promise<void> {
  await mockTip(page);
  await page.goto(PAGE); await invoice(page); await page.locator("#swap-chain-consent").check();
  await page.locator("#swap-start").click();
  await expect(page.locator("#swap-quote-accept")).toBeDisabled();
  await page.evaluate(async () => {
    const wallet = await window.uiFixture.wallet.open();
    try { await wallet.verifyBackup(new TextDecoder().decode(await wallet.exportBackup())); }
    finally { wallet.close(); }
  });
  // Re-quote using the same persisted identity, now verified.
  await page.locator("#swap-edit").click();
  await page.locator("#swap-start").click();
  await expect(page.locator("#swap-quote-accept")).toBeEnabled();
}

async function delayFinalInfo(page: Page): Promise<void> {
  await page.evaluate(() => {
    const prototype = window.uiFixture.wallet.prototype, original = prototype.info;
    prototype.info = async function() {
      prototype.info = original;
      const info = await original.call(this);
      window.uiFixture.infoPending = true;
      await new Promise<void>((resolve) => { window.uiFixture.releaseInfo = resolve; });
      return info;
    };
  });
}

async function invoice(page: Page): Promise<void> {
  const now = Math.floor(Date.now() / 1000);
  await page.locator("#swap-invoice").fill(testInvoice("automatic_setup", "1000000", now, now + 7200));
}

async function mockTip(page: Page, genesis = regtest.genesis_hash): Promise<string[]> {
  const requests: string[] = [];
  await page.route(`${API}/**`, async (route) => {
    requests.push(route.request().url());
    expect(route.request().postData()).toBeNull();
    const path = new URL(route.request().url()).pathname;
    await route.fulfill({ body: path.endsWith("/0") ? genesis : path.endsWith("/height") ? "100" : "a".repeat(64),
      headers: { "Access-Control-Allow-Origin": "http://127.0.0.1:18765" } });
  });
  return requests;
}

test("defaults generate a refund address and key, fetch an approved tip, and block execution until a matching backup check", async ({ page }, info) => {
  const requests = await mockTip(page);
  await page.goto(PAGE);
  await invoice(page);
  expect(requests).toEqual([]);
  await page.locator("#swap-start").click();
  await expect(page.locator("#swap-status")).toContainText("Approve the named mempool API");
  expect(requests).toEqual([]);
  await page.locator("#swap-chain-consent").check();
  await page.locator("#swap-start").click();
  await expect(page.locator("#swap-quote-accept")).toBeDisabled();
  expect(requests).toHaveLength(5);
  const prepared = await page.evaluate(() => window.uiFixture.requests[0]) as {
    refundScript: string; tipHeight: number; ageRecipient: string; refundAllocation: { index: number; path: string };
  };
  expect(prepared.tipHeight).toBe(100);
  expect(prepared.refundScript).toMatch(/^0014[0-9a-f]{40}$/);
  expect(prepared.ageRecipient).toMatch(/^age1/);
  expect(prepared.refundAllocation).toMatchObject({ index: 0, path: "m/84'/1'/2'/0/0" });
  expect(JSON.stringify(prepared, (_key, value) => typeof value === "bigint" ? value.toString() : value)).not.toMatch(/mnemonic|privateKey|AGE-SECRET/);
  const backupPanel = page.locator("#swap-quote-backup");
  await backupPanel.locator("input[type=file]").setInputFiles({ name: "wrong.json", mimeType: "application/json",
    buffer: Buffer.from(JSON.stringify({ format: "rillswap-browser-recovery", version: 1, scheme: "bip84-rillswap-v1",
      mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about" })) });
  await expect(backupPanel).toContainText("different recovery key");
  await expect(page.locator("#swap-quote-accept")).toBeDisabled();
  expect(await page.evaluate(() => window.uiFixture.executed)).toBe(0);
  const downloading = page.waitForEvent("download");
  await backupPanel.getByRole("link").click();
  const download = await downloading;
  const file = `tmp/ui-backup-${info.workerIndex}-${info.retry}.json`;
  await download.saveAs(file);
  await expect(page.locator("#swap-quote-accept")).toBeDisabled();
  await backupPanel.locator("input[type=file]").setInputFiles(file);
  await expect(page.locator("#swap-quote-accept")).toBeEnabled();
  expect(await page.evaluate(() => window.uiFixture.executed)).toBe(0);
  await page.locator("#swap-quote-accept").click();
  await expect(page.locator("#swap-error")).toContainText("Fixture stopped before funding");
  expect(await page.evaluate(() => window.uiFixture.executed)).toBe(1);
});

test("wrong chain identity prevents quote preparation", async ({ page }) => {
  await mockTip(page, "f".repeat(64));
  await page.goto(PAGE); await invoice(page); await page.locator("#swap-chain-consent").check();
  await page.locator("#swap-start").click();
  await expect(page.locator("#swap-status")).toContainText("genesis does not match");
  expect(await page.evaluate(() => window.uiFixture.requests)).toEqual([]);
});

test("canceling automatic setup never shows a late quote or reuses the allocated address", async ({ page }) => {
  let release: (() => void) | undefined;
  let delayed = true;
  await page.route(`${API}/**`, async (route) => {
    if (delayed) { delayed = false; await new Promise<void>((resolve) => { release = resolve; }); }
    const path = new URL(route.request().url()).pathname;
    await route.fulfill({ body: path.endsWith("/0") ? regtest.genesis_hash : path.endsWith("/height") ? "100" : "a".repeat(64),
      headers: { "Access-Control-Allow-Origin": "http://127.0.0.1:18765" } });
  });
  await page.goto(PAGE); await invoice(page); await page.locator("#swap-chain-consent").check();
  await page.locator("#swap-start").click();
  await expect.poll(() => !!release).toBe(true);
  await page.locator("#swap-edit").click(); release!();
  await expect(page.locator("#swap-status")).toContainText("Ready for a new quote");
  await page.locator("#swap-start").click();
  await expect(page.locator("#swap-quote-accept")).toBeVisible();
  const prepared = await page.evaluate(() => window.uiFixture.requests) as { refundAllocation: { index: number } }[];
  expect(prepared).toHaveLength(1);
  expect(prepared[0]!.refundAllocation.index).toBe(1);
});

test("the accepted provider stays pinned while the final wallet check is pending", async ({ page }) => {
  await verifiedQuote(page); await delayFinalInfo(page);
  await page.locator("#swap-quote-accept").click();
  await page.waitForFunction(() => window.uiFixture.infoPending);
  const options = page.locator("input[name=verified-provider]");
  await expect(options.nth(1)).toBeDisabled();
  // Even a synthetic selection event during the await cannot change the captured choice.
  await options.nth(1).evaluate((option) => option.dispatchEvent(new Event("change")));
  await page.evaluate(() => window.uiFixture.releaseInfo!());
  await expect(page.locator("#swap-error")).toContainText("Fixture stopped before funding");
  expect(await page.evaluate(() => window.uiFixture.executedProviders)).toEqual(["4".repeat(64)]);
});

for (const mutation of ["unverified", "changed", "unreadable"]) {
  test(`the final persisted wallet check refuses ${mutation} state before acceptance`, async ({ page }) => {
    await verifiedQuote(page);
    await page.evaluate(async (mutation) => {
      const db = await new Promise<IDBDatabase>((resolve) => { const req = indexedDB.open("rillswap-browser-wallet-v1", 1); req.onsuccess = () => resolve(req.result); });
      await new Promise<void>((resolve) => {
        const tx = db.transaction("identity", "readwrite"), store = tx.objectStore("identity"), req = store.get("wallet");
        req.onsuccess = () => { store.put(mutation === "unreadable" ? { version: 99 } : { ...req.result,
          ...(mutation === "unverified" ? { backupVerified: false } : { mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about" }) }, "wallet"); };
        tx.oncomplete = () => resolve();
      }); db.close();
    }, mutation);
    await page.locator("#swap-quote-accept").click();
    await expect(page.locator("#swap-error")).toBeVisible();
    expect(await page.evaluate(() => window.uiFixture.executed)).toBe(0);
  });
}

test("canceling the pending final wallet check prevents execution and stale UI", async ({ page }) => {
  await verifiedQuote(page); await delayFinalInfo(page);
  await page.locator("#swap-quote-accept").click();
  await page.waitForFunction(() => window.uiFixture.infoPending);
  await page.locator("#swap-edit").click();
  await page.evaluate(() => window.uiFixture.releaseInfo!());
  await expect(page.locator("#swap-status")).toContainText("Ready for a new quote");
  await expect(page.locator("#swap-start")).toBeEnabled();
  expect(await page.evaluate(() => window.uiFixture.executed)).toBe(0);
});
