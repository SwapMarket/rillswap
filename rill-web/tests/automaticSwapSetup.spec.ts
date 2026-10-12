import { expect, test, type Page } from "@playwright/test";
import regtest from "../src/networks/regtest-rillswap-e2e-v1.json" with { type: "json" };
import { testInvoice } from "../../rill-payments/tests/helpers";
import { scriptAddress } from "../src/swap/address";

const PAGE = "http://127.0.0.1:18765/test-only/swap.html";
const API = "http://127.0.0.1:8091/api";

async function verifiedQuote(page: Page): Promise<void> {
  await mockTip(page);
  await page.goto(PAGE); await invoice(page);
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

test("defaults fetch a tip on quote action and the stored browser key approves acceptance without a backup check", async ({ page }) => {
  const requests = await mockTip(page);
  await page.goto(PAGE);
  expect(requests).toEqual([]);
  await expect(page.locator("#swap-chain-consent")).toHaveCount(0);
  await expect(page.locator("#swap-chain-disclosure")).not.toBeVisible();
  await page.locator("#swap-privacy summary").click();
  await expect(page.locator("#swap-chain-disclosure")).toContainText(API);
  expect(requests).toEqual([]);
  await page.locator("#swap-privacy summary").click();
  await invoice(page);
  await page.locator("#swap-start").click();
  await expect(page.locator("#swap-quote-accept")).toBeEnabled();
  expect(requests).toHaveLength(5);
  const prepared = await page.evaluate(() => window.uiFixture.requests[0]) as {
    refundScript: string; tipHeight: number; ageRecipient: string; refundAllocation: { index: number; path: string };
  };
  expect(prepared.tipHeight).toBe(100);
  expect(prepared.refundScript).toMatch(/^0014[0-9a-f]{40}$/);
  expect(prepared.ageRecipient).toMatch(/^age1/);
  expect(prepared.refundAllocation).toMatchObject({ index: 0, path: "m/84'/1'/2'/0/0" });
  expect(JSON.stringify(prepared, (_key, value) => typeof value === "bigint" ? value.toString() : value)).not.toMatch(/mnemonic|privateKey|AGE-SECRET/);
  // No checkbox or upload gate: continuing is the acceptance, and the stored key is the approval.
  await expect(page.locator("#swap-quote-backup")).toHaveCount(0);
  await expect(page.locator("#swap-quote-review input[type=checkbox]")).toHaveCount(0);
  await expect(page.locator("#swap-quote-consent")).toContainText("By continuing you accept");
  expect(await page.evaluate(async () => { const wallet = await window.uiFixture.wallet.open();
    try { return (await wallet.info()).backupVerified; } finally { wallet.close(); } })).toBe(false);
  expect(await page.evaluate(() => window.uiFixture.executed)).toBe(0);
  await page.locator("#swap-quote-accept").click();
  await expect(page.locator("#swap-error")).toContainText("Fixture stopped before funding");
  expect(await page.evaluate(() => window.uiFixture.executed)).toBe(1);
  // The started swap replaces the form with a tracking view whose link carries the encrypted record.
  await expect(page.locator("#swap-form")).toBeHidden();
  await expect(page.locator("#swap-tracking h2")).toHaveText("Bitcoin to Lightning swap");
  expect(new URL(page.url()).hash).toBe("#swap=BwcH&network=regtest");
  await expect(page.locator("#swap-link-anchor")).toHaveAttribute("href", page.url());
  await expect(page.locator('#swap-backups a[download$=".age"]')).toHaveCount(1);
  await expect(page.locator("#swap-another")).toHaveAttribute("href", "./swap.html");
  expect(requests).toHaveLength(5); // publishing the link connects nowhere
});

test("wrong chain identity prevents quote preparation", async ({ page }) => {
  await mockTip(page, "f".repeat(64));
  await page.goto(PAGE); await invoice(page);
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
  await page.goto(PAGE); await invoice(page);
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

for (const mutation of ["changed", "unreadable"]) {
  test(`the final persisted wallet check refuses ${mutation} state before acceptance`, async ({ page }) => {
    await verifiedQuote(page);
    await page.evaluate(async (mutation) => {
      const db = await new Promise<IDBDatabase>((resolve) => { const req = indexedDB.open("rillswap-browser-wallet-v1", 1); req.onsuccess = () => resolve(req.result); });
      await new Promise<void>((resolve) => {
        const tx = db.transaction("identity", "readwrite"), store = tx.objectStore("identity"), req = store.get("wallet");
        req.onsuccess = () => { store.put(mutation === "unreadable" ? { version: 99 } : { ...req.result,
          mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about" }, "wallet"); };
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

test("Lightning to Bitcoin keeps estimates private and retains sessions only until continuation or cancellation", async ({ page }) => {
  const tips = await mockTip(page);
  await page.goto(PAGE);
  await page.getByRole("button", { name: "Switch direction" }).click();
  await page.locator("#swap-receive-amount").fill("50000");
  await page.locator("#swap-start").click(); // the payout address is not needed for an estimate
  await expect(page.locator("#swap-quote-review h2")).toHaveText("51,006 sat");
  await expect(page.locator("#swap-quote-review")).toContainText("receive 50,000 sat on-chain");
  await expect(page.locator("#swap-quote-review")).toContainText("Estimated price");
  await expect(page.locator("#swap-quote-review")).toContainText("Payout after 2 confirmations (about 20 min)");
  await expect(page.locator("#swap-quote-review")).toContainText("pending for up to about 288 blocks");
  await expect(page.locator("#swap-reverse-pending")).toContainText("no address or payment hash was shared");
  await expect(page.locator("#swap-quote-accept")).toHaveCount(0);
  expect(tips).toEqual([]); // estimates need no chain height
  const fixture = await page.evaluate(() => ({ requests: window.uiFixture.requests, disposed: window.uiFixture.disposed }));
  expect(fixture.disposed).toBe(0); // retained only for the explicit Continue action
  const request = fixture.requests[0] as Record<string, unknown> & { payoutSat: bigint;
    limits: { minRefundDelayBlocks: number; maxIncomingHtlcDelayBlocks: number; minClaimFeeReserveSat: bigint } };
  expect(request.payoutSat).toBe(50_000n);
  expect(Object.keys(request).sort()).toEqual(["limits", "network", "payoutSat"]);
  expect(request.limits).toMatchObject({ minRefundDelayBlocks: 72, maxIncomingHtlcDelayBlocks: 432, minClaimFeeReserveSat: 500n });
  await expect(page.locator("#swap-reverse-continue")).toBeEnabled(); // the stored browser key is the approval
  await expect(page.locator("#swap-reverse-key-backup")).toHaveCount(0);
  await expect(page.locator("#swap-start")).toBeDisabled();
  await expect(page.locator("#swap-receive-address")).toBeEnabled(); // still editable before continuation
  await page.locator("#swap-reverse-continue").click();
  await expect(page.locator("#swap-reverse-refusal")).toContainText("Enter the Bitcoin address");
  expect(await page.evaluate(() => window.uiFixture.disposed)).toBe(0);
  await page.locator("#swap-receive-address").fill("not-an-address");
  await page.locator("#swap-reverse-continue").click();
  await expect(page.locator("#swap-reverse-refusal")).not.toHaveText("");
  expect(await page.evaluate(() => window.uiFixture.disposed)).toBe(0);
  await page.locator("#swap-edit").click();
  expect(await page.evaluate(() => window.uiFixture.disposed)).toBe(2);
  await expect(page.locator("#swap-start")).toBeEnabled();
  await expect(page.locator("#swap-receive-address")).toBeEnabled();
});

test("continuing a Lightning to Bitcoin estimate sends only the address entered at continuation", async ({ page }) => {
  await mockTip(page);
  await page.goto(PAGE);
  await page.getByRole("button", { name: "Switch direction" }).click();
  await page.locator("#swap-receive-amount").fill("50000");
  await page.locator("#swap-start").click();
  await expect(page.locator("#swap-reverse-continue")).toBeEnabled();
  await page.locator("#swap-receive-address").fill(scriptAddress(`0014${"11".repeat(20)}`, "regtest"));
  await page.locator("#swap-reverse-continue").click();
  await expect(page.locator("#swap-reverse-refusal")).toHaveText("");
  await expect(page.locator("#swap-receive-address")).toBeDisabled();
  await expect.poll(() => page.evaluate(() => window.uiFixture.disposed)).toBe(1); // the unselected estimate only
  await expect(page.locator("#swap-reverse-continue")).toHaveCount(0); // execution replaced the estimate review
});
