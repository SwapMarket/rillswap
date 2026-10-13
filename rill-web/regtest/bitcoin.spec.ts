import { test, expect } from "@playwright/test";
import { assertDisposableStack, command, composeEnabled, providerState, webURL } from "./stack";
import { fundBitcoinQuote } from "./bitcoinFlow";

test("browser validates a finalized Bitcoin PSBT and receives Lightning, with confirmed provider claim", async ({ page }, testInfo) => {
  test.skip(!composeEnabled, "Explicit disposable Compose opt-in required");
  assertDisposableStack();
  const errors: string[] = []; page.on("pageerror", (error) => errors.push(error.message));
  const invoice = command("invoice", "20000", "--node", "user");
  const paymentHash = JSON.parse(command("lncli", "user", "decodepayreq", invoice)).payment_hash;
  await page.goto(webURL()); await page.locator("#swap-invoice").fill(invoice);
  await page.locator("#swap-start").click();
  await expect(page.locator("#swap-quote-accept")).toBeEnabled({ timeout: 60000 });
  await page.locator("#swap-quote-accept").click();
  const txid = await fundBitcoinQuote(page);
  const preimage = (await page.locator("#swap-preimage").textContent())!.trim();
  expect(preimage).toMatch(/^[0-9a-f]{64}$/);
  const settled = JSON.parse(command("lncli", "user", "lookupinvoice", paymentHash));
  expect(settled.state).toBe("SETTLED"); expect(settled.r_preimage).toBe(preimage); // lncli renders byte fields as hex
  expect(JSON.parse(command("bitcoin-cli", "getrawtransaction", txid, "true")).confirmations).toBeGreaterThanOrEqual(1);
  await expect.poll(() => providerState("btc-to-ln", paymentHash), { timeout: 60000 }).toBe("CLAIMED");
  const backup = page.locator('#swap-backups a[download*="paid-recovery"]');
  await expect(backup).toBeVisible();
  const downloading = page.waitForEvent("download"); await backup.click();
  await (await downloading).saveAs(testInfo.outputPath("paid-recovery.age"));
  expect(errors).toEqual([]);
});
