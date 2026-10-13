import { expect, type Page } from "@playwright/test";
import { command } from "./stack";

/** Fund an accepted browser quote using Core's real finalized PSBT, never a mock chain response. */
export async function fundBitcoinQuote(page: Page): Promise<string> {
  await expect(page.locator("#swap-funding-uri")).toBeVisible();
  const uri = new URL((await page.locator("#swap-funding-uri").getAttribute("href"))!);
  const amount = uri.searchParams.get("amount")!;
  expect(Number(amount)).toBeGreaterThan(0);
  // The scoped dev chain reader has no address index. Exercise its supported
  // explicit-transaction path, retaining browser validation and provider consent.
  const psbt = command("fund-psbt", uri.pathname, amount);
  await page.locator("#swap-funding-advanced summary").click();
  await page.locator("#swap-psbt").fill(psbt);
  await page.getByRole("button", { name: "Check funding", exact: true }).click();
  await expect(page.locator("#swap-funding-raw")).toBeVisible();
  const txid = command("broadcast", (await page.locator("#swap-funding-raw").textContent())!.trim());
  command("mine", "1");
  await page.getByRole("button", { name: "I broadcast it", exact: true }).click();
  await expect(page.locator("#swap-stage h2")).toHaveText("Invoice paid", { timeout: 120000 });
  return txid;
}
