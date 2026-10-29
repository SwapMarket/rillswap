import type { Page } from "@playwright/test";
import canonicalize from "canonicalize";
import { readFileSync } from "node:fs";
import { directorySettled, expect, MAINNET_RELAYS, openRecoveryKey, openSettings, test } from "./fixtures/swapPage";
import { encryptCanonicalRecoveryForRecipient } from "../src/recoveryAgeContainer";
import { swapLinkFragment } from "../src/swapLink";
import type { RecoveryRefundCase } from "../unit/fixtures/recoveryRefundCases";

const URL = "http://127.0.0.1:18765/swap.html";
const FIXTURE = "http://127.0.0.1:18765/test-only/swap.html";

async function edit(page: Page, selector: string, value: string): Promise<void> {
  await page.locator(selector).fill(value);
  await page.locator(selector).blur();
}

test("valid connection edits survive reload and network round trips, but ordinary and safety controls do not", async ({ page, relaySockets }) => {
  await page.goto(URL); await directorySettled(page);
  await openSettings(page, "connection", "evm", "advanced");
  await edit(page, "#swap-relay", "wss://private-mainnet.example");
  await edit(page, "#swap-chain-api", "https://chain.example/api/");
  await edit(page, "#swap-broadcast-api", "https://send.example/api");
  await edit(page, "#swap-evm-rpc", "https://rpc.example");
  await page.locator("#swap-ranking").selectOption("price");
  await page.locator("#swap-provider").fill("a".repeat(64));
  await page.locator("#swap-reverse-claim-confirmations").fill("0");
  await page.locator("#swap-tip").fill("100");
  await page.locator("#swap-network").selectOption("signet");
  await expect(page.locator("#swap-relay")).toHaveValue(MAINNET_RELAYS.join("\n"));
  await edit(page, "#swap-relay", "wss://private-signet.example");
  await page.locator("#swap-network").selectOption("mainnet");
  await expect(page.locator("#swap-relay")).toHaveValue("wss://private-mainnet.example/");
  await expect(page.locator("#swap-chain-api")).toHaveValue("https://chain.example/api");
  relaySockets.splice(0);
  await page.reload(); await directorySettled(page);
  expect(relaySockets).toEqual(["wss://private-mainnet.example/"]);
  await openSettings(page, "connection", "evm", "advanced");
  await expect(page.locator("#swap-broadcast-api")).toHaveValue("https://send.example/api");
  await expect(page.locator("#swap-evm-rpc")).toHaveValue("https://rpc.example");
  await expect(page.locator("#swap-ranking")).toHaveValue("time");
  for (const selector of ["#swap-provider", "#swap-reverse-claim-confirmations", "#swap-tip"]) await expect(page.locator(selector)).toHaveValue("");
  await page.locator("#swap-network").selectOption("signet");
  await expect(page.locator("#swap-relay")).toHaveValue("wss://private-signet.example/");
  await page.reload(); // Network selection is not a saved preference.
  await expect(page.locator("#swap-network")).toHaveValue("mainnet");
});

test("invalid committed edits are not saved, and reset affects only the current network", async ({ page }) => {
  await page.goto(URL); await openSettings(page, "connection");
  await edit(page, "#swap-chain-api", "https://custom.example/api");
  await edit(page, "#swap-chain-api", "https://");
  await expect(page.locator("#swap-chain-api")).toHaveValue("https://");
  await expect(page.locator("#swap-connection-status")).toContainText("not saved");
  await page.reload(); await openSettings(page, "connection");
  await expect(page.locator("#swap-chain-api")).toHaveValue("https://custom.example/api");
  const originalApi = await page.locator("#swap-broadcast-api").inputValue();
  await page.locator("#swap-network").selectOption("signet");
  await edit(page, "#swap-relay", "wss://signet.example");
  await page.locator("#swap-network").selectOption("mainnet");
  await openSettings(page, "advanced");
  await page.locator("#swap-tip").fill("123");
  await page.locator("#swap-reset-connections").click();
  await expect(page.locator("#swap-tip")).toHaveValue("123");
  await expect(page.locator("#swap-chain-api")).toHaveValue(originalApi);
  await expect(page.locator("#swap-connection-status")).toContainText("reset to current defaults");
  await page.locator("#swap-network").selectOption("signet");
  await expect(page.locator("#swap-relay")).toHaveValue("wss://signet.example/");
  await page.reload(); await openSettings(page, "connection");
  await expect(page.locator("#swap-chain-api")).toHaveValue(originalApi);
});

test("recovery links select their network preferences before the first real provider discovery", async ({ page, relaySockets }) => {
  await page.goto(URL); await directorySettled(page); await openSettings(page, "connection");
  await edit(page, "#swap-relay", "wss://mainnet-only.example");
  await page.locator("#swap-network").selectOption("signet");
  await directorySettled(page);
  await edit(page, "#swap-relay", "wss://signet-only.example");
  relaySockets.splice(0);
  // The fragment parser only needs opaque ciphertext to choose the network. Recovery rejects these bytes locally.
  await page.goto(URL + swapLinkFragment({ file: new Uint8Array([1, 2, 3]), network: "signet" }));
  await directorySettled(page);
  await expect(page.locator("#swap-network")).toHaveValue("signet");
  await expect(page.locator("#swap-relay")).toHaveValue("wss://signet-only.example/");
  expect(relaySockets).toEqual(["wss://signet-only.example/"]);
});

for (const raw of ["{", '{"version":99,"overrides":{}}', '{"version":1,"overrides":{"relays":[]}}']) {
  test(`unreadable preferences never silently contact fallback relays: ${raw}`, async ({ page, relaySockets }) => {
    await page.goto(URL); await directorySettled(page); await openSettings(page, "connection");
    await edit(page, "#swap-relay", "wss://private.example");
    const key = await page.evaluate((raw) => {
      const key = Object.keys(localStorage).find((key) => key.startsWith("rillswap:connections:v1:"))!;
      localStorage.setItem(key, raw); return key;
    }, raw);
    relaySockets.splice(0);
    await page.clock.install();
    await page.reload();
    await expect(page.locator("#swap-estimate")).toContainText("Reset connection settings");
    await page.clock.fastForward(6 * 60_000);
    expect(relaySockets).toEqual([]);
    expect(await page.evaluate((key) => localStorage.getItem(key), key)).toBe(raw);
    await page.locator("#swap-start").click();
    await expect(page.locator("#swap-settings")).toBeVisible();
    expect(relaySockets).toEqual([]);
    await openSettings(page, "connection");
    await page.locator("#swap-reset-connections").click();
    await directorySettled(page);
    expect(relaySockets.length).toBeGreaterThan(0);
    expect(relaySockets.every((url) => MAINNET_RELAYS.includes(url))).toBe(true);
    expect(await page.evaluate((key) => localStorage.getItem(key), key)).toBeNull();
  });
}

test("blocked storage requires an explicit defaults choice and keeps subsequent edits session-only", async ({ page, relaySockets }) => {
  await page.addInitScript(() => Object.defineProperty(window, "localStorage", { get() { throw new DOMException("denied", "SecurityError"); } }));
  await page.goto(URL);
  await expect(page.locator("#swap-estimate")).toContainText("Saved connections could not be read");
  expect(relaySockets).toEqual([]);
  await openRecoveryKey(page);
  await expect(page.locator("#swap-wallet-status")).toContainText("browser recovery key");
  await openSettings(page, "connection");
  await page.locator("#swap-reset-connections").click();
  await directorySettled(page);
  await expect(page.locator("#swap-connection-status")).toContainText("Defaults restored for this session only");
  await edit(page, "#swap-relay", "wss://session.example");
  await expect(page.locator("#swap-connection-status")).toContainText("session only");
  await page.locator("#swap-network").selectOption("signet");
  await page.locator("#swap-network").selectOption("mainnet");
  await expect(page.locator("#swap-relay")).toHaveValue("wss://session.example/");
});

test("failed deletion reports session-only reset and does not claim saved overrides were removed", async ({ page }) => {
  await page.goto(URL); await openSettings(page, "connection");
  await edit(page, "#swap-chain-api", "https://saved.example/api");
  await page.evaluate(() => { Storage.prototype.removeItem = () => { throw new DOMException("denied"); }; });
  await page.locator("#swap-reset-connections").click();
  await expect(page.locator("#swap-connection-status")).toContainText("Defaults restored for this session only");
  await page.reload(); await openSettings(page, "connection");
  await expect(page.locator("#swap-chain-api")).toHaveValue("https://saved.example/api");
});

test("reset and reload preserve recovery identity, verified backup, refund counters and checkpoint bytes", async ({ page }) => {
  await page.goto(FIXTURE);
  const recipient = await page.evaluate(async () => {
    const wallet = await window.uiFixture.wallet.open();
    try { return (await wallet.recoveryKey()).recipient; } finally { wallet.close(); }
  });
  const item: RecoveryRefundCase = JSON.parse(readFileSync(new globalThis.URL("../tmp/preview/test-only/recovery-refund-cases.json", import.meta.url), "utf8"))[0];
  const encrypted = await encryptCanonicalRecoveryForRecipient(new TextEncoder().encode(canonicalize(item.record)!), recipient);
  const before = await page.evaluate(async (bytes) => {
    const wallet = await window.uiFixture.wallet.open();
    try {
      await wallet.verifyBackup(new TextDecoder().decode(await wallet.exportBackup()));
      await wallet.allocateRefund("regtest");
      return { info: await wallet.info(), id: await wallet.saveFundedRecovery("regtest", Uint8Array.from(bytes)) };
    } finally { wallet.close(); }
  }, Array.from(encrypted));
  await openSettings(page, "connection");
  await edit(page, "#swap-chain-api", "https://custom.example/api");
  await page.locator("#swap-reset-connections").click();
  await page.reload();
  const after = await page.evaluate(async (id) => {
    const wallet = await window.uiFixture.wallet.open();
    try { return { info: await wallet.info(), next: (await wallet.allocateRefund("regtest")).index,
      bytes: Array.from((await wallet.readFundedRecovery(id)).ciphertext) }; } finally { wallet.close(); }
  }, before.id);
  expect(after.info).toEqual(before.info);
  expect(after.next).toBe(1);
  expect(after.bytes).toEqual(Array.from(encrypted));
});
