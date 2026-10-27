import { expect, test } from "./fixtures/swapPage";
import canonicalize from "canonicalize";
import { readFileSync } from "node:fs";
import { encryptCanonicalRecoveryForRecipient } from "../src/recoveryAgeContainer";
import { createRecoveryKey } from "../src/recoveryKeys";
import type { InspectionCase } from "../unit/fixtures/recoveryInspectionCases";

const corpus = (): InspectionCase[] => JSON.parse(readFileSync(new URL("../tmp/preview/test-only/recovery-inspection-cases.json", import.meta.url), "utf8"));
const plaintext = (name: string): Uint8Array => new TextEncoder().encode(canonicalize(corpus().find((item) => item.name === name)!.record)!);
const payload = (buffer: Uint8Array, name: string) => ({ name, mimeType: "application/octet-stream", buffer: Buffer.from(buffer) });

declare global {
  interface Window { recoveryImportPending: boolean; releaseRecoveryImport: () => void }
}

test("the recovery panel uses the saved browser key and makes no external connection while opening a local file", async ({ page }) => {
  const requests: string[] = [], sockets: string[] = [], consoleOutput: string[] = [];
  page.on("request", (request) => requests.push(request.url()));
  page.on("websocket", (socket) => sockets.push(socket.url()));
  page.on("console", (message) => consoleOutput.push(message.text()));
  await page.goto("http://127.0.0.1:18765/test-only/swap.html");
  await expect(page.locator("#swap-recovery-result")).not.toBeVisible();
  const recipient = await page.evaluate(async () => {
    const wallet = await window.uiFixture.wallet.open();
    try { return (await wallet.recoveryKey()).recipient; } finally { wallet.close(); }
  });
  const file = await encryptCanonicalRecoveryForRecipient(plaintext("signed funding revision zero"), recipient);
  await page.locator("#swap-recovery summary").first().click();
  await page.locator("#swap-recovery-file").setInputFiles(payload(file, "my-funded-swap.age"));
  await page.locator("#swap-recovery-inspect").click();
  await expect(page.locator("#swap-recovery-result h3")).toHaveText("Recovery record verified");
  await expect(page.locator("#swap-recovery-result")).toContainText("regtest · BTC to Lightning · 1 recorded funding revision.");
  await expect(page.locator("#swap-recovery-result")).toContainText("first eligible block is 1101");
  await expect(page.locator("#swap-recovery-result")).toContainText("Local inspection did not connect, sign, or broadcast");
  expect(sockets).toEqual([]);
  for (const url of requests) expect(new URL(url).host).toBe("127.0.0.1:18765");
  expect(consoleOutput.join("\n")).not.toContain("contract_secret_key");
  expect(consoleOutput.join("\n")).not.toContain("AGE-SECRET-KEY");
});

test("existing mainnet files can be inspected with their original age key while new mainnet swaps remain blocked", async ({ page }) => {
  const key = await createRecoveryKey();
  const file = await encryptCanonicalRecoveryForRecipient(plaintext("expired mainnet legacy, no binding"), key.recipient);
  await page.goto("http://127.0.0.1:18765/swap.html");
  await expect(page.locator("#swap-start")).toBeDisabled();
  await page.locator("#swap-recovery summary").first().click();
  await page.locator("#swap-recovery-file").setInputFiles(payload(file, "older-mainnet-swap.age"));
  await page.locator("#swap-recovery-key-file").setInputFiles(payload(key.file, "older-key.age-key"));
  await page.locator("#swap-recovery-inspect").click();
  await expect(page.locator("#swap-recovery-result h3")).toHaveText("Recovery record verified");
  await expect(page.locator("#swap-recovery-result")).toContainText("mainnet · BTC to Lightning · 0 recorded funding revisions.");
  await expect(page.locator("#swap-start")).toBeDisabled();
});

test("wrong key, wrong network, and damaged signed data are refused without exposing input or replacing the browser identity", async ({ page }) => {
  const key = await createRecoveryKey();
  const file = await encryptCanonicalRecoveryForRecipient(plaintext("signed funding revision zero"), key.recipient);
  await page.goto("http://127.0.0.1:18765/test-only/swap.html");
  const fingerprint = await page.evaluate(async () => {
    const wallet = await window.uiFixture.wallet.open();
    try { return (await wallet.info()).fingerprint; } finally { wallet.close(); }
  });
  await page.locator("#swap-recovery summary").first().click();
  await page.locator("#swap-recovery-file").setInputFiles(payload(file, "private-error-canary.age"));
  await page.locator("#swap-recovery-inspect").click();
  await expect(page.locator("#swap-recovery-result")).toContainText("Could not verify this recovery file");
  await expect(page.locator("#swap-recovery-result")).not.toContainText("private-error-canary");
  await page.locator("#swap-recovery-key-file").setInputFiles(payload(key.file, "original.key"));
  await page.locator("#swap-settings-toggle").click();
  await page.locator("#swap-network").selectOption("signet");
  await page.locator("#swap-settings-close").click();
  await page.locator("#swap-recovery-inspect").click();
  await expect(page.locator("#swap-recovery-result")).toContainText("Could not verify this recovery file");
  await page.locator("#swap-settings-toggle").click();
  await page.locator("#swap-network").selectOption("regtest");
  await page.locator("#swap-settings-close").click();
  const damaged = await encryptCanonicalRecoveryForRecipient(plaintext("invalid provider_terms_signature"), key.recipient);
  await page.locator("#swap-recovery-file").setInputFiles(payload(damaged, "damaged.age"));
  await page.locator("#swap-recovery-inspect").click();
  await expect(page.locator("#swap-recovery-result")).toContainText("Could not verify this recovery file");
  const current = await page.evaluate(async () => {
    const wallet = await window.uiFixture.wallet.open();
    try { return (await wallet.info()).fingerprint; } finally { wallet.close(); }
  });
  expect(current).toBe(fingerprint);
});

test("oversized local recovery and key files are refused before decryption", async ({ page }) => {
  await page.goto("http://127.0.0.1:18765/test-only/swap.html");
  await page.locator("#swap-recovery summary").first().click();
  await page.locator("#swap-recovery-file").setInputFiles(payload(new Uint8Array(256 * 1024 + 1), "large.age"));
  await page.locator("#swap-recovery-inspect").click();
  await expect(page.locator("#swap-recovery-result")).toContainText("at most 256 KiB");
  await page.locator("#swap-recovery-file").setInputFiles(payload(new Uint8Array(1), "small.age"));
  await page.locator("#swap-recovery-key-file").setInputFiles(payload(new Uint8Array(4097), "large.key"));
  await page.locator("#swap-recovery-inspect").click();
  await expect(page.locator("#swap-recovery-result")).toContainText("at most 4 KiB");
});

test("changing the independently selected network while opening a file discards the inspection", async ({ page }) => {
  await page.goto("http://127.0.0.1:18765/test-only/swap.html");
  await expect(page.locator("#swap-wallet-status")).toContainText("New browser recovery key created");
  const recipient = await page.evaluate(async () => {
    const wallet = await window.uiFixture.wallet.open();
    try { return (await wallet.recoveryKey()).recipient; } finally { wallet.close(); }
  });
  const file = await encryptCanonicalRecoveryForRecipient(plaintext("signed funding revision zero"), recipient);
  await page.locator("#swap-recovery summary").first().click();
  await page.locator("#swap-recovery-file").setInputFiles(payload(file, "swap.age"));
  await page.evaluate(() => {
    const prototype = window.uiFixture.wallet.prototype, original = prototype.recoveryKey;
    prototype.recoveryKey = async function() {
      prototype.recoveryKey = original;
      const key = await original.call(this);
      window.recoveryImportPending = true;
      await new Promise<void>((resolve) => { window.releaseRecoveryImport = resolve; });
      return key;
    };
  });
  await page.locator("#swap-recovery-inspect").click();
  await page.waitForFunction(() => window.recoveryImportPending);
  await page.locator("#swap-settings-toggle").click();
  await page.locator("#swap-network").selectOption("signet");
  await page.locator("#swap-settings-close").click();
  await page.evaluate(() => window.releaseRecoveryImport());
  await expect(page.locator("#swap-recovery-result")).toContainText("Could not verify this recovery file");
  await expect(page.locator("#swap-recovery-result h3")).toHaveCount(0);
  await expect(page.locator("#swap-recovery-inspect")).toBeEnabled();
});
