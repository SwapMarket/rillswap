import { expect, test, type Page } from "@playwright/test";
import canonicalize from "canonicalize";
import { readFileSync } from "node:fs";
import { encryptCanonicalRecoveryForRecipient } from "../src/recoveryAgeContainer";
import { createRecoveryKey } from "../src/recoveryKeys";
import type { RecoveryRefundCase } from "../unit/fixtures/recoveryRefundCases";

const BASE = "http://127.0.0.1:8091/api";
const corpus = (): RecoveryRefundCase[] => JSON.parse(readFileSync(new URL("../tmp/preview/test-only/recovery-refund-cases.json", import.meta.url), "utf8"));
const payload = (buffer: Uint8Array, name: string) => ({ name, mimeType: "application/octet-stream", buffer: Buffer.from(buffer) });

async function importRecord(page: Page, item: RecoveryRefundCase): Promise<void> {
  const recipient = await page.evaluate(async () => {
    const wallet = await window.uiFixture.wallet.open();
    try { return (await wallet.recoveryKey()).recipient; } finally { wallet.close(); }
  });
  const encrypted = await encryptCanonicalRecoveryForRecipient(new TextEncoder().encode(canonicalize(item.record)!), recipient);
  await page.locator("#swap-recovery summary").first().click();
  await page.locator("#swap-recovery-file").setInputFiles(payload(encrypted, "public-test-swap.age"));
  await page.locator("#swap-recovery-inspect").click();
  await expect(page.locator("#swap-recovery-result h3")).toHaveText("Recovery record verified");
}

async function chainApi(page: Page, item: RecoveryRefundCase, tip = 1101, pause?: () => Promise<void>) {
  const calls: string[] = [];
  await page.route(`${BASE}/**`, async (route) => {
    const request = route.request(), path = new URL(request.url()).pathname.slice(5);
    calls.push(path);
    expect(request.method()).toBe("GET"); expect(request.postData()).toBeNull();
    expect(request.headers()["authorization"]).toBeUndefined(); expect(request.headers()["referer"]).toBeUndefined();
    if (path.endsWith("/hex") && pause) await pause();
    let body: string | undefined;
    if (path === "block-height/0") body = item.record.network_identity.genesis_hash;
    else if (path === "blocks/tip/height") body = String(tip);
    else if (path === "blocks/tip/hash") body = "a".repeat(64);
    else if (path === "block-height/1000") body = "d".repeat(64);
    else if (path === `tx/${item.record.funding_history[item.bindingRevision]!.binding.funding_txid}/hex`) body = item.fundingTxHex;
    else if (path.endsWith("/status")) body = JSON.stringify({ confirmed: true, block_height: 1000, block_hash: "d".repeat(64) });
    else if (path.endsWith("/outspend/0")) body = '{"spent":false}';
    await route.fulfill({ status: body ? 200 : 404, body: body ?? "Unknown fixture transaction", headers: {
      "Access-Control-Allow-Origin": "http://127.0.0.1:18765", "Content-Type": path.endsWith("/status") || path.includes("outspend") ? "application/json" : "text/plain",
    } });
  });
  return calls;
}

test("local inspection connects to nothing; an explicit funding check reports trusted mature observations", async ({ page }) => {
  const item = corpus()[0]!, calls = await chainApi(page, item);
  await page.goto("http://127.0.0.1:18765/test-only/swap.html");
  await importRecord(page, item);
  expect(calls).toEqual([]);
  await expect(page.locator("#swap-recovery-revision")).not.toBeVisible();
  await page.locator("#swap-recovery-check-funding").click();
  await expect(page.locator("#swap-recovery-funding-result h3")).toHaveText("Funding observed by your API");
  await expect(page.locator("#swap-recovery-funding-result")).toContainText("102 confirmations");
  await expect(page.locator("#swap-recovery-funding-result")).toContainText("refund lock has passed");
  await expect(page.locator("#swap-recovery-funding-result")).toContainText("not independent chain proof or permission to sign");
  await expect(page.locator("#swap-recovery-funding-result")).toContainText("Nothing was signed or broadcast");
  expect(calls.filter((path) => path.endsWith("/hex"))).toHaveLength(2);
  expect(calls.filter((path) => path.includes("outspend"))).toHaveLength(2);
  await page.locator("#swap-recovery-file").setInputFiles([]);
  await expect(page.locator("#swap-recovery-funding-controls")).not.toBeVisible();
  await expect(page.locator("#swap-recovery-result h3")).toHaveCount(0);
  await expect(page.locator("#swap-recovery-funding-result h3")).toHaveCount(0);
});

test("a coherent immature observation is a waiting state, not a refund authorization", async ({ page }) => {
  const item = corpus()[0]!; await chainApi(page, item, 1100);
  await page.goto("http://127.0.0.1:18765/test-only/swap.html"); await importRecord(page, item);
  await page.locator("#swap-recovery-check-funding").click();
  await expect(page.locator("#swap-recovery-funding-result h3")).toHaveText("Funding observed by your API");
  await expect(page.locator("#swap-recovery-funding-result")).toContainText("Waiting for a tip above block 1100");
  await expect(page.locator("#swap-recovery-funding-result")).not.toContainText("refund lock has passed");
});

for (const changed of ["network", "API"]) {
  test(`completed observations are cleared on ${changed} changes without any new connection`, async ({ page }) => {
    const item = corpus()[0]!, calls = await chainApi(page, item);
    const outside: string[] = [], sockets: string[] = [];
    page.on("request", (request) => { if (new URL(request.url()).host !== "127.0.0.1:18765") outside.push(request.url()); });
    page.on("websocket", (socket) => sockets.push(socket.url()));
    await page.goto("http://127.0.0.1:18765/test-only/swap.html"); await importRecord(page, item);
    await page.locator("#swap-recovery-check-funding").click();
    await expect(page.locator("#swap-recovery-funding-result h3")).toHaveText("Funding observed by your API");
    const before = calls.length;
    const outsideBefore = outside.length;
    await page.locator("#swap-settings-toggle").click();
    if (changed === "network") await page.locator("#swap-network").selectOption("signet");
    else await page.locator("#swap-chain-api").fill("https://mempool.space/api");
    await page.locator("#swap-settings-close").click();
    await expect(page.locator("#swap-recovery-funding-result")).toBeEmpty();
    expect(calls).toHaveLength(before);
    expect(outside).toHaveLength(outsideBefore); expect(sockets).toEqual([]);
  });
}

test("a failed observation acknowledges no signing/broadcast without denying the API disclosure", async ({ page }) => {
  const item = corpus()[0]!, calls = await chainApi(page, item);
  await page.route(`${BASE}/tx/*/outspend/0`, (route) => route.fulfill({ status: 200, body: '{"spent":true}', headers: { "Access-Control-Allow-Origin": "http://127.0.0.1:18765" } }));
  await page.goto("http://127.0.0.1:18765/test-only/swap.html"); await importRecord(page, item);
  await page.locator("#swap-recovery-check-funding").click();
  await expect(page.locator("#swap-recovery-funding-result")).toContainText("Funding could not be verified");
  await expect(page.locator("#swap-recovery-funding-result")).toContainText("Nothing was signed or broadcast");
  await expect(page.locator("#swap-recovery-funding-result")).not.toContainText("Nothing was signed or sent");
  expect(calls.some((path) => path.endsWith("/hex"))).toBe(true);
});

test("zero funding history never exposes a funding check or makes a chain connection", async ({ page }) => {
  const item = structuredClone(corpus()[0]!); item.record.funding_history = [];
  const calls = await chainApi(page, item);
  await page.goto("http://127.0.0.1:18765/test-only/swap.html"); await importRecord(page, item);
  await expect(page.locator("#swap-recovery-result")).toContainText("0 recorded funding revisions");
  await expect(page.locator("#swap-recovery-funding-controls")).not.toBeVisible();
  expect(calls).toEqual([]);
});

test("production CSP blocks unapproved recovery API origins while mainnet funding stays disabled", async ({ page }) => {
  const item = corpus().find((c) => c.name === "existing mainnet refund")!, key = await createRecoveryKey();
  const encrypted = await encryptCanonicalRecoveryForRecipient(new TextEncoder().encode(canonicalize(item.record)!), key.recipient);
  let reached = false;
  await page.route("https://unapproved.invalid/**", async (route) => { reached = true; await route.abort(); });
  await page.goto("http://127.0.0.1:18765/swap.html");
  await page.locator("#swap-settings-toggle").click(); await page.locator("#swap-chain-api").fill("https://unapproved.invalid/api");
  await page.locator("#swap-settings-close").click();
  await page.locator("#swap-recovery summary").first().click();
  await page.locator("#swap-recovery-file").setInputFiles(payload(encrypted, "mainnet-test.age"));
  await page.locator("#swap-recovery-key-file").setInputFiles(payload(key.file, "original.key"));
  await page.locator("#swap-recovery-inspect").click();
  await expect(page.locator("#swap-recovery-result h3")).toHaveText("Recovery record verified");
  await page.locator("#swap-recovery-check-funding").click();
  await expect(page.locator("#swap-recovery-funding-result")).toContainText("Funding could not be verified");
  expect(reached).toBe(false); await expect(page.locator("#swap-start")).toBeDisabled();
});

test("multiple revisions require an explicit choice and a failed newest revision never falls back automatically", async ({ page }) => {
  const item = corpus().find((c) => c.name === "explicit older revision selection")!, calls = await chainApi(page, item);
  await page.goto("http://127.0.0.1:18765/test-only/swap.html"); await importRecord(page, item);
  await expect(page.locator("#swap-recovery-revision")).toHaveValue("1");
  await page.locator("#swap-recovery-check-funding").click();
  await expect(page.locator("#swap-recovery-funding-result")).toContainText("Funding could not be verified");
  expect(calls.some((path) => path.includes(item.record.funding_history[0]!.binding.funding_txid))).toBe(false);
  await page.locator("#swap-recovery-revision").selectOption("0");
  await expect(page.locator("#swap-recovery-funding-result")).toBeEmpty();
  await page.locator("#swap-recovery-check-funding").click();
  await expect(page.locator("#swap-recovery-funding-result h3")).toHaveText("Funding observed by your API");
});

for (const changed of ["network", "API", "file", "key", "revision"]) {
  test(`changed ${changed} while observing discards the stale result`, async ({ page }) => {
    const item = corpus().find((c) => c.name === "explicit newest revision selection")!;
    let release!: () => void, started!: () => void;
    const pending = new Promise<void>((resolve) => { started = resolve; });
    const gate = new Promise<void>((resolve) => { release = resolve; });
    await chainApi(page, item, 1101, async () => { started(); await gate; });
    await page.goto("http://127.0.0.1:18765/test-only/swap.html"); await importRecord(page, item);
    await page.locator("#swap-recovery-check-funding").click(); await pending;
    if (changed === "network" || changed === "API") {
      await page.locator("#swap-settings-toggle").click();
      if (changed === "network") await page.locator("#swap-network").selectOption("signet");
      else await page.locator("#swap-chain-api").fill("https://mempool.space/api");
      await page.locator("#swap-settings-close").click();
    } else if (changed === "file") await page.locator("#swap-recovery-file").setInputFiles([]);
    else if (changed === "key") {
      const key = await createRecoveryKey(); await page.locator("#swap-recovery-key-file").setInputFiles(payload(key.file, "different.key"));
    } else await page.evaluate(() => {
      const select = document.querySelector<HTMLSelectElement>("#swap-recovery-revision")!;
      select.value = "0"; select.dispatchEvent(new Event("change"));
    });
    release();
    await expect(page.locator("#swap-recovery-funding-result")).toContainText("Funding could not be verified");
    await expect(page.locator("#swap-recovery-funding-result h3")).toHaveCount(0);
    await expect(page.locator("#swap-recovery-check-funding")).toBeEnabled();
  });
}
