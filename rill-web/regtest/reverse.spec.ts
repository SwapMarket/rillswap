/** Opt-in isolated real node acceptance. Never resets or mines the default dev project. */
import { test, expect, type Page } from "@playwright/test";
import { execFileSync, spawn } from "node:child_process";
import { mkdirSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { assertDisposableStack, composeEnabled } from "./stack";
import { stopPaymentProcess } from "./paymentProcess";

const root = resolve(import.meta.dirname, "../.."), artifacts = resolve(root, "tmp/reverse-live");
const enabled = process.env.RILLSWAP_RUN_BROWSER_REVERSE_REGTEST === "1";
const project = process.env.COMPOSE_PROJECT_NAME;
const command = (...args: string[]): string => execFileSync(resolve(root, "dev/devctl"), args, { cwd: root, env: process.env, encoding: "utf8", timeout: 30000 }).trim();
async function download(page: Page, selector: string, filename: string): Promise<string> {
  const event = page.waitForEvent("download"); await page.locator(selector).click(); const value = await event, target = resolve(artifacts, filename); await value.saveAs(target); return target;
}
function inspectBackup(wallet: string, recovery: string): { paymentHash: string; requiredDepth: number; contractHash: string } {
  const script = `import { parseWalletBackup, walletRecoveryKey } from "./src/browserRecoveryWallet";
    import { decryptRecoveryContainer } from "./src/recoveryKeys";
    const key = await walletRecoveryKey(parseWalletBackup(await Bun.file(process.argv[1]).text()));
    const plaintext = await decryptRecoveryContainer(new Uint8Array(await Bun.file(process.argv[2]).arrayBuffer()), key.identity);
    const doc = JSON.parse(new TextDecoder().decode(plaintext)); plaintext.fill(0); key.file.fill(0);
    console.log(JSON.stringify({ paymentHash: doc.contract_terms.invoice_binding.payment_hash, requiredDepth: doc.contract_terms.funding_confirmations, contractHash: doc.contract_hash }));`;
  return JSON.parse(execFileSync("bun", ["-e", script, wallet, recovery], { cwd: resolve(root, "rill-web"), encoding: "utf8", timeout: 30000 }));
}

for (const nodePayment of [false, true]) {
test(`real unilateral browser reverse swap (${nodePayment ? "configured node" : "external wallet"}) pays once, claims nominal payout and settles its held invoice`, async ({ page }) => {
  test.skip(!enabled && !composeEnabled, "Explicit disposable-regtest opt-in required");
  assertDisposableStack();
  expect(project).toMatch(/^rill-reverse-browser-[a-z0-9-]+$/); // refuse the existing/default development project
  expect(process.env.RILL_DEV_WEB_PORT).toMatch(/^[0-9]{4,5}$/);
  expect(process.env.RILL_DEV_WEB_PORT).not.toBe("5273"); mkdirSync(artifacts, { recursive: true });
  let payer: ReturnType<typeof spawn> | undefined;
  try {
  const address = command("address", "--wallet", "user");
  let payments = 0, broadcasts = 0;
  const errors: string[] = []; page.on("pageerror", (error) => errors.push(error.message));
  page.on("request", (request) => { if (request.method() === "POST" && request.url().includes("/v2/router/route/send")) payments++;
    if (request.method() === "POST" && request.url().endsWith("/api/tx")) broadcasts++; });
  await page.goto(`http://127.0.0.1:${process.env.RILL_DEV_WEB_PORT}/swap.html`);
  await page.getByRole("button", { name: "Switch direction" }).click();
  await page.locator("#swap-receive-amount").fill("50000");
  await page.locator("#swap-start").click();
  await expect(page.locator("#swap-reverse-continue")).toBeEnabled(); // no backup check gate; the address is entered before continuing
  await page.locator("#swap-wallet-setup summary").click();
  const wallet = await download(page, '#swap-wallet-actions a[download="rillswap-recovery-key.json"]', "wallet.json");
  await page.locator("#swap-receive-address").fill(address);
  await page.locator("#swap-reverse-continue").click();
  await expect(page.locator('#swap-reverse-backups a[download="rillswap-ln-to-btc-terms.age"]')).toBeVisible();
  const backup = await download(page, '#swap-reverse-backups a[download="rillswap-ln-to-btc-terms.age"]', "terms.age"), signed = inspectBackup(wallet, backup);
  if (nodePayment) {
    await page.locator("#swap-reverse-advanced summary").click();
    await page.locator("#swap-reverse-connect").click();
    await expect(page.locator("#swap-reverse-pay")).toBeEnabled();
    await page.locator("#swap-reverse-pay").click();
  } else {
    // Any external Lightning wallet can pay the explicitly accepted hold invoice.
    await page.locator("#swap-reverse-accept").click();
    const invoice = (await page.locator("#swap-reverse-invoice").textContent())!.trim();
    payer = spawn(resolve(root, "dev/devctl"), ["lncli", "user", "payinvoice", "--force", invoice], {
      cwd: root, env: process.env, timeout: 150000, detached: true, stdio: "ignore",
    });
    payer.on("error", () => {}); // exit-code assertion below still refuses a failed payer
  }
  await expect(page.locator("#swap-reverse-prepare-claim")).toBeVisible({ timeout: 90000 }); // the page listens by itself
  await download(page, '#swap-reverse-backups a[download="rillswap-ln-to-btc-funded.age"]', "funded.age");
  command("mine", String(signed.requiredDepth));
  await page.locator("#swap-reverse-prepare-claim").click();
  await download(page, '#swap-reverse-backups a[download="rillswap-ln-to-btc-claim.age"]', "claim.age");
  await page.locator("#swap-reverse-broadcast").click();
  await expect(page.locator("#swap-status")).toContainText("Claim accepted:");
  const text = await page.locator("#swap-status").textContent(), txid = text!.match(/Claim accepted: ([0-9a-f]{64})/)![1]!;
  command("mine", "1");
  await expect.poll(() => JSON.parse(command("lncli", "maker", "lookupinvoice", signed.paymentHash)).state).toBe("SETTLED");
  await expect.poll(() => {
    const all = JSON.parse(command("lncli", "user", "listpayments", "--include_incomplete")); return all.payments.find((value: { payment_hash: string }) => value.payment_hash === signed.paymentHash)?.status;
  }).toBe("SUCCEEDED");
  await expect.poll(() => execFileSync("docker", ["exec", `${project}-tools-1`, "python", "-c",
    "import sqlite3,sys; c=sqlite3.connect('file:/state/makers/ln-to-btc/provider-store/live.sqlite?mode=ro',uri=True); print(c.execute('select state from swaps where contract_hash=?',(sys.argv[1],)).fetchone()[0])", signed.contractHash],
    { encoding: "utf8", timeout: 10000 }).trim()).toBe("SETTLED");
  const raw = JSON.parse(command("bitcoin-cli", "getrawtransaction", txid, "true")); expect(raw.confirmations).toBeGreaterThanOrEqual(1);
  expect(raw.vout).toHaveLength(1); expect(Math.round(Number(raw.vout[0].value) * 1e8)).toBeGreaterThanOrEqual(50000); expect(raw.vout[0].scriptPubKey.address).toBe(address);
  expect(raw.vin[0].txinwitness).toHaveLength(4); expect(raw.vin[0].txinwitness[1]).toMatch(/^[0-9a-f]{64}$/);
  expect(payments).toBe(nodePayment ? 1 : 0); expect(broadcasts).toBe(1); expect(errors).toEqual([]);
  await page.locator("#swap-reverse-settlement").click();
  await expect(page.locator("#swap-status")).toContainText(nodePayment ? "Swap complete" : "Bitcoin claim confirmed");
  if (payer) {
    await new Promise<void>((done) => { if (payer!.exitCode !== null || payer!.signalCode !== null) done(); else payer!.once("exit", () => done()); });
    expect(payer.exitCode).toBe(0);
  }
  // Reload never renews payment or claim submission. Recover the exact saved
  // bytes through the real page and persistent browser identity/journal.
  await page.reload();
  // The encrypted swap link opens recovery automatically. Clicking its summary
  // here would close the panel instead of preparing the explicit file import.
  await expect(page.locator("#swap-recovery-result h3")).toHaveText("Lightning to Bitcoin recovery verified");
  await page.locator("#swap-recovery-file").setInputFiles(resolve(artifacts, "claim.age")); await page.locator("#swap-recovery-inspect").click();
  await expect(page.locator("#swap-recovery-result h3")).toHaveText("Lightning to Bitcoin recovery verified");
  await page.locator("#swap-reverse-recovery-local").click(); await expect(page.locator("#swap-reverse-recovery-message")).toContainText("Local state: accepted");
  await expect(page.locator("#swap-reverse-recovery-broadcast")).toBeDisabled();
  await page.locator("#swap-reverse-recovery-export").click();
  const savedClaim = page.locator('a[download="rillswap-recovered-claim.hex"]'); await expect(savedClaim).toBeVisible();
  const exportedPath = await download(page, 'a[download="rillswap-recovered-claim.hex"]', "recovered-claim.hex");
  expect(readFileSync(exportedPath, "utf8")).toBe(raw.hex);
  expect(payments).toBe(nodePayment ? 1 : 0); expect(broadcasts).toBe(1); expect(errors).toEqual([]);
  } finally {
    // Own the host command group, even if a browser assertion fails after dispatch.
    // Killing it does not establish that LND canceled an already-dispatched payment.
    if (payer) await stopPaymentProcess(payer);
  }
});
}
