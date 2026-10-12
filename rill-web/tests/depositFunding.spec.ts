import { expect, test, type Page } from "@playwright/test";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import regtest from "../src/networks/regtest-rillswap-e2e-v1.json" with { type: "json" };
import { testInvoice } from "../../rill-payments/tests/helpers";
import { scriptAddress } from "../src/swap/address";
import { parseTransaction, serializeTransaction, type Transaction } from "../src/swap/transaction";
import taproot from "../unit/fixtures/taproot-cases-v1.json" with { type: "json" };

const PAGE = "http://127.0.0.1:18765/test-only/swap.html";
const API = "http://127.0.0.1:8091/api";
const SCRIPT = taproot.valid[0]!.artifacts.script_pubkey;
const ADDRESS = scriptAddress(SCRIPT, "regtest");
const AMOUNT = 101_000n;

function deposit(): { parent: Transaction; tx: Transaction } {
  const change = hexToBytes(`0014${"ab".repeat(20)}`);
  const coinbase = { txid: "11".repeat(32), vout: 0, scriptSig: new Uint8Array(), sequence: 0xffffffff, witness: [new Uint8Array([1])] };
  const parent = parseTransaction(serializeTransaction({ version: 2, inputs: [coinbase], outputs: [{ value: AMOUNT + 1_000n, script: change }], locktime: 0 }, true));
  const input = { txid: parent.txid, vout: 0, scriptSig: new Uint8Array(), sequence: 0xfffffffd, witness: [new Uint8Array(64)] };
  const outputs = [{ value: AMOUNT, script: hexToBytes(SCRIPT) }, { value: 800n, script: change }];
  return { parent, tx: parseTransaction(serializeTransaction({ version: 2, inputs: [input], outputs, locktime: 0 }, true)) };
}

const entry = (tx: Transaction, confirmed: boolean) => ({
  txid: tx.txid, status: { confirmed },
  vout: tx.outputs.map((output) => ({ scriptpubkey: bytesToHex(output.script), value: Number(output.value) })),
});

/** Chain API: tip answers plus an address history that advances on each poll. */
async function chain(page: Page, histories: unknown[][], transactions: readonly Transaction[]): Promise<string[]> {
  const requests: string[] = [];
  let polls = 0;
  await page.route(`${API}/**`, async (route) => {
    const path = new URL(route.request().url()).pathname.replace("/api/", "");
    requests.push(path);
    const headers = { "Access-Control-Allow-Origin": "http://127.0.0.1:18765" };
    if (path === `address/${ADDRESS}/txs`) { await route.fulfill({ body: JSON.stringify(histories[Math.min(polls++, histories.length - 1)]), headers }); return; }
    const hex = path.match(/^tx\/([0-9a-f]{64})\/hex$/);
    const found = hex && transactions.find((tx) => tx.txid === hex[1]);
    if (hex) { await (found ? route.fulfill({ body: bytesToHex(found.raw), headers }) : route.fulfill({ status: 404, headers })); return; }
    await route.fulfill({ body: path.endsWith("/0") ? regtest.genesis_hash : path.endsWith("/height") ? "100" : "a".repeat(64), headers });
  });
  return requests;
}

async function startSwap(page: Page, expectAddress = true): Promise<void> {
  await page.goto(PAGE);
  const now = Math.floor(Date.now() / 1000);
  await page.locator("#swap-invoice").fill(testInvoice("deposit_funding", "1000000", now, now + 7200));
  await page.evaluate((script) => { window.uiFixture.fundingScript = script; }, SCRIPT);
  await page.locator("#swap-start").click();
  await page.locator("#swap-quote-accept").click();
  if (expectAddress) await expect(page.locator("#swap-contract-address")).toHaveText(ADDRESS);
}

test("the default funding step shows the address and binds the deposit once it confirms", async ({ page }) => {
  const { parent, tx } = deposit();
  const requests = await chain(page, [[entry(tx, false)], [entry(tx, true)]], [tx, parent]);
  await startSwap(page);
  await expect(page.locator("#swap-funding-uri")).toHaveAttribute("href", `bitcoin:${ADDRESS}?amount=0.00101000`);
  await expect(page.locator("#swap-funding-rules")).toContainText("at most 500 sat");
  await expect(page.locator("#swap-funding-qr")).toHaveAttribute("aria-label", `QR code: bitcoin:${ADDRESS}?amount=0.00101000`);
  expect(await page.locator("#swap-funding-qr path").getAttribute("d")).toMatch(/^(M\d+ \d+h1v1h-1z)+$/);
  await expect(page.locator("#swap-funding-advanced")).not.toHaveAttribute("open");
  await expect(page.locator("#swap-psbt")).toBeHidden(); // the PSBT path stays behind the disclosure
  await expect(page.locator("#swap-deposit-status")).toHaveText(`Payment ${tx.txid} seen, waiting for its first confirmation.`);
  await expect(page.locator("#swap-error")).toHaveText("Fixture stopped after funding", { timeout: 20_000 });
  expect(await page.evaluate(() => window.uiFixture.fundingSource)).toEqual({ depositTxid: tx.txid });
  // Both the deposit and its parent were fetched by hash so the fee rests on verified bytes.
  expect(requests).toContain(`tx/${tx.txid}/hex`);
  expect(requests).toContain(`tx/${parent.txid}/hex`);
});

test("the advanced PSBT path still hands the pasted PSBT to the swap", async ({ page }) => {
  await chain(page, [[]], []);
  await startSwap(page);
  await expect(page.locator("#swap-deposit-status")).toContainText("Waiting for your payment");
  await page.locator("#swap-funding-advanced summary").click();
  await page.locator("#swap-psbt").fill("cHNidP8BAH0=");
  await page.getByRole("button", { name: "Check funding" }).click();
  await expect(page.locator("#swap-error")).toHaveText("Fixture stopped after funding");
  expect(await page.evaluate(() => window.uiFixture.fundingSource)).toEqual({ psbt: "cHNidP8BAH0=" });
});

test("two confirmed deposits stop the swap instead of choosing one", async ({ page }) => {
  const first = deposit().tx;
  const second = parseTransaction(serializeTransaction({ ...first, locktime: 1 }, true));
  await chain(page, [[entry(first, true), entry(second, true)]], []);
  await startSwap(page, false); // the first poll already answers, replacing the address with the outcome
  await expect(page.locator("#swap-error")).toContainText(`Several confirmed payments reached this address (${first.txid}, ${second.txid})`);
  expect(await page.evaluate(() => window.uiFixture.fundingSource)).toBeUndefined();
});
