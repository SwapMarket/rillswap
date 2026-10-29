import { test, expect } from "@playwright/test";
import { assertDisposableStack, command, compose, composeEnabled, providerState, run, webURL } from "./stack";
import { fundBitcoinQuote } from "./bitcoinFlow";

type SwapRow = { session: string; contract: string; state: string };

function swaps(direction: string): SwapRow[] {
  return JSON.parse(compose("exec", "-T", "tools", "python", "-c",
    "import sqlite3,json,sys; c=sqlite3.connect('file:/state/makers/'+sys.argv[1]+'/provider-store/live.sqlite?mode=ro',uri=True); "
    + "print(json.dumps([dict(session=s,contract=h,state=t) for s,h,t in c.execute('select session_id,contract_hash,state from swaps')]))",
    direction));
}

for (const direction of ["btc-to-ln", "ln-to-btc"] as const) {
  test(`two simultaneous CLI ${direction} swaps settle with distinct funding and recovery`, async () => {
    test.skip(!composeEnabled, "Explicit disposable Compose opt-in required");
    assertDisposableStack();
    test.setTimeout(300000);
    // Both funders still require separate sufficient confirmed witness coins.
    const wallet = direction === "btc-to-ln" ? "user" : "maker";
    const destinations = Object.fromEntries([0, 1].map(() => [command("address", "--wallet", wallet), 0.002]));
    command("bitcoin-cli", `-rpcwallet=${wallet}`, "sendmany", "", JSON.stringify(destinations));
    command("mine", "1");
    const before = new Set(swaps(direction).map((row) => row.session));
    command("miner", "pause");
    const pending = [20000, 21000].map((amount) =>
      run("swap", direction, String(amount)).then(
        (output) => ({ output, error: undefined }), (error: unknown) => ({ output: "", error })));
    let barrierError: unknown;
    try {
      // Both must reach funded, nonterminal states before either can confirm.
      await expect.poll(() => swaps(direction).filter((row) => !before.has(row.session)
        && row.state === (direction === "btc-to-ln" ? "FUNDING_SEEN" : "FUNDING_SENT")).length,
        { timeout: 90000 }).toBe(2);
    } catch (error) { barrierError = error; }
    finally { command("miner", "resume"); }
    // Drain both commands even if the overlap assertion failed, and expose a
    // command's actual diagnostic before reporting a secondary polling timeout.
    const results = await Promise.all(pending);
    for (const result of results) if (result.error) throw result.error;
    if (barrierError) throw barrierError;
    const funding: string[] = [], recovery: string[] = [], contracts: string[] = [];
    for (const result of results) {
      expect(result.output).toContain(direction === "btc-to-ln" ? "Paid. preimage" : "Received");
      funding.push(result.output.match(/\(funding ([0-9a-f]{64}), contract/)![1]!);
      contracts.push(result.output.match(/, contract ([0-9a-f]{64})\)/)![1]!);
      recovery.push(result.output.match(/recovery files in (\S+)/)![1]!);
    }
    expect(new Set(funding).size).toBe(2);
    expect(new Set(contracts).size).toBe(2);
    expect(new Set(recovery).size).toBe(2);
    const inputs = funding.map((txid) => {
      const tx = JSON.parse(command("bitcoin-cli", "getrawtransaction", txid, "true"));
      expect(tx.confirmations).toBeGreaterThanOrEqual(1);
      expect(tx.vin).toHaveLength(1);
      return `${tx.vin[0].txid}:${tx.vin[0].vout}`;
    });
    expect(new Set(inputs).size).toBe(2);
    const terminal = direction === "btc-to-ln" ? "CLAIMED" : "SETTLED";
    await expect.poll(() => swaps(direction).filter((row) => contracts.includes(row.contract))
      .map((row) => row.state), { timeout: 60000 }).toEqual([terminal, terminal]);
    for (const path of recovery) expect(compose("exec", "-T", "tools", "test", "-s", `${path}/recovery.age`)).toBe("");
    // Unrelated operator reservations are valid and must not be cleared.
    await expect.poll(() => {
      const locked = JSON.parse(command("bitcoin-cli", `-rpcwallet=${wallet}`, "listlockunspent")) as { txid: string; vout: number }[];
      return locked.filter((coin) => inputs.includes(`${coin.txid}:${coin.vout}`));
    }).toEqual([]);
  });
}

test("signed CLI funding keeps its coin reserved across a wallet restart", async () => {
  test.skip(!composeEnabled, "Explicit disposable Compose opt-in required");
  assertDisposableStack();
  const address = command("address", "--wallet", "user");
  command("bitcoin-cli", "-rpcwallet=user", "sendtoaddress", address, "0.002");
  command("mine", "1");
  const script = JSON.parse(command("bitcoin-cli", "-rpcwallet=user", "getaddressinfo", address)).scriptPubKey;
  const coin = JSON.parse(compose("exec", "-T", "tools", "python", "-c",
    "import json,sys; from pathlib import Path; from rill_core.wire.types import NetworkIdentity; from rill_cli.wallet_rpc import WalletRpc; "
    + "w=WalletRpc(port=18443,cookie_path='/state/user/core.cookie',wallet='user',network=NetworkIdentity.model_validate_json(Path('/state/user/network.json').read_bytes())); "
    + "f=w.fund(bytes.fromhex(sys.argv[1]),50000,fee_rate_sat_vb=2); "
    + "print(json.dumps(dict(txid=f.inputs[0].txid.hex(),vout=f.inputs[0].output_index)))", script));
  try {
    expect(JSON.parse(command("bitcoin-cli", "-rpcwallet=user", "listlockunspent"))).toContainEqual(coin);
    command("bitcoin-cli", "unloadwallet", "user");
    command("bitcoin-cli", "loadwallet", "user");
    expect(JSON.parse(command("bitcoin-cli", "-rpcwallet=user", "listlockunspent"))).toContainEqual(coin);
  } finally {
    // Explicit operator cleanup: this test never submits the signed transaction.
    command("bitcoin-cli", "-rpcwallet=user", "lockunspent", "true", JSON.stringify([coin]));
  }
});

test("two browser tabs retain independent swaps while the later swap settles first", async ({ context }) => {
  test.skip(!composeEnabled, "Explicit disposable Compose opt-in required");
  assertDisposableStack();
  test.setTimeout(300000);
  const pages = await Promise.all([context.newPage(), context.newPage()]);
  const invoices = [20000, 21000].map((amount) => command("invoice", String(amount), "--node", "user"));
  const hashes = invoices.map((invoice) => JSON.parse(command("lncli", "user", "decodepayreq", invoice)).payment_hash);
  const errors: string[] = [];
  await Promise.all(pages.map(async (page, index) => {
    page.on("pageerror", (error) => errors.push(error.message));
    await page.goto(webURL());
    await page.locator("#swap-invoice").fill(invoices[index]!);
    await page.locator("#swap-start").click();
    await expect(page.locator("#swap-funding-uri")).toBeVisible({ timeout: 60000 });
  }));
  expect(await pages[0]!.locator("#swap-funding-uri").getAttribute("href"))
    .not.toBe(await pages[1]!.locator("#swap-funding-uri").getAttribute("href"));
  for (const index of [1, 0]) {
    const page = pages[index]!;
    await fundBitcoinQuote(page);
    const invoice = JSON.parse(command("lncli", "user", "lookupinvoice", hashes[index]!));
    expect(invoice.state).toBe("SETTLED");
    expect(invoice.r_preimage).toBe((await page.locator("#swap-preimage").textContent())!.trim());
    await expect.poll(() => providerState("btc-to-ln", hashes[index]!), { timeout: 60000 }).toBe("CLAIMED");
    if (index === 1) {
      await expect(pages[0]!.locator("#swap-funding-uri")).toBeVisible();
      expect(JSON.parse(command("lncli", "user", "lookupinvoice", hashes[0]!)).state).toBe("OPEN");
    }
  }
  for (const page of pages) {
    await page.reload();
    await expect(page.locator("#swap-recovery-result h3")).toHaveText("Recovery record verified");
  }
  expect(errors).toEqual([]);
});
