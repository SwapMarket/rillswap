/**
 * Opt-in acceptance of the browser ERC20 to Lightning swap against the running dev stack. A fake
 * EIP-1193 wallet forwards signing to Anvil's unlocked user account (account 1); it spends dev fUSDC only.
 */
import { test, expect } from "@playwright/test";
import { execFileSync } from "node:child_process";
import { resolve } from "node:path";

const root = resolve(import.meta.dirname, "../..");
const enabled = process.env.RILLSWAP_RUN_BROWSER_ERC20_REGTEST === "1";
const project = process.env.COMPOSE_PROJECT_NAME ?? "rillswap-dev";
const webPort = process.env.RILL_DEV_WEB_PORT ?? "5273", anvilPort = process.env.RILL_DEV_ANVIL_PORT ?? "8545";
const USER = "0x70997970c51812dc3a010c7d01b50e0d17dc79c8"; // Anvil account 1, funded with fUSDC by bootstrap
const command = (...args: string[]): string => execFileSync(resolve(root, "dev/devctl"), args, { cwd: root, env: process.env, encoding: "utf8", timeout: 30000 }).trim();
const makerState = (lockTxHash: string): string => execFileSync("docker", ["exec", `${project}-tools-1`, "python", "-c",
  "import sqlite3,sys; c=sqlite3.connect('file:/state/makers/erc20-to-ln/provider-store/live.sqlite?mode=ro',uri=True); "
  + "r=c.execute(\"select s.state from swaps s join evm_swaps e on e.session_id=s.session_id where lower(replace(e.lock_tx_hash,'0x',''))=?\",(sys.argv[1],)).fetchone(); print(r[0] if r else '')",
  lockTxHash], { encoding: "utf8", timeout: 10000 }).trim();

test("browser locks fUSDC through an injected wallet and the provider pays the invoice", async ({ page }) => {
  test.skip(!enabled, "Explicit dev-stack opt-in required");
  const invoice = command("invoice", "20000", "--node", "user");
  const paymentHash = JSON.parse(command("lncli", "user", "decodepayreq", invoice)).payment_hash as string;
  const errors: string[] = []; page.on("pageerror", (error) => errors.push(error.message));
  const walletCalls: string[] = [];
  await page.exposeFunction("__walletCall", (method: string) => { walletCalls.push(method); });
  await page.addInitScript(({ rpc, account }) => {
    (window as unknown as { ethereum: unknown }).ethereum = {
      request: async ({ method, params }: { method: string; params?: unknown[] }) => {
        (window as unknown as { __walletCall: (m: string) => void }).__walletCall(method);
        if (method === "eth_requestAccounts" || method === "eth_accounts") return [account];
        if (method === "wallet_switchEthereumChain") return null;
        // Anvil runs with --base-fee 0; its eth_sendTransaction defaults would otherwise pick a priority fee above the max fee.
        if (method === "eth_sendTransaction") params = [{ ...(params![0] as object), maxFeePerGas: "0x0", maxPriorityFeePerGas: "0x0" }];
        const response = await fetch(rpc, { method: "POST", headers: { "content-type": "application/json" },
          body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params: params ?? [] }) });
        const body = await response.json() as { result?: unknown; error?: { message: string } };
        if (body.error) throw new Error(body.error.message);
        return body.result;
      },
    };
  }, { rpc: `http://127.0.0.1:${anvilPort}`, account: USER });
  await page.goto(`http://127.0.0.1:${webPort}/swap.html`);
  await page.locator("#swap-from").selectOption("usdc");
  await expect(page.locator("#swap-to")).toHaveValue("ln");
  await page.locator("#swap-invoice").fill(invoice);
  await page.locator("#swap-start").click();
  await expect(page.locator("#swap-quote-accept")).toBeVisible({ timeout: 60000 });
  await expect(page.locator("#swap-quote-summary h2")).toContainText("fUSDC");
  const lockText = (await page.locator("#swap-quote-summary h2").textContent())!;
  expect(Number(lockText.split(" ")[0])).toBeGreaterThanOrEqual(20); // 20,000 sat at 100,000 fUSDC/BTC plus the fee
  await page.locator("#swap-quote-accept").click();
  await expect(page.locator("#swap-status")).toContainText("Lightning invoice paid", { timeout: 150000 });
  const paid = await page.locator("#swap-erc20-paid").textContent();
  const lockTx = paid!.match(/Lock ([0-9a-f]{64})/)![1]!;
  const receipt = JSON.parse(command("cast", "receipt", `0x${lockTx}`, "--json"));
  expect(receipt.status).toBe("0x1");
  expect(walletCalls.filter((method) => method === "eth_sendTransaction").length).toBe(2); // approve, lock
  await expect.poll(() => JSON.parse(command("lncli", "user", "lookupinvoice", paymentHash)).state).toBe("SETTLED");
  await expect(page.locator('#swap-erc20-files a[download="rillswap-fusdc-to-ln-paid.age"]')).toBeVisible();
  expect(errors).toEqual([]);
  // The provider's store converges on CLAIMED once its claim confirms.
  await expect.poll(() => makerState(lockTx), { timeout: 60000 }).toBe("CLAIMED");
  // The swap link reopens the encrypted record locally; the chain check sees the provider's claim, so no refund is offered.
  expect(page.url()).toContain("#");
  await page.reload();
  await expect(page.locator("#swap-recovery-result h3")).toHaveText("fUSDC to Lightning recovery verified");
  await expect(page.locator("#swap-recovery-result")).toContainText(`Lock transaction ${lockTx}`);
  await page.locator("#swap-evm-recovery-check").click();
  await expect(page.locator("#swap-evm-recovery-message")).toContainText("Claimed by the provider");
  await expect(page.locator("#swap-evm-recovery-refund")).toBeDisabled();
  expect(errors).toEqual([]);
});
