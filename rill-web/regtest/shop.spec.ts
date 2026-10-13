import { test, expect } from "@playwright/test";
import { assertDisposableStack, command, compose, composeEnabled, run, shopURL } from "./stack";
import { fundBitcoinQuote } from "./bitcoinFlow";

const methods = [
  { rail: "lightning", label: "Lightning" }, { rail: "btc-swap", label: "Bitcoin" },
  { rail: "fusdc", label: "USDC" }, { rail: "fusdt", label: "USDT" },
  { rail: "monero", label: "Monero" }, { rail: "monero", label: "Monero", parts: 2 },
];

/** Quiesce only the owned fixture while establishing an invoice, never during payment. */
async function withStableMerchantCheckout<T>(create: () => Promise<T>): Promise<{ order: T; height: number }> {
  assertDisposableStack();
  expect(compose("ps", "--format", "{{.State}}", "miner")).toBe("running");
  expect(command("miner", "status")).toBe("auto-miner running");
  try {
    // A pause flag is not an acknowledgment: its worker may already be mining.
    // Stop the process and drain any admitted Core mining RPC before reading tips.
    compose("stop", "--timeout", "10", "miner");
    let height = 0;
    await expect(() => {
      const active = JSON.parse(command("bitcoin-cli", "getrpcinfo")).active_commands;
      expect(active.some((rpc: { method: string }) => ["generatetoaddress", "generatetodescriptor", "generateblock"].includes(rpc.method))).toBe(false);
      const tip = JSON.parse(command("bitcoin-cli", "getblockchaininfo"));
      const node = JSON.parse(command("lncli", "merchant", "getinfo"));
      expect(node.synced_to_chain).toBe(true);
      expect(node.block_hash).toBe(tip.bestblockhash); expect(node.block_height).toBe(tip.blocks);
      height = tip.blocks;
    }).toPass({ timeout: 60000 });
    return { order: await create(), height };
  } finally {
    // Compose start also starts dependencies, including the one-shot bootstrap.
    // Restart only the existing miner, without recreating it or running setup.
    compose("up", "-d", "--no-deps", "--no-recreate", "miner");
    await expect(() => expect(compose("ps", "--format", "{{.State}}", "miner")).toBe("running")).toPass({ timeout: 30000 });
  }
}

for (const { rail, label, parts } of methods) {
  test(`storefront accepts a real ${label} payment${parts ? " split across two transactions" : ""} and keeps its verified receipt`, async ({ page, request }) => {
    test.skip(!composeEnabled, "Explicit disposable Compose opt-in required");
    test.setTimeout(300000); assertDisposableStack();
    const errors: string[] = []; page.on("pageerror", (error) => errors.push(error.message));
    await page.goto(shopURL());
    await page.locator("#products .card").filter({ hasText: "Sticker" }).getByRole("button", { name: "Buy" }).click();
    await page.getByRole("radio", { name: new RegExp(`^${label}\\b`) }).check();
    const create = async () => {
      await page.getByRole("button", { name: "Continue to payment", exact: true }).click();
      await expect(page.locator("#order-status")).toHaveText("waiting");
      const id = (await page.locator("#order-id").textContent())!;
      const response = await request.get(`${shopURL()}/api/orders/${id}`); expect(response.ok()).toBe(true);
      return { id, before: await response.json() };
    };
    const checkout = rail === "lightning" || rail === "btc-swap"
      ? await withStableMerchantCheckout(create) : { order: await create(), height: null };
    const { id, before } = checkout.order;
    expect(before.rail).toBe(rail); expect(before.acceptance).toBeNull();
    if (rail === "lightning") expect(await run("pay", before.invoice)).toContain("paid, preimage");
    else if (rail === "btc-swap") {
      const link = page.getByRole("link", { name: "Continue in RillSwap" });
      expect(new URL((await link.getAttribute("href"))!).hash).toContain(encodeURIComponent(before.invoice));
      const opened = page.waitForEvent("popup"); await link.click(); const swap = await opened;
      swap.on("pageerror", (error) => errors.push(error.message));
      await expect(swap.locator("#swap-invoice")).toHaveValue(before.invoice);
      await swap.locator("#swap-start").click();
      await expect(swap.locator("#swap-quote-accept")).toBeEnabled({ timeout: 60000 });
      await swap.locator("#swap-quote-accept").click();
      await fundBitcoinQuote(swap);
      await swap.close();
    } else if (rail === "monero") await run("pay-xmr", id, "--parts", String(parts ?? 1));
    else await run("pay-token", id);
    await expect(page.locator("#order-status")).toHaveText("paid", { timeout: 180000 });
    await expect(page.locator("#order-acceptance")).toContainText("Merchant signature verified");
    const accepted = await (await request.get(`${shopURL()}/api/orders/${id}`)).json();
    expect(accepted.acceptance.eventId).toBeTruthy(); expect(accepted.acceptance.publicKey).toMatch(/^[0-9a-f]{64}$/);
    expect(accepted.acceptance.detail).toBeTruthy(); expect(accepted.acceptance.acceptedAt).toBeGreaterThan(0);
    if (rail === "lightning" || rail === "btc-swap") {
      const hash = JSON.parse(command("lncli", "user", "decodepayreq", before.invoice)).payment_hash;
      expect(JSON.parse(command("lncli", "merchant", "lookupinvoice", hash)).state).toBe("SETTLED");
    }
    if (checkout.height !== null) await expect.poll(() => Number(command("bitcoin-cli", "getblockcount")), { timeout: 30000 }).toBeGreaterThan(checkout.height);
    // Reload reopens the existing order, rather than initiating a new payment.
    await page.reload(); await page.locator(`#history tr[data-id="${id}"] a`).click();
    await expect(page.locator("#order-status")).toHaveText("paid");
    await expect(page.locator("#order-acceptance")).toContainText(accepted.acceptance.eventId);
    if (rail === "lightning") {
      // Restart only our disposable applications. The original accepted order/receipt must survive.
      compose("restart", "merchant", "shop");
      await expect(async () => {
        const response = await request.get(`${shopURL()}/api/orders/${id}`);
        expect(response.ok()).toBe(true);
        const restored = await response.json(); expect(restored.status).toBe("paid");
        expect(restored.acceptance).toEqual(accepted.acceptance);
      }).toPass({ timeout: 90000 });
    }
    expect(errors).toEqual([]);
  });
}

test("quiet checkout fixture restores actual mining after an operation fails", async () => {
  test.skip(!composeEnabled, "Explicit disposable Compose opt-in required");
  let height = 0;
  await expect(withStableMerchantCheckout(async () => {
    height = Number(command("bitcoin-cli", "getblockcount"));
    throw new Error("Owned checkout fixture failure");
  })).rejects.toThrow("Owned checkout fixture failure");
  expect(compose("ps", "--format", "{{.State}}", "miner")).toBe("running");
  await expect.poll(() => Number(command("bitcoin-cli", "getblockcount")), { timeout: 30000 }).toBeGreaterThan(height);
});
