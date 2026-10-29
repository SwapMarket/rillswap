import { test, expect, type Page } from "@playwright/test";
import type { EvmAssetIdentity } from "../src/manualProviderAdvertisement";

const PAGE = "http://127.0.0.1:18765/test-only/erc20-funding.html";
const asset = { chain_id: 1, token_contract: `0x${"ab".repeat(20)}`, htlc_contract: `0x${"cd".repeat(20)}` } as EvmAssetIdentity;
const account = `0x${"ef".repeat(20)}`;
type LockWindow = {
  erc20FundingLock: (asset: EvmAssetIdentity, account: string, signal?: AbortSignal) => <T>(body: () => Promise<T>) => Promise<T>;
  release?: () => void;
  entered?: boolean;
};

async function open(page: Page): Promise<void> {
  await page.goto(PAGE);
  await page.waitForFunction(() => typeof (window as unknown as LockWindow).erc20FundingLock === "function");
}

test("same-wallet funding waits across tabs, then resumes after confirmation releases the lock", async ({ context }) => {
  const first = await context.newPage(), second = await context.newPage();
  await Promise.all([open(first), open(second)]);
  const held = first.evaluate(({ asset, account }) => {
    const w = window as unknown as LockWindow;
    return w.erc20FundingLock(asset, account)(() => new Promise<string>((resolve) => {
      w.release = () => resolve("confirmed");
    }));
  }, { asset, account });
  await first.waitForFunction(() => typeof (window as unknown as LockWindow).release === "function");
  const waiting = second.evaluate(async ({ asset, account }) => {
    const w = window as unknown as LockWindow;
    // Address case must not partition the allowance lock.
    return w.erc20FundingLock({ ...asset, token_contract: asset.token_contract.toUpperCase() }, account.toUpperCase())(async () => {
      w.entered = true;
      return "second funded";
    });
  }, { asset, account });
  await expect.poll(() => second.evaluate(async () => (await navigator.locks.query()).pending?.length)).toBe(1);
  expect(await second.evaluate(() => (window as unknown as LockWindow).entered)).toBeUndefined();
  await first.evaluate(() => (window as unknown as LockWindow).release!());
  expect(await held).toBe("confirmed");
  expect(await waiting).toBe("second funded");
});

for (const dimension of ["account", "chain", "token", "htlc"] as const) {
  test(`unrelated ${dimension} funding does not wait`, async ({ page }) => {
    await open(page);
    expect(await page.evaluate(async ({ asset, account, dimension }) => {
      const w = window as unknown as LockWindow;
      const first = w.erc20FundingLock(asset, account)(() => new Promise<void>((resolve) => { w.release = resolve; }));
      while (!w.release) await new Promise((resolve) => setTimeout(resolve, 0));
      const other = { ...asset };
      if (dimension === "chain") other.chain_id++;
      if (dimension === "token") other.token_contract = `0x${"12".repeat(20)}`;
      if (dimension === "htlc") other.htlc_contract = `0x${"34".repeat(20)}`;
      try {
        return await w.erc20FundingLock(other, dimension === "account" ? `0x${"56".repeat(20)}` : account)(async () => "funded");
      } finally { w.release(); await first; }
    }, { asset, account, dimension })).toBe("funded");
  });
}

test("aborting a queued swap prevents its funding callback without interrupting the owner", async ({ page }) => {
  await open(page);
  const result = page.evaluate(async ({ asset, account }) => {
    const w = window as unknown as LockWindow;
    const owner = w.erc20FundingLock(asset, account)(() => new Promise<string>((resolve) => { w.release = () => resolve("owner confirmed"); }));
    while (!w.release) await new Promise((resolve) => setTimeout(resolve, 0));
    const abort = new AbortController();
    const waiter = w.erc20FundingLock(asset, account, abort.signal)(async () => { w.entered = true; });
    abort.abort();
    let refused = false;
    try { await waiter; } catch (error) { refused = error instanceof DOMException && error.name === "AbortError"; }
    w.release();
    return { refused, entered: w.entered ?? false, owner: await owner };
  }, { asset, account });
  expect(await result).toEqual({ refused: true, entered: false, owner: "owner confirmed" });
});

test("a failed funding callback releases the lock, and unsupported browsers refuse it", async ({ page }) => {
  await open(page);
  expect(await page.evaluate(async ({ asset, account }) => {
    const w = window as unknown as LockWindow, lock = w.erc20FundingLock(asset, account);
    try { await lock(async () => { throw new Error("wallet refused"); }); } catch { /* the next swap can retry */ }
    const next = await lock(async () => "released");
    Object.defineProperty(navigator, "locks", { value: undefined, configurable: true });
    try { w.erc20FundingLock(asset, account); } catch (error) { return { next, error: (error as Error).message }; }
    return { next, error: "not refused" };
  }, { asset, account })).toEqual({ next: "released", error: expect.stringContaining("Web Locks support") });
});
