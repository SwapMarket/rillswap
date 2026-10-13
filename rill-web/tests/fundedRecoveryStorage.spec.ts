import { expect, test } from "@playwright/test";
import type {} from "./browserRecoveryWallet.spec";

const URL = "http://127.0.0.1:18765/test-only/wallet.html";

test("concurrent immutable funded checkpoints survive reload with exact bytes and network isolation", async ({ page }) => {
  await page.goto(URL); await page.waitForFunction(() => window.walletReady);
  const ids = await page.evaluate(async () => {
    const wallet = await window.walletApi.BrowserRecoveryWallet.open();
    try {
      const bytes = Uint8Array.of(1, 2, 3);
      const saves = [wallet.saveFundedRecovery("regtest", bytes), wallet.saveFundedRecovery("regtest", bytes),
        wallet.saveFundedRecovery("signet", bytes), wallet.saveFundedRecovery("regtest", Uint8Array.of(4, 5, 6))];
      bytes.fill(9); // Copy before the first asynchronous operation, not after commit.
      return await Promise.all(saves);
    } finally { wallet.close(); }
  });
  expect(ids[0]).toBe(ids[1]); expect(new Set(ids).size).toBe(3);
  await page.reload(); await page.waitForFunction(() => window.walletReady);
  const result = await page.evaluate(async (ids) => {
    const wallet = await window.walletApi.BrowserRecoveryWallet.open();
    try {
      return { entries: await wallet.listFundedRecoveries(), bytes: Array.from((await wallet.readFundedRecovery(ids[0]!)).ciphertext),
        network: (await wallet.readFundedRecovery(ids[2]!)).network, created: wallet.newlyCreated };
    } finally { wallet.close(); }
  }, ids);
  expect(result.entries).toHaveLength(3); expect(result.bytes).toEqual([1, 2, 3]);
  expect(result.network).toBe("signet"); expect(result.created).toBe(false);
});

for (const mode of ["quota", "abort", "relaxed", "unsupported", "readback", "mismatch"]) test(`${mode} cannot grant funded checkpoint persistence`, async ({ page }) => {
  await page.goto(URL); await page.waitForFunction(() => window.walletReady);
  const result = await page.evaluate(async (mode) => {
    const wallet = await window.walletApi.BrowserRecoveryWallet.open();
    const add = IDBObjectStore.prototype.add, get = IDBObjectStore.prototype.get, transaction = IDBDatabase.prototype.transaction;
    let committed = false, refused = false;
    IDBObjectStore.prototype.add = function(this: IDBObjectStore, ...args: Parameters<typeof add>) {
      if (mode === "quota") throw new DOMException("quota", "QuotaExceededError");
      const request = add.apply(this, args);
      if (mode === "abort") request.addEventListener("success", () => this.transaction.abort());
      return request;
    };
    IDBDatabase.prototype.transaction = function(this: IDBDatabase, ...args: Parameters<typeof transaction>) {
      if (mode === "unsupported" && args[1] === "readwrite" && args[2]?.durability === "strict") throw new TypeError("strict unsupported");
      if (mode === "readback" && committed && args[1] === "readonly") throw new Error("readback lost");
      const tx = mode === "relaxed" && args[1] === "readwrite"
        ? transaction.call(this, args[0], "readwrite", { durability: "relaxed" }) : transaction.apply(this, args);
      if (args[1] === "readwrite") tx.addEventListener("complete", () => { committed = true; });
      return tx;
    };
    IDBObjectStore.prototype.get = function(this: IDBObjectStore, ...args: Parameters<typeof get>) {
      const request = get.apply(this, args);
      if (mode === "mismatch" && committed && this.transaction.mode === "readonly") {
        request.addEventListener("success", () => { if (request.result?.ciphertext) request.result.ciphertext[0] ^= 1; });
      }
      return request;
    };
    try { await wallet.saveFundedRecovery("regtest", Uint8Array.of(1, 2, 3)); } catch { refused = true; }
    finally { IDBObjectStore.prototype.add = add; IDBObjectStore.prototype.get = get; IDBDatabase.prototype.transaction = transaction; }
    try { return { refused, entries: (await wallet.listFundedRecoveries()).length }; } finally { wallet.close(); }
  }, mode);
  expect(result.refused).toBe(true); expect(result.entries).toBe(["readback", "mismatch"].includes(mode) ? 1 : 0);
});

test("damaged snapshots remain visible beside valid snapshots and cannot replace the wallet", async ({ page }) => {
  await page.goto(URL); await page.waitForFunction(() => window.walletReady);
  const result = await page.evaluate(async () => {
    const wallet = await window.walletApi.BrowserRecoveryWallet.open();
    const id = await wallet.saveFundedRecovery("regtest", Uint8Array.of(1));
    const valid = await wallet.saveFundedRecovery("regtest", Uint8Array.of(2));
    const db = await new Promise<IDBDatabase>((resolve) => { const request = indexedDB.open(window.walletApi.WALLET_DATABASE, 1); request.onsuccess = () => resolve(request.result); });
    await new Promise<void>((resolve) => {
      const tx = db.transaction("identity", "readwrite");
      tx.objectStore("identity").put({ version: 99 }, id); tx.oncomplete = () => resolve();
    });
    const entries = await wallet.listFundedRecoveries();
    let refused = false;
    try { await wallet.readFundedRecovery(id); } catch { refused = true; }
    let overwriteRefused = false;
    try { await wallet.saveFundedRecovery("regtest", Uint8Array.of(1)); } catch { overwriteRefused = true; }
    const damaged = await new Promise<unknown>((resolve) => { const request = db.transaction("identity").objectStore("identity").get(id); request.onsuccess = () => resolve(request.result); });
    const preserved = Array.from((await wallet.readFundedRecovery(valid)).ciphertext);
    wallet.close();
    await new Promise<void>((resolve) => { const tx = db.transaction("identity", "readwrite"); tx.objectStore("identity").delete("wallet"); tx.oncomplete = () => resolve(); });
    let replacementRefused = false;
    try { const unexpected = await window.walletApi.BrowserRecoveryWallet.open(); unexpected.close(); } catch { replacementRefused = true; }
    const remaining = await new Promise<number>((resolve) => { const request = db.transaction("identity").objectStore("identity").count(); request.onsuccess = () => resolve(request.result); });
    db.close(); return { refused, overwriteRefused, damaged, entries, preserved, replacementRefused, remaining };
  });
  expect(result.refused).toBe(true); expect(result.entries.filter((entry) => "error" in entry)).toHaveLength(1);
  expect(result.preserved).toEqual([2]); expect(result.replacementRefused).toBe(true); expect(result.remaining).toBe(2);
  expect(result.overwriteRefused).toBe(true); expect(result.damaged).toEqual({ version: 99 });
});
