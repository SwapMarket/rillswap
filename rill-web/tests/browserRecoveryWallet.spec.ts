import { expect, test } from "@playwright/test";
import type { BrowserRecoveryWallet } from "../src/browserRecoveryWallet";

declare global {
  interface Window {
    walletApi: { BrowserRecoveryWallet: typeof BrowserRecoveryWallet; WALLET_DATABASE: string };
    walletReady: boolean;
  }
}
const URL = "http://127.0.0.1:18765/test-only/wallet.html";

test("two tabs initialize one identity and atomically reserve distinct refund indices", async ({ context }) => {
  const pages = await Promise.all([context.newPage(), context.newPage()]);
  await Promise.all(pages.map(async (page) => { await page.goto(URL); await page.waitForFunction(() => window.walletReady); }));
  const results = await Promise.all(pages.map((page) => page.evaluate(async () => {
    const wallet = await window.walletApi.BrowserRecoveryWallet.open();
    try {
      const info = await wallet.info();
      const allocations = await Promise.all(Array.from({ length: 10 }, () => wallet.allocateRefund("regtest")));
      return { fingerprint: info.fingerprint, created: wallet.newlyCreated, allocations };
    } finally { wallet.close(); }
  })));
  expect(new Set(results.map((result) => result.fingerprint)).size).toBe(1);
  expect(results.filter((result) => result.created)).toHaveLength(1);
  const allocations = results.flatMap((result) => result.allocations);
  expect(allocations.map((item) => item.index).sort((a, b) => a - b)).toEqual(Array.from({ length: 20 }, (_, i) => i));
  expect(new Set(allocations.map((item) => item.address)).size).toBe(20);
});

test("backup verification racing allocation preserves the counter high-water mark", async ({ page }) => {
  await page.goto(URL); await page.waitForFunction(() => window.walletReady);
  const result = await page.evaluate(async () => {
    const wallet = await window.walletApi.BrowserRecoveryWallet.open();
    try {
      const backup = new TextDecoder().decode(await wallet.exportBackup());
      await Promise.all([wallet.verifyBackup(backup), ...Array.from({ length: 12 }, () => wallet.allocateRefund("signet"))]);
      return { info: await wallet.info(), next: (await wallet.allocateRefund("signet")).index };
    } finally { wallet.close(); }
  });
  expect(result.info.backupVerified).toBe(true);
  expect(result.next).toBe(12);
});

test("corrupt or unsupported stored state is preserved, never replaced with a new identity", async ({ page }) => {
  await page.goto(URL); await page.waitForFunction(() => window.walletReady);
  const result = await page.evaluate(async () => {
    const wallet = await window.walletApi.BrowserRecoveryWallet.open(); wallet.close();
    const write = await new Promise<IDBDatabase>((resolve) => { const req = indexedDB.open(window.walletApi.WALLET_DATABASE, 1); req.onsuccess = () => resolve(req.result); });
    await new Promise<void>((resolve) => { const tx = write.transaction("identity", "readwrite"); tx.objectStore("identity").put({ version: 99 }, "wallet"); tx.oncomplete = () => resolve(); });
    let refused = false;
    try { const reopened = await window.walletApi.BrowserRecoveryWallet.open(); reopened.close(); } catch { refused = true; }
    const value = await new Promise<unknown>((resolve) => { const req = write.transaction("identity").objectStore("identity").get("wallet"); req.onsuccess = () => resolve(req.result); });
    write.close(); return { refused, value };
  });
  expect(result).toEqual({ refused: true, value: { version: 99 } });
});

test("aborted allocation does not expose an address or advance durable state", async ({ page }) => {
  await page.goto(URL); await page.waitForFunction(() => window.walletReady);
  const result = await page.evaluate(async () => {
    const wallet = await window.walletApi.BrowserRecoveryWallet.open();
    const original = IDBObjectStore.prototype.put;
    let refused = false;
    try {
      IDBObjectStore.prototype.put = () => { throw new DOMException("quota", "QuotaExceededError"); };
      try { await wallet.allocateRefund("mainnet"); } catch { refused = true; }
    } finally { IDBObjectStore.prototype.put = original; }
    try { return { refused, next: (await wallet.allocateRefund("mainnet")).index }; }
    finally { wallet.close(); }
  });
  expect(result).toEqual({ refused: true, next: 0 });
});

test("reload reuses the verified identity and retains consumed indices", async ({ page }) => {
  await page.goto(URL); await page.waitForFunction(() => window.walletReady);
  const initial = await page.evaluate(async () => {
    const wallet = await window.walletApi.BrowserRecoveryWallet.open();
    try {
      await wallet.verifyBackup(new TextDecoder().decode(await wallet.exportBackup()));
      await wallet.allocateRefund("regtest");
      return (await wallet.info()).fingerprint;
    } finally { wallet.close(); }
  });
  await page.reload(); await page.waitForFunction(() => window.walletReady);
  const restored = await page.evaluate(async () => {
    const wallet = await window.walletApi.BrowserRecoveryWallet.open();
    try { return { created: wallet.newlyCreated, info: await wallet.info(), index: (await wallet.allocateRefund("regtest")).index }; }
    finally { wallet.close(); }
  });
  expect(restored.created).toBe(false);
  expect(restored.info.fingerprint).toBe(initial);
  expect(restored.info.backupVerified).toBe(true);
  expect(restored.index).toBe(1);
});

test("abort after successful write request never returns an address or consumes a durable index", async ({ page }) => {
  await page.goto(URL); await page.waitForFunction(() => window.walletReady);
  const result = await page.evaluate(async () => {
    const wallet = await window.walletApi.BrowserRecoveryWallet.open();
    const original = IDBObjectStore.prototype.put;
    let refused = false;
    IDBObjectStore.prototype.put = function(this: IDBObjectStore, ...args: Parameters<typeof original>) {
      const request = original.apply(this, args);
      request.addEventListener("success", () => this.transaction.abort());
      return request;
    };
    try { await wallet.allocateRefund("regtest"); } catch { refused = true; }
    finally { IDBObjectStore.prototype.put = original; wallet.close(); }
    const reopened = await window.walletApi.BrowserRecoveryWallet.open();
    try { return { refused, next: (await reopened.allocateRefund("regtest")).index }; }
    finally { reopened.close(); }
  });
  expect(result).toEqual({ refused: true, next: 0 });
});

test("derivation failure after commit never reuses its consumed index", async ({ page }) => {
  await page.goto(URL); await page.waitForFunction(() => window.walletReady);
  const result = await page.evaluate(async () => {
    const wallet = await window.walletApi.BrowserRecoveryWallet.open();
    const original = Uint8Array.prototype.fill;
    const originalTransaction = IDBDatabase.prototype.transaction;
    let committed = false;
    let refused = false;
    IDBDatabase.prototype.transaction = function(this: IDBDatabase, ...args: Parameters<typeof originalTransaction>) {
      const tx = originalTransaction.apply(this, args);
      if (args[1] === "readwrite") tx.addEventListener("complete", () => { committed = true; });
      return tx;
    };
    Uint8Array.prototype.fill = function(this: Uint8Array, ...args: Parameters<typeof original>) {
      if (committed) throw new Error("fixture derivation failure after commit");
      return original.apply(this, args);
    };
    try { await wallet.allocateRefund("regtest"); } catch { refused = true; }
    finally { Uint8Array.prototype.fill = original; IDBDatabase.prototype.transaction = originalTransaction; }
    try { return { refused, next: (await wallet.allocateRefund("regtest")).index }; }
    finally { wallet.close(); }
  });
  expect(result).toEqual({ refused: true, next: 1 });
});

test("counter exhaustion persists and mismatch verification never resets a counter or flag", async ({ page }) => {
  await page.goto(URL); await page.waitForFunction(() => window.walletReady);
  const result = await page.evaluate(async () => {
    const wallet = await window.walletApi.BrowserRecoveryWallet.open();
    await wallet.verifyBackup(new TextDecoder().decode(await wallet.exportBackup()));
    const db = await new Promise<IDBDatabase>((resolve) => { const req = indexedDB.open(window.walletApi.WALLET_DATABASE, 1); req.onsuccess = () => resolve(req.result); });
    await new Promise<void>((resolve) => {
      const tx = db.transaction("identity", "readwrite"), store = tx.objectStore("identity"), req = store.get("wallet");
      req.onsuccess = () => { store.put({ ...req.result, nextIndex: { ...req.result.nextIndex, mainnet: 2 ** 31 - 1 } }, "wallet"); };
      tx.oncomplete = () => resolve();
    });
    let mismatch = false, exhausted = false;
    try { await wallet.verifyBackup(JSON.stringify({ format: "rillswap-browser-recovery", version: 1, scheme: "bip84-rillswap-v1",
      mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about" })); } catch { mismatch = true; }
    const final = await wallet.allocateRefund("mainnet");
    try { await wallet.allocateRefund("mainnet"); } catch { exhausted = true; }
    const info = await wallet.info(); wallet.close(); db.close();
    return { mismatch, exhausted, final: final.index, verified: info.backupVerified };
  });
  expect(result).toEqual({ mismatch: true, exhausted: true, final: 2 ** 31 - 1, verified: true });
});

test("partial, malformed, and unsupported identities remain byte-for-byte unchanged", async ({ page }) => {
  await page.goto(URL); await page.waitForFunction(() => window.walletReady);
  const result = await page.evaluate(async () => {
    const wallet = await window.walletApi.BrowserRecoveryWallet.open(); wallet.close();
    const db = await new Promise<IDBDatabase>((resolve) => { const req = indexedDB.open(window.walletApi.WALLET_DATABASE, 1); req.onsuccess = () => resolve(req.result); });
    const get = () => new Promise<Record<string, unknown>>((resolve) => { const req = db.transaction("identity").objectStore("identity").get("wallet"); req.onsuccess = () => resolve(req.result); });
    const put = (value: unknown) => new Promise<void>((resolve) => { const tx = db.transaction("identity", "readwrite"); tx.objectStore("identity").put(value, "wallet"); tx.oncomplete = () => resolve(); });
    const valid = await get(), counters = valid.nextIndex as Record<string, number>;
    const malformed = [ { ...valid, nextIndex: { mainnet: 0 } }, { ...valid, mnemonic: "not a mnemonic" },
      { ...valid, nextIndex: { ...counters, regtest: -1 } }, { ...valid, nextIndex: { ...counters, signet: 2 ** 31 + 1 } },
      { ...valid, nextIndex: { ...counters, mainnet: 0.5 } }, { ...valid, scheme: "future" }, { ...valid, backupVerified: "yes" } ];
    let allRefused = true, allPreserved = true;
    for (const value of malformed) {
      await put(value);
      try { const unexpected = await window.walletApi.BrowserRecoveryWallet.open(); unexpected.close(); allRefused = false; } catch { /* expected */ }
      allPreserved &&= JSON.stringify(await get()) === JSON.stringify(value);
    }
    db.close(); return { allRefused, allPreserved };
  });
  expect(result).toEqual({ allRefused: true, allPreserved: true });
});

test("unavailable IndexedDB and a future database version never create a fallback identity", async ({ page }) => {
  await page.goto(URL); await page.waitForFunction(() => window.walletReady);
  const result = await page.evaluate(async () => {
    const wallet = await window.walletApi.BrowserRecoveryWallet.open(); wallet.close();
    const original = indexedDB;
    Object.defineProperty(window, "indexedDB", { configurable: true, get: () => { throw new DOMException("denied", "SecurityError"); } });
    let unavailable = false, future = false;
    try { const unexpected = await window.walletApi.BrowserRecoveryWallet.open(); unexpected.close(); } catch { unavailable = true; }
    finally { Object.defineProperty(window, "indexedDB", { configurable: true, value: original }); }
    const db = await new Promise<IDBDatabase>((resolve) => { const req = indexedDB.open(window.walletApi.WALLET_DATABASE, 2); req.onsuccess = () => resolve(req.result); });
    db.close();
    try { const unexpected = await window.walletApi.BrowserRecoveryWallet.open(); unexpected.close(); } catch { future = true; }
    return { unavailable, future };
  });
  expect(result).toEqual({ unavailable: true, future: true });
});
