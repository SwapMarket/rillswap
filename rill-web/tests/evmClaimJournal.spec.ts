import { test, expect, type Page } from "@playwright/test";
import type { EvmClaimJournal } from "../src/evmClaimJournal";
declare global { interface Window { EvmClaimJournal: typeof EvmClaimJournal; evmJournalReady: boolean } }
async function ready(page: Page): Promise<void> {
  await page.goto("http://127.0.0.1:18765/test-only/evm-journal.html"); await page.waitForFunction(() => window.evmJournalReady);
}
test("encrypted recovery commits survive reload; exposure is atomic across tabs and never reset by a stale file", async ({ page, context }) => {
  await ready(page);
  await page.evaluate(async () => { const journal = new window.EvmClaimJournal(); await journal.create("contract", new Uint8Array([1, 2])); });
  const other = await context.newPage(); await ready(other);
  const expose = (tab: Page) => tab.evaluate(async () => {
    try { await new window.EvmClaimJournal().expose("contract"); return true; } catch { return false; }
  });
  expect((await Promise.all([expose(page), expose(other)])).filter(Boolean)).toHaveLength(1);
  await page.reload(); await page.waitForFunction(() => window.evmJournalReady);
  const result = await page.evaluate(async () => {
    const journal = new window.EvmClaimJournal(); await journal.save("contract", new Uint8Array([3]));
    let duplicate = false; try { await journal.create("contract", new Uint8Array([4])); duplicate = true; } catch {}
    const entry = await journal.read("contract");
    return { exposure: entry!.exposure, ciphertext: Array.from(entry!.ciphertext), duplicate };
  });
  expect(result).toEqual({ exposure: "unknown", ciphertext: [3], duplicate: false });
  expect(await expose(page)).toBe(false);
});
test("absent journal state and an aborted strict commit cannot authorize exposure", async ({ page }) => {
  await ready(page);
  const result = await page.evaluate(async () => {
    const journal = new window.EvmClaimJournal();
    let missing = false; try { await journal.expose("missing"); missing = true; } catch {}
    const original = IDBObjectStore.prototype.put;
    IDBObjectStore.prototype.put = function (...args: Parameters<IDBObjectStore["put"]>) {
      const request = original.apply(this, args); this.transaction.abort(); return request;
    };
    let committed = false;
    try { await journal.create("aborted", new Uint8Array([1])); committed = true; } catch {}
    finally { IDBObjectStore.prototype.put = original; }
    return { missing, committed, entry: await journal.read("aborted") };
  });
  expect(result).toEqual({ missing: false, committed: false, entry: null });
});
