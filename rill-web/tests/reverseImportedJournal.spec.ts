import { expect, test, type Page } from "@playwright/test";
import { readFileSync } from "node:fs";
import type { BrowserReverseJournal, ImportedClaimDraft, ImportedClaimRecord, ReverseJournalRecord, ReverseIntentContext, ReverseClaimIntent } from "../src/browserReverseJournal";
import type { BoundedHoldPlan } from "../src/swap/browserHoldPayer";
declare global { interface Window { BrowserReverseJournal: typeof BrowserReverseJournal; reverseJournalReady: boolean } }
const fixture = (): { context: ReverseIntentContext; plan: BoundedHoldPlan; claim: ReverseClaimIntent } => JSON.parse(readFileSync(new URL("../tmp/preview/test-only/reverse-journal-draft.json", import.meta.url), "utf8"));
const draft = (): ImportedClaimDraft => ({ networkIdentity: fixture().context.networkIdentity, fundingTxid: fixture().claim.fundingTxid, fundingVout: fixture().claim.fundingVout,
  bindingHash: "a".repeat(64), fundedPlaintextDigest: "b".repeat(64), feeSat: "100" });
const ready = async (page: Page) => { await page.goto("http://127.0.0.1:18765/test-only/reverse-journal.html"); await page.waitForFunction(() => window.reverseJournalReady); };
const reserve = (page: Page, value = draft()) => page.evaluate(async (draft) => {
  const j = await window.BrowserReverseJournal.open(); try { return await j.reserveImportedClaim(draft, new TextEncoder().encode("age-encryption.org/v1\n" + "public-fake-funded-cipher".repeat(4))); } finally { j.close(); }
}, value);

test("explicit funded import stores a claim-only predecessor and no payment authority, with resumable reservation", async ({ page }) => {
  await ready(page);
  const empty = await page.evaluate(async () => { const j = await window.BrowserReverseJournal.open(); j.close(); const db = await new Promise<IDBDatabase>((resolve) => { const r = indexedDB.open("rillswap-reverse-execution"); r.onsuccess = () => resolve(r.result); });
    const counts = await Promise.all(["sessions", "payments", "claims"].map((name) => new Promise<number>((resolve) => { const r = db.transaction(name).objectStore(name).count(); r.onsuccess = () => resolve(r.result); }))); db.close(); return counts; });
  expect(empty).toEqual([0, 0, 0]);
  const saved = await reserve(page); expect(saved.priorExposure).toBe("unknown"); expect(saved.stage).toBe("recovery-reserved"); expect(saved).not.toHaveProperty("payment"); expect(saved.claim).toBeNull();
  await page.reload(); await page.waitForFunction(() => window.reverseJournalReady);
  expect(await reserve(page)).toEqual(saved); const changed = { ...draft(), feeSat: "101" }; await expect(reserve(page, changed)).rejects.toThrow();
});

test("competing private candidates select one exact fallback and one exposure winner across tabs", async ({ page, context }) => {
  await ready(page); const saved = await reserve(page), other = await context.newPage(); await ready(other);
  const select = (tab: Page, txid: string) => tab.evaluate(async ({ saved, claim, txid }) => { const j = await window.BrowserReverseJournal.open();
    try { return await j.saveImportedClaim(saved, { ...claim, txid }, new TextEncoder().encode("age-encryption.org/v1\n" + txid.repeat(2)), false); } catch { return null; } finally { j.close(); }
  }, { saved, claim: fixture().claim, txid });
  const selected = await Promise.all([select(page, "a".repeat(64)), select(other, "c".repeat(64))]); expect(selected.filter(Boolean)).toHaveLength(1);
  const winner = selected.find(Boolean)!; expect(winner.funded).toEqual(saved.funded); expect(winner.fallback).not.toBeNull();
  const expose = (tab: Page) => tab.evaluate(async (record) => { const j = await window.BrowserReverseJournal.open(); try { return await j.exposeImportedClaim(record); } catch { return null; } finally { j.close(); } }, winner);
  const outcomes = await Promise.all([expose(page), expose(other)]); expect(outcomes.filter(Boolean)).toHaveLength(1);
  const unknown = outcomes.find(Boolean)!;
  expect(await page.evaluate(async (r) => { const j = await window.BrowserReverseJournal.open(); try { return await j.reexportImportedClaim(r); } finally { j.close(); } }, unknown)).toEqual(unknown);
  expect(await expose(page)).toBeNull();
});

test("fresh execution and imported recovery contend on the same network/outpoint election", async ({ page, context }) => {
  await ready(page); const data = fixture();
  const funded = await page.evaluate(async ({ context, plan }) => { const j = await window.BrowserReverseJournal.open(), cipher = new TextEncoder().encode("age-encryption.org/v1\n" + "public-fake-cipher".repeat(6));
    try { return await j.saveFunding(await j.beginPayment(await j.saveTerms(await j.createFresh(context, cipher), cipher), "http://127.0.0.1:8093", plan, cipher), cipher); } finally { j.close(); }
  }, data);
  const other = await context.newPage(); await ready(other);
  const fresh = page.evaluate(async ({ funded, claim }) => { const j = await window.BrowserReverseJournal.open(); try { return await j.prepareClaim(funded, claim, new TextEncoder().encode("age-encryption.org/v1\n" + "claim-cipher".repeat(8))); } catch { return null; } finally { j.close(); } }, { funded, claim: data.claim });
  const imported = reserve(other).catch(() => null); const winners = await Promise.all([fresh, imported]); expect(winners.filter(Boolean)).toHaveLength(1);
});

for (const transition of ["reservation", "fallback", "exposure"]) {
  test(`committed ${transition} with rejected readback retains state and prevents another selected exposure`, async ({ page }) => {
    await ready(page);
    const result = await page.evaluate(async ({ draft, claim, transition }) => {
      const j = await window.BrowserReverseJournal.open(), cipher = new TextEncoder().encode("age-encryption.org/v1\n" + "public-fake-cipher".repeat(6));
      let reserved: ImportedClaimRecord | undefined, ready: ImportedClaimRecord | undefined;
      if (transition !== "reservation") reserved = await j.reserveImportedClaim(draft, cipher);
      if (transition === "exposure") ready = await j.saveImportedClaim(reserved!, claim, cipher, false);
      const lookup = j.claimOwner.bind(j); let reads = 0;
      j.claimOwner = async (...args) => { reads++; if (reads === (transition === "reservation" ? 2 : 1)) throw new Error("committed readback unavailable"); return lookup(...args); };
      let refused = false;
      try { if (transition === "reservation") await j.reserveImportedClaim(draft, cipher); else if (transition === "fallback") await j.saveImportedClaim(reserved!, claim, cipher, false); else await j.exposeImportedClaim(ready!); } catch { refused = true; }
      j.claimOwner = lookup;
      const retained = await j.claimOwner(draft.networkIdentity, draft.fundingTxid, draft.fundingVout) as ImportedClaimRecord;
      let replay = false;
      if (transition === "reservation") { const resumed = await j.reserveImportedClaim(draft, cipher); replay = resumed.digest === retained.digest; }
      else try { if (transition === "fallback") await j.saveImportedClaim(reserved!, claim, cipher, false); else await j.exposeImportedClaim(ready!); replay = true; } catch {}
      j.close(); return { refused, retained, replay };
    }, { draft: draft(), claim: fixture().claim, transition });
    expect(result.refused).toBe(true); expect(result.retained.stage).toBe(transition === "reservation" ? "recovery-reserved" : transition === "fallback" ? "claim-ready" : "claim-unknown");
    expect(result.replay).toBe(transition === "reservation");
  });
}

for (const damage of ["missing marker", "corrupt marker", "missing owner", "corrupt owner"]) {
  test(`existing imported ${damage} is preserved and cannot be replaced`, async ({ page }) => {
    await ready(page); const saved = await reserve(page);
    const result = await page.evaluate(async ({ saved, damage }) => {
      const db = await new Promise<IDBDatabase>((resolve) => { const r = indexedDB.open("rillswap-reverse-execution"); r.onsuccess = () => resolve(r.result); });
      const markers = await new Promise<{ id: string }[]>((resolve) => { const r = db.transaction("claims").objectStore("claims").getAll(); r.onsuccess = () => resolve(r.result); });
      const target = damage.includes("marker") ? "claims" : "sessions", id = target === "claims" ? markers[0]!.id : saved.id;
      await new Promise<void>((resolve) => { const tx = db.transaction(target, "readwrite"); if (damage.startsWith("missing")) tx.objectStore(target).delete(id); else tx.objectStore(target).put({ id }); tx.oncomplete = () => resolve(); });
      const before = await new Promise<unknown[]>((resolve) => { const tx = db.transaction(["sessions", "claims"]), a = tx.objectStore("sessions").getAll(), b = tx.objectStore("claims").getAll(); tx.oncomplete = () => resolve([a.result, b.result]); });
      const j = await window.BrowserReverseJournal.open(); let refused = false;
      try { await j.reserveImportedClaim(saved.draft, new TextEncoder().encode("age-encryption.org/v1\n" + "other-valid-header-cipher".repeat(4))); } catch { refused = true; } j.close();
      const after = await new Promise<unknown[]>((resolve) => { const tx = db.transaction(["sessions", "claims"]), a = tx.objectStore("sessions").getAll(), b = tx.objectStore("claims").getAll(); tx.oncomplete = () => resolve([a.result, b.result]); }); db.close(); return { refused, before, after };
    }, { saved, damage }); expect(result.refused).toBe(true); expect(result.after).toEqual(result.before);
  });
}

test("retained fresh UNKNOWN owner with missing election cannot be bypassed by claim-only import", async ({ page }) => {
  await ready(page); const data = fixture();
  await page.evaluate(async ({ context, plan, claim }) => { const j = await window.BrowserReverseJournal.open(), cipher = new TextEncoder().encode("age-encryption.org/v1\n" + "public-fake-cipher".repeat(6));
    const funded = await j.saveFunding(await j.beginPayment(await j.saveTerms(await j.createFresh(context, cipher), cipher), "http://127.0.0.1:8093", plan, cipher), cipher);
    await j.beginClaimExposure(await j.prepareClaim(funded, claim, cipher)); j.close();
    const db = await new Promise<IDBDatabase>((resolve) => { const r = indexedDB.open("rillswap-reverse-execution"); r.onsuccess = () => resolve(r.result); });
    await new Promise<void>((resolve) => { const tx = db.transaction("claims", "readwrite"); tx.objectStore("claims").clear(); tx.oncomplete = () => resolve(); }); db.close();
  }, data);
  await expect(reserve(page)).rejects.toThrow();
});

test("imported writes refuse unavailable strict durability without creating authority", async ({ page }) => {
  await ready(page);
  const result = await page.evaluate(async (draft) => {
    const j = await window.BrowserReverseJournal.open(), original = IDBDatabase.prototype.transaction;
    IDBDatabase.prototype.transaction = function(...args: Parameters<IDBDatabase["transaction"]>) { const tx = original.apply(this, args);
      if (args[1] === "readwrite") Object.defineProperty(tx, "durability", { value: "relaxed" }); return tx; };
    let refused = false; try { await j.reserveImportedClaim(draft, new TextEncoder().encode("age-encryption.org/v1\n" + "valid-header-placeholder".repeat(4))); } catch { refused = true; }
    finally { IDBDatabase.prototype.transaction = original; }
    const owner = await j.claimOwner(draft.networkIdentity, draft.fundingTxid, draft.fundingVout); j.close(); return { refused, owner };
  }, draft()); expect(result.refused).toBe(true); expect(result.owner).toBeUndefined();
});
for (const transition of ["reservation", "fallback", "exposure"]) {
  test(`claim marker failure after queued ${transition} session write rolls back atomically`, async ({ page }) => {
    await ready(page);
    const result = await page.evaluate(async ({ draft, claim, transition }) => {
      const j = await window.BrowserReverseJournal.open(), cipher = new TextEncoder().encode("age-encryption.org/v1\n" + "valid-header-placeholder".repeat(4));
      let prior: ImportedClaimRecord | undefined;
      if (transition !== "reservation") prior = await j.reserveImportedClaim(draft, cipher);
      if (transition === "exposure") prior = await j.saveImportedClaim(prior!, claim, cipher, false);
      const add = IDBObjectStore.prototype.add, put = IDBObjectStore.prototype.put;
      IDBObjectStore.prototype.add = function(...args) { if (this.name === "claims") throw new DOMException("quota", "QuotaExceededError"); return add.apply(this, args); };
      IDBObjectStore.prototype.put = function(...args) { if (this.name === "claims") throw new DOMException("quota", "QuotaExceededError"); return put.apply(this, args); };
      let refused = false;
      try { if (transition === "reservation") await j.reserveImportedClaim(draft, cipher); else if (transition === "fallback") await j.saveImportedClaim(prior!, claim, cipher, false); else await j.exposeImportedClaim(prior!); } catch { refused = true; }
      finally { IDBObjectStore.prototype.add = add; IDBObjectStore.prototype.put = put; }
      const after = await j.claimOwner(draft.networkIdentity, draft.fundingTxid, draft.fundingVout); j.close(); return { refused, prior, after };
    }, { draft: draft(), claim: fixture().claim, transition }); expect(result.refused).toBe(true); expect(result.after).toEqual(result.prior);
  });
}
