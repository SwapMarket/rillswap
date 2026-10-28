import { expect, test, type Page } from "@playwright/test";
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import type { BrowserReverseJournal, ReverseIntentContext, ReverseClaimIntent, ReverseJournalRecord } from "../src/browserReverseJournal";
import type { BoundedHoldPlan } from "../src/swap/browserHoldPayer";
import mainnet from "../src/networks/mainnet.json" with { type: "json" };

declare global { interface Window { BrowserReverseJournal: typeof BrowserReverseJournal; reverseJournalReady: boolean } }
const draft = (): { context: ReverseIntentContext; plan: BoundedHoldPlan; claim: ReverseClaimIntent } =>
  JSON.parse(readFileSync(new URL("../tmp/preview/test-only/reverse-journal-draft.json", import.meta.url), "utf8"));
async function ready(page: Page) { await page.goto("http://127.0.0.1:18765/test-only/reverse-journal.html"); await page.waitForFunction(() => window.reverseJournalReady); }
async function prepare(page: Page, context = draft().context): Promise<ReverseJournalRecord> {
  return page.evaluate(async (context) => {
    const journal = await window.BrowserReverseJournal.open(); const cipher = new TextEncoder().encode("age-encryption.org/v1\n" + "public-test-only-encrypted-placeholder".repeat(4));
    try { const saved = await journal.createFresh(context, cipher); return await journal.saveTerms(saved, cipher); } finally { journal.close(); }
  }, context);
}

test("fresh preparation persists immutable encrypted snapshots without any payment authority", async ({ page }) => {
  await ready(page); const saved = await prepare(page);
  expect(saved.stage).toBe("terms-ready"); expect(saved.payment).toBeNull(); expect(saved.claim).toBeNull(); expect(saved.snapshots).toHaveLength(2);
  await page.reload(); await page.waitForFunction(() => window.reverseJournalReady);
  const restored = await page.evaluate(async (context) => {
    const journal = await window.BrowserReverseJournal.open();
    try { const record = await journal.get(context.networkIdentity, context.sessionId); return { record, frozen: Object.isFrozen(record) && Object.isFrozen(record!.context.request.limits) }; }
    finally { journal.close(); }
  }, saved.context);
  expect(restored.record).toEqual(saved); expect(restored.frozen).toBe(true);
  expect(Object.keys(saved).sort()).toEqual(["claim", "context", "digest", "id", "payment", "snapshots", "stage"]);
});

test("listing saved executions includes prepayment stages without granting payment authority", async ({ page }) => {
  await ready(page);
  const saved = await prepare(page);
  const result = await page.evaluate(async () => {
    const journal = await window.BrowserReverseJournal.open();
    try { return await journal.list(); } finally { journal.close(); }
  });
  expect(result).toEqual([saved]);
  expect(result[0]!.payment).toBeNull(); expect(result[0]!.claim).toBeNull();
});

test("mainnet intent storage requires the pinned identity and grants no payment or claim authority", async ({ page }) => {
  await ready(page);
  const context = { ...draft().context, networkIdentity: mainnet };
  const record = await prepare(page, context);
  expect(record.context.networkIdentity).toEqual(mainnet);
  expect(record.payment).toBeNull(); expect(record.claim).toBeNull();
  const refused = await page.evaluate(async (context) => {
    const journal = await window.BrowserReverseJournal.open();
    try {
      await journal.createFresh({ ...context, networkIdentity: { ...context.networkIdentity, genesis_hash: "00".repeat(32) } }, new Uint8Array(100));
      return false;
    } catch { return true; } finally { journal.close(); }
  }, context);
  expect(refused).toBe(true);
});

test("two tabs and recreated sessions for the same payer/payment hash elect only one irreversible dispatch", async ({ page, context }) => {
  await ready(page); const first = await prepare(page);
  const secondPage = await context.newPage(); await ready(secondPage);
  const second = await prepare(secondPage, { ...draft().context, sessionId: "d".repeat(64) });
  const attempt = (tab: Page, record: ReverseJournalRecord) => tab.evaluate(async ({ record, plan }) => {
    const journal = await window.BrowserReverseJournal.open();
    try { return await journal.beginPayment(record, "http://127.0.0.1:8093", plan, new TextEncoder().encode("age-encryption.org/v1\n" + "public-cipher-placeholder".repeat(4))); }
    catch { return null; } finally { journal.close(); }
  }, { record, plan: draft().plan });
  const outcomes = await Promise.all([attempt(page, first), attempt(secondPage, second)]);
  expect(outcomes.filter(Boolean)).toHaveLength(1);
  const winner = outcomes.find(Boolean)!; expect(winner.stage).toBe("payment-unknown"); expect(winner.payment!.state).toBe("submission-unknown");
  expect(await attempt(page, winner)).toBeNull();
  expect(await attempt(secondPage, outcomes[0] ? second : first)).toBeNull();
});

test("an invoice shown for an external wallet is one UNKNOWN payment per hash, restored as such, and funds like a dispatched route", async ({ page, context }) => {
  await ready(page); const first = await prepare(page);
  const secondPage = await context.newPage(); await ready(secondPage);
  const second = await prepare(secondPage, { ...draft().context, sessionId: "d".repeat(64) });
  const expose = (tab: Page, record: ReverseJournalRecord) => tab.evaluate(async ({ record, binding }) => {
    const journal = await window.BrowserReverseJournal.open();
    try { return await journal.exposeInvoice(record, binding, new TextEncoder().encode("age-encryption.org/v1\n" + "public-cipher-placeholder".repeat(4))); }
    catch { return null; } finally { journal.close(); }
  }, { record, binding: draft().plan.invoiceBinding });
  const outcomes = await Promise.all([expose(page, first), expose(secondPage, second)]);
  expect(outcomes.filter(Boolean)).toHaveLength(1);
  const winner = outcomes.find(Boolean)!; expect(winner.stage).toBe("payment-unknown");
  expect(winner.payment).toEqual({ state: "external-wallet", paymentHash: draft().context.request.payment_hash, invoiceBinding: draft().plan.invoiceBinding });
  // A node dispatch for the same hash is a different payer and is not blocked by storage; the execution object refuses it instead.
  await page.reload(); await page.waitForFunction(() => window.reverseJournalReady);
  const restored = await page.evaluate(async ({ context, cipher }) => {
    const journal = await window.BrowserReverseJournal.open();
    try { const record = (await journal.get(context.networkIdentity, context.sessionId))!; return await journal.saveFunding(record, new TextEncoder().encode(cipher)); }
    finally { journal.close(); }
  }, { context: winner.context, cipher: "age-encryption.org/v1\n" + "public-cipher-placeholder".repeat(4) });
  expect(restored.stage).toBe("funded"); expect(restored.payment).toEqual(winner.payment);
  const wrongHash = await page.evaluate(async ({ record, binding }) => {
    const journal = await window.BrowserReverseJournal.open();
    try { await journal.exposeInvoice(record, { ...binding, payment_hash: "e".repeat(64) }, new TextEncoder().encode("age-encryption.org/v1\n" + "public-cipher-placeholder".repeat(4))); return false; }
    catch { return true; } finally { journal.close(); }
  }, { record: outcomes[0] ? second : first, binding: draft().plan.invoiceBinding });
  expect(wrongHash).toBe(true);
});

test("the shown invoice text is kept only when it hashes to the signed binding, and survives a reload", async ({ page }) => {
  await ready(page); const record = await prepare(page);
  const invoice = "lnbcrt511u1journalinvoicefixture", hash = (text: string) => createHash("sha256").update(text).digest("hex");
  const expose = (bolt11: string, bolt11Sha256: string) => page.evaluate(async ({ record, binding, bolt11 }) => {
    const journal = await window.BrowserReverseJournal.open();
    try { return await journal.exposeInvoice(record, binding, new TextEncoder().encode("age-encryption.org/v1\n" + "public-cipher-placeholder".repeat(4)), bolt11); }
    catch { return null; } finally { journal.close(); }
  }, { record, binding: { ...draft().plan.invoiceBinding, bolt11_sha256: bolt11Sha256 }, bolt11 });
  // Each refused text hashes to its binding, so only the format rule refuses it.
  const long = "ln" + "q".repeat(2047), upper = invoice.toUpperCase();
  for (const [text, bound] of [[invoice + "x", hash(invoice)], [upper, hash(upper)], [long, hash(long)], ["", hash("")]] as const) {
    expect(await expose(text, bound)).toBeNull();
  }
  const shown = await expose(invoice, hash(invoice));
  expect(shown!.stage).toBe("payment-unknown");
  expect(shown!.payment).toEqual({ state: "external-wallet", paymentHash: draft().context.request.payment_hash,
    invoiceBinding: { ...draft().plan.invoiceBinding, bolt11_sha256: hash(invoice) }, bolt11: invoice });
  await page.reload(); await page.waitForFunction(() => window.reverseJournalReady);
  const restored = await page.evaluate(async (context) => {
    const journal = await window.BrowserReverseJournal.open();
    try { return { record: await journal.get(context.networkIdentity, context.sessionId), list: await journal.list() }; } finally { journal.close(); }
  }, shown!.context);
  expect(restored.record).toEqual(shown); expect(restored.list).toEqual([shown]);
});

test("funding preserves UNKNOWN and precedes the immutable fallback, whose exposure has one winner", async ({ page, context }) => {
  await ready(page); const prepared = await prepare(page);
  const claimReady = await page.evaluate(async ({ prepared, draft }) => {
    const journal = await window.BrowserReverseJournal.open(), cipher = new TextEncoder().encode("age-encryption.org/v1\n" + "public-cipher-placeholder".repeat(4));
    try {
      const unknown = await journal.beginPayment(prepared, "http://127.0.0.1:8093", draft.plan, cipher);
      const funded = await journal.saveFunding(unknown, cipher);
      return { funded, ready: await journal.prepareClaim(funded, draft.claim, cipher) };
    } finally { journal.close(); }
  }, { prepared, draft: draft() });
  expect(claimReady.funded.stage).toBe("funded"); expect(claimReady.funded.claim).toBeNull();
  expect(claimReady.ready.snapshots.slice(0, 4)).toEqual(claimReady.funded.snapshots); expect(claimReady.ready.payment).toEqual(claimReady.funded.payment);
  const second = await context.newPage(); await ready(second);
  const expose = (tab: Page) => tab.evaluate(async (record) => {
    const journal = await window.BrowserReverseJournal.open();
    try { return await journal.beginClaimExposure(record); } catch { return null; } finally { journal.close(); }
  }, claimReady.ready);
  const outcomes = await Promise.all([expose(page), expose(second)]); expect(outcomes.filter(Boolean)).toHaveLength(1);
  const winner = outcomes.find(Boolean)!; expect(winner.stage).toBe("claim-unknown");
  const restored = await page.evaluate(async (record) => {
    const journal = await window.BrowserReverseJournal.open();
    try { let replay = false; try { await journal.beginClaimExposure(record); replay = true; } catch {}
      const exported = await journal.reexportIdentical(record), accepted = await journal.markAccepted(record, record.claim!.txid);
      return { replay, exported, accepted, afterAcceptance: await journal.reexportIdentical(accepted) };
    } finally { journal.close(); }
  }, winner);
  expect(restored.replay).toBe(false); expect(restored.exported.snapshots).toEqual(claimReady.ready.snapshots);
  expect(restored.accepted.stage).toBe("accepted"); expect(restored.afterAcceptance.snapshots).toEqual(claimReady.ready.snapshots);
});

test("durable payment commitment with interrupted readback remains UNKNOWN and cannot be reauthorized", async ({ page }) => {
  await ready(page); const prepared = await prepare(page);
  const result = await page.evaluate(async ({ prepared, plan }) => {
    const journal = await window.BrowserReverseJournal.open(), original = journal.get.bind(journal);
    journal.get = async () => { throw new Error("interrupted readback"); }; let refused = false;
    try { await journal.beginPayment(prepared, "http://127.0.0.1:8093", plan, new TextEncoder().encode("age-encryption.org/v1\n" + "public-cipher-placeholder".repeat(4))); } catch { refused = true; }
    journal.get = original;
    try { const stored = (await journal.get(prepared.context.networkIdentity, prepared.context.sessionId))!; let replay = false;
      try { await journal.beginPayment(stored, "http://127.0.0.1:8093", plan, new TextEncoder().encode("age-encryption.org/v1\n" + "public-cipher-placeholder".repeat(4))); replay = true; } catch {}
      return { refused, stored, replay };
    } finally { journal.close(); }
  }, { prepared, plan: draft().plan });
  expect(result.refused).toBe(true); expect(result.stored.stage).toBe("payment-unknown"); expect(result.replay).toBe(false);
});

test("failed strict durability or payment-marker write does not authorize dispatch or partially advance the session", async ({ page }) => {
  await ready(page); const prepared = await prepare(page);
  const result = await page.evaluate(async ({ prepared, plan }) => {
    const journal = await window.BrowserReverseJournal.open(), original = IDBObjectStore.prototype.add; let refused = false;
    const transaction = IDBDatabase.prototype.transaction;
    let strictRefused = false;
    IDBDatabase.prototype.transaction = function (...args: Parameters<IDBDatabase["transaction"]>) {
      const tx = transaction.apply(this, args); if (args[1] === "readwrite") Object.defineProperty(tx, "durability", { value: "relaxed" }); return tx;
    };
    try { await journal.beginPayment(prepared, "http://127.0.0.1:8093", plan, new TextEncoder().encode("age-encryption.org/v1\n" + "public-cipher-placeholder".repeat(4))); } catch { strictRefused = true; }
    finally { IDBDatabase.prototype.transaction = transaction; }
    IDBObjectStore.prototype.add = function (...args: Parameters<IDBObjectStore["add"]>) {
      if (this.name === "payments") throw new DOMException("quota", "QuotaExceededError"); return original.apply(this, args);
    };
    try { await journal.beginPayment(prepared, "http://127.0.0.1:8093", plan, new TextEncoder().encode("age-encryption.org/v1\n" + "public-cipher-placeholder".repeat(4))); } catch { refused = true; }
    finally { IDBObjectStore.prototype.add = original; }
    try { return { refused, strictRefused, stored: await journal.get(prepared.context.networkIdentity, prepared.context.sessionId) }; } finally { journal.close(); }
  }, { prepared, plan: draft().plan });
  expect(result.refused).toBe(true); expect(result.strictRefused).toBe(true); expect(result.stored).toEqual(prepared);
});

test("missing or corrupted election records remain preserved and block instead of treating absence as fresh authority", async ({ page }) => {
  await ready(page); const prepared = await prepare(page);
  const result = await page.evaluate(async ({ prepared, plan }) => {
    const journal = await window.BrowserReverseJournal.open();
    const saved = await journal.beginPayment(prepared, "http://127.0.0.1:8093", plan, new TextEncoder().encode("age-encryption.org/v1\n" + "public-cipher-placeholder".repeat(4)));
    const raw = await new Promise<IDBDatabase>((resolve) => { const request = indexedDB.open("rillswap-reverse-execution"); request.onsuccess = () => resolve(request.result); });
    const ticket = await new Promise<{ id: string }>((resolve) => { const request = raw.transaction("payments").objectStore("payments").getAll(); request.onsuccess = () => resolve(request.result[0]); });
    await new Promise<void>((resolve) => { const tx = raw.transaction("payments", "readwrite"); tx.objectStore("payments").put({ id: ticket.id }); tx.oncomplete = () => resolve(); });
    let blocked = false; try { await journal.get(saved.context.networkIdentity, saved.context.sessionId); } catch { blocked = true; }
    const preserved = await new Promise<unknown>((resolve) => { const request = raw.transaction("payments").objectStore("payments").get(ticket.id); request.onsuccess = () => resolve(request.result); });
    await new Promise<void>((resolve) => { const tx = raw.transaction("payments", "readwrite"); tx.objectStore("payments").delete(ticket.id); tx.oncomplete = () => resolve(); });
    let missingBlocked = false; try { await journal.get(saved.context.networkIdentity, saved.context.sessionId); } catch { missingBlocked = true; }
    raw.close(); journal.close(); return { blocked, missingBlocked, preserved, expected: { id: ticket.id } };
  }, { prepared, plan: draft().plan });
  expect(result.blocked).toBe(true); expect(result.missingBlocked).toBe(true); expect(result.preserved).toEqual(result.expected);
});

test("failed session write after queued payment election aborts both records", async ({ page }) => {
  await ready(page); const prepared = await prepare(page);
  const result = await page.evaluate(async ({ prepared, plan }) => {
    const journal = await window.BrowserReverseJournal.open(), original = IDBObjectStore.prototype.put; let refused = false;
    IDBObjectStore.prototype.put = function (...args: Parameters<IDBObjectStore["put"]>) {
      if (this.name === "sessions") throw new DOMException("quota", "QuotaExceededError"); return original.apply(this, args);
    };
    try { await journal.beginPayment(prepared, "http://127.0.0.1:8093", plan, new TextEncoder().encode("age-encryption.org/v1\n" + "public-cipher-placeholder".repeat(4))); } catch { refused = true; }
    finally { IDBObjectStore.prototype.put = original; }
    const raw = await new Promise<IDBDatabase>((resolve) => { const request = indexedDB.open("rillswap-reverse-execution"); request.onsuccess = () => resolve(request.result); });
    const count = await new Promise<number>((resolve) => { const request = raw.transaction("payments").objectStore("payments").count(); request.onsuccess = () => resolve(request.result); }); raw.close();
    try { return { refused, count, stored: await journal.get(prepared.context.networkIdentity, prepared.context.sessionId) }; } finally { journal.close(); }
  }, { prepared, plan: draft().plan });
  expect(result.refused).toBe(true); expect(result.count).toBe(0); expect(result.stored).toEqual(prepared);
});

test("incompatible store shapes are refused and preserved, never repaired on open", async ({ page }) => {
  await ready(page);
  for (const shape of ["missing", "extra", "keypath", "index"]) {
    const result = await page.evaluate(async (shape) => {
      await new Promise<void>((resolve) => { const request = indexedDB.deleteDatabase("rillswap-reverse-execution"); request.onsuccess = () => resolve(); });
      const raw = await new Promise<IDBDatabase>((resolve) => { const request = indexedDB.open("rillswap-reverse-execution"); request.onupgradeneeded = () => {
        for (const name of shape === "missing" ? ["sessions"] : ["sessions", "payments", "claims"]) {
          const store = request.result.createObjectStore(name, { keyPath: shape === "keypath" ? "wrong" : "id" }); if (shape === "index") store.createIndex("unexpected", "stage");
        }
        if (shape === "extra") request.result.createObjectStore("unexpected");
      }; request.onsuccess = () => resolve(request.result); });
      const before = Array.from(raw.objectStoreNames); raw.close(); let refused = false;
      try { (await window.BrowserReverseJournal.open()).close(); } catch { refused = true; }
      const check = await new Promise<IDBDatabase>((resolve) => { const request = indexedDB.open("rillswap-reverse-execution"); request.onsuccess = () => resolve(request.result); });
      const after = Array.from(check.objectStoreNames); check.close(); return { refused, before, after };
    }, shape);
    expect(result.refused, shape).toBe(true); expect(result.after).toEqual(result.before);
  }
});

test("captured contexts/ciphertext survive caller mutation and damaged snapshots block unchanged", async ({ page }) => {
  await ready(page);
  const result = await page.evaluate(async (context) => {
    const journal = await window.BrowserReverseJournal.open(), cipher = new TextEncoder().encode("age-encryption.org/v1\n" + "public-cipher-placeholder".repeat(4));
    const originalCipher = Array.from(cipher), pending = journal.createFresh(context, cipher);
    (context as { deadlineAt: number }).deadlineAt = 1; cipher.fill(0);
    const saved = await pending; journal.close();
    const corrupt = { ...saved, snapshots: [{ ...saved.snapshots[0], digest: "0".repeat(64) }] };
    const raw = await new Promise<IDBDatabase>((resolve) => { const request = indexedDB.open("rillswap-reverse-execution"); request.onsuccess = () => resolve(request.result); });
    await new Promise<void>((resolve) => { const tx = raw.transaction("sessions", "readwrite"); tx.objectStore("sessions").put(corrupt); tx.oncomplete = () => resolve(); });
    const reader = await window.BrowserReverseJournal.open(); let refused = false;
    try { await reader.get(saved.context.networkIdentity, saved.context.sessionId); } catch { refused = true; } finally { reader.close(); }
    const after = await new Promise<unknown>((resolve) => { const request = raw.transaction("sessions").objectStore("sessions").get(saved.id); request.onsuccess = () => resolve(request.result); }); raw.close();
    return { saved, originalCipher, refused, corrupt, after };
  }, draft().context);
  expect(result.saved.context.deadlineAt).toBe(draft().context.deadlineAt);
  expect(result.saved.snapshots[0]!.ciphertextHex).toBe(Buffer.from(result.originalCipher).toString("hex"));
  expect(result.refused).toBe(true); expect(result.after).toEqual(result.corrupt);
});

test("a full-network/outpoint claim election cannot be replaced by another session or fee plan", async ({ page }) => {
  await ready(page); const first = await prepare(page);
  const secondContext = structuredClone(draft().context) as { request: { payment_hash: string }; sessionId: string } & ReverseIntentContext;
  secondContext.sessionId = "e".repeat(64); secondContext.request.payment_hash = "f".repeat(64);
  const second = await prepare(page, secondContext);
  const result = await page.evaluate(async ({ first, second, draft }) => {
    const journal = await window.BrowserReverseJournal.open(), cipher = new TextEncoder().encode("age-encryption.org/v1\n" + "public-cipher-placeholder".repeat(4));
    try {
      const fundedFirst = await journal.saveFunding(await journal.beginPayment(first, "http://127.0.0.1:8093", draft.plan, cipher), cipher);
      const otherPlan = { ...draft.plan, paymentHash: second.context.request.payment_hash, invoiceBinding: { ...draft.plan.invoiceBinding, payment_hash: second.context.request.payment_hash } };
      const fundedSecond = await journal.saveFunding(await journal.beginPayment(second, "http://127.0.0.1:8093", otherPlan, cipher), cipher);
      const saved = await journal.prepareClaim(fundedFirst, draft.claim, cipher); let replaced = false;
      try { await journal.prepareClaim(fundedSecond, { ...draft.claim, txid: "d".repeat(64), signedDigest: "e".repeat(64) }, cipher); replaced = true; } catch {}
      return { replaced, saved, restored: await journal.get(saved.context.networkIdentity, saved.context.sessionId) };
    } finally { journal.close(); }
  }, { first, second, draft: draft() });
  expect(result.replaced).toBe(false); expect(result.restored).toEqual(result.saved);
});

test("claim exposure or acceptance readback interruption never grants another exposure transition", async ({ page }) => {
  await ready(page); const prepared = await prepare(page);
  const result = await page.evaluate(async ({ prepared, draft }) => {
    const journal = await window.BrowserReverseJournal.open(), cipher = new TextEncoder().encode("age-encryption.org/v1\n" + "public-cipher-placeholder".repeat(4));
    try {
      const funded = await journal.saveFunding(await journal.beginPayment(prepared, "http://127.0.0.1:8093", draft.plan, cipher), cipher);
      const ready = await journal.prepareClaim(funded, draft.claim, cipher), original = journal.get.bind(journal);
      journal.get = async () => { throw new Error("interrupted readback"); }; let exposureFailed = false;
      try { await journal.beginClaimExposure(ready); } catch { exposureFailed = true; }
      journal.get = original; const unknown = (await journal.get(ready.context.networkIdentity, ready.context.sessionId))!;
      journal.get = async () => { throw new Error("interrupted acceptance readback"); }; let acceptFailed = false;
      try { await journal.markAccepted(unknown, unknown.claim!.txid); } catch { acceptFailed = true; }
      journal.get = original; const accepted = (await journal.get(ready.context.networkIdentity, ready.context.sessionId))!; let replay = false;
      try { await journal.beginClaimExposure(accepted); replay = true; } catch {}
      return { exposureFailed, unknown, acceptFailed, accepted, replay, exported: await journal.reexportIdentical(accepted) };
    } finally { journal.close(); }
  }, { prepared, draft: draft() });
  expect(result.exposureFailed).toBe(true); expect(result.unknown.stage).toBe("claim-unknown"); expect(result.acceptFailed).toBe(true);
  expect(result.accepted.stage).toBe("accepted"); expect(result.replay).toBe(false); expect(result.exported.snapshots).toEqual(result.accepted.snapshots);
});

for (const damage of ["missing", "corrupt"]) {
  for (const transition of ["funding", "claim"]) {
    test(`damaged predecessor election blocks ${transition} without mutation: ${damage}`, async ({ page }) => {
      await ready(page); const prepared = await prepare(page);
      const result = await page.evaluate(async ({ prepared, draft, damage, transition }) => {
        const journal = await window.BrowserReverseJournal.open(), cipher = new TextEncoder().encode("age-encryption.org/v1\n" + "public-cipher-placeholder".repeat(4));
        const paid = await journal.beginPayment(prepared, "http://127.0.0.1:8093", draft.plan, cipher);
        const predecessor = transition === "claim" ? await journal.saveFunding(paid, cipher) : paid;
        const raw = await new Promise<IDBDatabase>((resolve) => { const request = indexedDB.open("rillswap-reverse-execution"); request.onsuccess = () => resolve(request.result); });
        const ticket = await new Promise<{ id: string }>((resolve) => { const request = raw.transaction("payments").objectStore("payments").getAll(); request.onsuccess = () => resolve(request.result[0]); });
        await new Promise<void>((resolve) => { const tx = raw.transaction("payments", "readwrite");
          if (damage === "missing") tx.objectStore("payments").delete(ticket.id); else tx.objectStore("payments").put({ id: ticket.id }); tx.oncomplete = () => resolve(); });
        let refused = false;
        try { if (transition === "funding") await journal.saveFunding(predecessor, cipher); else await journal.prepareClaim(predecessor, draft.claim, cipher); } catch { refused = true; }
        const state = await new Promise<{ session: unknown; payment: unknown; claims: number }>((resolve) => {
          const tx = raw.transaction(["sessions", "payments", "claims"]), session = tx.objectStore("sessions").get(predecessor.id),
            payment = tx.objectStore("payments").get(ticket.id), claims = tx.objectStore("claims").count();
          tx.oncomplete = () => resolve({ session: session.result, payment: payment.result, claims: claims.result });
        });
        raw.close(); journal.close(); return { refused, state, predecessor, damaged: damage === "missing" ? undefined : { id: ticket.id } };
      }, { prepared, draft: draft(), damage, transition });
      expect(result.refused).toBe(true); expect(result.state.session).toEqual(result.predecessor);
      expect(result.state.claims).toBe(0); expect(result.state.payment).toEqual(result.damaged);
    });
  }
}
