import { expect, test, type Page } from "@playwright/test";
import { readFileSync } from "node:fs";
import canonicalize from "canonicalize";
import type * as RefundActions from "../src/browserRefund";
import type { RecoveryRefundCase } from "../unit/fixtures/recoveryRefundCases";

declare global { interface Window { refundActions: typeof RefundActions } }
const vector = (): RecoveryRefundCase => JSON.parse(readFileSync(new URL("../tmp/preview/test-only/recovery-refund-cases.json", import.meta.url), "utf8"))[0];
async function ready(page: Page) { await page.goto("http://127.0.0.1:18765/test-only/refund-journal.html"); await page.waitForFunction(() => window.refundJournalReady); }

test("approved preparation stores before exposure, reuses exact bytes, and writes UNKNOWN before its single POST", async ({ page }) => {
  await ready(page);
  const item = vector();
  const result = await page.evaluate(async ({ item, plaintext }) => {
    const network = item.expectedNetwork as { name: "regtest"; genesis_hash: string };
    const document = new TextEncoder().encode(plaintext), selection = { fundingAttemptId: item.fundingAttemptId, bindingRevision: item.bindingRevision };
    const base = "http://127.0.0.1:8091/api";
    let gets = 0, posts = 0, unknownBeforePost = false, signedBody = "";
    const transport = async (url: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const path = String(url).slice(base.length + 1);
      if (init?.method === "POST") {
        posts++; signedBody = String(init.body);
        const journal = await window.BrowserRefundJournal.open();
        const stored = await journal.get(network, item.record.funding_history[0]!.binding.funding_txid, 0); journal.close();
        unknownBeforePost = stored?.state === "submission-unknown" && signedBody === stored.refund.transactionHex;
        return new Response(stored!.refund.txid);
      }
      gets++;
      if (path === "block-height/0") return new Response(network.genesis_hash);
      if (path === "blocks/tip/height") return new Response("1101");
      if (path === "blocks/tip/hash") return new Response("a".repeat(64));
      if (path === "block-height/1000") return new Response("d".repeat(64));
      if (path.endsWith("/hex")) return new Response(item.fundingTxHex);
      if (path.endsWith("/status")) return new Response(JSON.stringify({ confirmed: true, block_height: 1000, block_hash: "d".repeat(64) }));
      if (path.endsWith("/outspend/0")) return new Response('{"spent":false}');
      throw new Error("unexpected endpoint");
    };
    const options = { fetch: transport, broadcastApi: base, assertCurrent() {} };
    const saved = await window.refundActions.prepareBrowserRefund(document, network, selection, base, 100n, options);
    const initialGets = gets;
    const reused = await window.refundActions.prepareBrowserRefund(document, network, selection, base, 100n, options);
    const reusedWithoutRequests = initialGets === gets;
    const outcome = await window.refundActions.broadcastBrowserRefund(document, network, selection, base, reused, options);
    let replayRefused = false;
    try { await window.refundActions.broadcastBrowserRefund(document, network, selection, base, saved, options); } catch { replayRefused = true; }
    const journal = await window.BrowserRefundJournal.open(); const stored = (await journal.get(network, saved.refund.fundingTxid, 0))!; journal.close();
    return { saved, reused, stored, outcome, reusedWithoutRequests, replayRefused, posts, unknownBeforePost, signedBody };
  }, { item, plaintext: canonicalize(item.record)! });
  expect(result.saved.state).toBe("prepared"); expect(result.reused).toEqual(result.saved); expect(result.reusedWithoutRequests).toBe(true);
  expect(result.outcome.outcome).toBe("accepted"); expect(result.stored.state).toBe("accepted");
  expect(result.posts).toBe(1); expect(result.replayRefused).toBe(true); expect(result.unknownBeforePost).toBe(true);
  expect(result.signedBody).toBe(result.saved.refund.transactionHex);
});

for (const failure of ["lost response", "wrong txid", "HTTP failure", "acceptance persistence"]) {
  test(`ambiguous ${failure} keeps immutable intent and allows identical export without another POST`, async ({ page }) => {
    await ready(page); const item = vector();
    const outcome = await page.evaluate(async ({ item, plaintext, failure }) => {
      const network = item.expectedNetwork as { name: "regtest"; genesis_hash: string }, base = "http://127.0.0.1:8091/api";
      const document = new TextEncoder().encode(plaintext), selection = { fundingAttemptId: item.fundingAttemptId, bindingRevision: item.bindingRevision };
      let posts = 0, reads = 0;
      const transport = async (url: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
        const path = String(url).slice(base.length + 1);
        if (init?.method === "POST") {
          posts++; if (failure === "lost response") throw new Error("lost response");
          if (failure === "wrong txid") return new Response("0".repeat(64));
          if (failure === "HTTP failure") return new Response("upstream failed", { status: 503 });
          const journal = await window.BrowserRefundJournal.open(); const stored = await journal.get(network, item.record.funding_history[0]!.binding.funding_txid, 0); journal.close();
          return new Response(stored!.refund.txid);
        }
        reads++;
        if (path === "block-height/0") return new Response(network.genesis_hash);
        if (path === "blocks/tip/height") return new Response("1101");
        if (path === "blocks/tip/hash") return new Response("a".repeat(64));
        if (path === "block-height/1000") return new Response("d".repeat(64));
        if (path.endsWith("/hex")) return new Response(item.fundingTxHex);
        if (path.endsWith("/status")) return new Response(JSON.stringify({ confirmed: true, block_height: 1000, block_hash: "d".repeat(64) }));
        if (path.endsWith("/outspend/0")) return new Response('{"spent":false}');
        throw new Error("unexpected endpoint");
      };
      const options = { fetch: transport, broadcastApi: base, assertCurrent() {} };
      const saved = await window.refundActions.prepareBrowserRefund(document, network, selection, base, 100n, options);
      const original = window.BrowserRefundJournal.prototype.markAccepted;
      if (failure === "acceptance persistence") window.BrowserRefundJournal.prototype.markAccepted = async () => { throw new Error("quota failure"); };
      let result;
      try { result = await window.refundActions.broadcastBrowserRefund(document, network, selection, base, saved, options); }
      finally { window.BrowserRefundJournal.prototype.markAccepted = original; }
      const loaded = await window.refundActions.prepareBrowserRefund(document, network, selection, base, 100n, options);
      const before = reads;
      const exported = await window.refundActions.exportBrowserRefund(document, network, selection, base, loaded, options);
      let replay = false; try { await window.refundActions.broadcastBrowserRefund(document, network, selection, base, loaded, options); replay = true; } catch {}
      return { result, loaded, identical: saved.refund.transactionHex === exported.refund.transactionHex, noReadsOnReexport: reads === before, replay, posts };
    }, { item, plaintext: canonicalize(item.record)!, failure });
    expect(outcome.result!.outcome).toBe("unknown"); expect(outcome.loaded.state).toBe("submission-unknown");
    expect(outcome.identical).toBe(true); expect(outcome.noReadsOnReexport).toBe(true); expect(outcome.replay).toBe(false); expect(outcome.posts).toBe(1);
  });
}

test("approval withdrawn before signing prevents randomness, storage writes, and spending-byte exposure", async ({ page }) => {
  await ready(page); const item = vector();
  const outcome = await page.evaluate(async ({ item, plaintext }) => {
    const network = item.expectedNetwork as { name: "regtest"; genesis_hash: string }, document = new TextEncoder().encode(plaintext);
    const original = crypto.getRandomValues.bind(crypto); let randomCalls = 0, refused = false;
    crypto.getRandomValues = ((array: Uint8Array) => { randomCalls++; return original(array); }) as typeof crypto.getRandomValues;
    try { await window.refundActions.prepareBrowserRefund(document, network, { fundingAttemptId: item.fundingAttemptId, bindingRevision: 0 }, "http://127.0.0.1:8091/api", 100n,
      { broadcastApi: "http://127.0.0.1:8092/api", assertCurrent() { throw new Error("approval withdrawn"); } }); } catch { refused = true; } finally { crypto.getRandomValues = original; }
    const journal = await window.BrowserRefundJournal.open(); const stored = await journal.get(network, item.record.funding_history[0]!.binding.funding_txid, 0); journal.close();
    return { refused, randomCalls, stored };
  }, { item, plaintext: canonicalize(item.record)! });
  expect(outcome.refused).toBe(true); expect(outcome.randomCalls).toBe(0); expect(outcome.stored).toBeUndefined();
});

for (const race of ["withdraw during observation", "withdraw after UNKNOWN commit", "two broadcasts", "export versus broadcast"]) {
  test(`asynchronous refund boundary: ${race}`, async ({ page }) => {
    await ready(page); const item = vector();
    const result = await page.evaluate(async ({ item, plaintext, race }) => {
      const document = new TextEncoder().encode(plaintext), network = item.expectedNetwork as { name: "regtest"; genesis_hash: string };
      const selection = { fundingAttemptId: item.fundingAttemptId, bindingRevision: 0 }, base = "http://127.0.0.1:8091/api";
      let approved = true, posts = 0, randomCalls = 0;
      let release!: () => void, started!: () => void;
      const pending = new Promise<void>((resolve) => { started = resolve; });
      const gate = new Promise<void>((resolve) => { release = resolve; });
      const transport = async (url: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
        const path = String(url).slice(base.length + 1);
        if (init?.method === "POST") {
          posts++; const journal = await window.BrowserRefundJournal.open(); const stored = await journal.get(network, item.record.funding_history[0]!.binding.funding_txid, 0); journal.close();
          return new Response(stored!.refund.txid);
        }
        if (path === "block-height/0") return new Response(network.genesis_hash);
        if (path === "blocks/tip/height") return new Response("1101");
        if (path === "blocks/tip/hash") return new Response("a".repeat(64));
        if (path === "block-height/1000") return new Response("d".repeat(64));
        if (path.endsWith("/hex")) {
          if (race === "withdraw during observation") { started(); await gate; }
          return new Response(item.fundingTxHex);
        }
        if (path.endsWith("/status")) return new Response(JSON.stringify({ confirmed: true, block_height: 1000, block_hash: "d".repeat(64) }));
        if (path.endsWith("/outspend/0")) return new Response('{"spent":false}');
        throw new Error("unexpected endpoint");
      };
      const options = { broadcastApi: base, fetch: transport, assertCurrent() { if (!approved) throw new Error("approval changed"); } };
      const originalRng = crypto.getRandomValues.bind(crypto);
      crypto.getRandomValues = ((array: Uint8Array) => { randomCalls++; return originalRng(array); }) as typeof crypto.getRandomValues;
      let stored, rejected = false, exportWon = false, outcomes: unknown[] = [];
      const originalExposure = window.BrowserRefundJournal.prototype.beginExposure;
      try {
        if (race === "withdraw during observation") {
          const action = window.refundActions.prepareBrowserRefund(document, network, selection, base, 100n, options).catch(() => { rejected = true; });
          await pending; approved = false; release(); await action;
        } else {
          const saved = await window.refundActions.prepareBrowserRefund(document, network, selection, base, 100n, options);
          const send = () => window.refundActions.broadcastBrowserRefund(document, network, selection, base, saved, options);
          if (race === "withdraw after UNKNOWN commit") {
            window.BrowserRefundJournal.prototype.beginExposure = async function (record) {
              const exposed = await originalExposure.call(this, record); started(); await gate; return exposed;
            };
            const action = send(); await pending; approved = false; release(); outcomes = [await action];
          } else if (race === "two broadcasts") {
            outcomes = await Promise.allSettled([send(), send()]);
          } else {
            const attempts = await Promise.allSettled([window.refundActions.exportBrowserRefund(document, network, selection, base, saved, options), send()]);
            exportWon = attempts[0]!.status === "fulfilled"; outcomes = attempts;
          }
        }
        const journal = await window.BrowserRefundJournal.open();
        stored = await journal.get(network, item.record.funding_history[0]!.binding.funding_txid, 0);
        const exported = stored?.state === "submission-unknown" ? await journal.reexportIdentical(stored) : undefined;
        journal.close(); return { posts, randomCalls, stored, rejected, outcomes, exportWon, identicalExport: exported?.refund.transactionHex === stored?.refund.transactionHex };
      } finally { crypto.getRandomValues = originalRng; window.BrowserRefundJournal.prototype.beginExposure = originalExposure; }
    }, { item, plaintext: canonicalize(item.record)!, race });
    if (race === "withdraw during observation") { expect(result.rejected).toBe(true); expect(result.randomCalls).toBe(0); expect(result.stored).toBeUndefined(); }
    else if (race === "two broadcasts") { expect(result.posts).toBe(1); expect(result.stored!.state).toBe("accepted"); }
    else if (race === "export versus broadcast") { expect(result.posts).toBe(result.exportWon ? 0 : 1); expect(result.stored!.state).toBe(result.exportWon ? "submission-unknown" : "accepted"); }
    else { expect(result.stored!.state).toBe("submission-unknown"); expect(result.identicalExport).toBe(true); }
    if (race !== "two broadcasts" && race !== "export versus broadcast") expect(result.posts).toBe(0);
    if (race === "two broadcasts" || race === "export versus broadcast") {
      expect(result.outcomes.filter((item) => (item as { status: string }).status === "fulfilled")).toHaveLength(1);
      expect(result.outcomes.filter((item) => (item as { status: string }).status === "rejected")).toHaveLength(1);
    }
  });
}
