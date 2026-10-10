import { expect, test, type Page } from "@playwright/test";
import { readFileSync } from "node:fs";
import type * as Recovery from "../src/browserReverseRecovery";
import type * as Keys from "../src/recoveryKeys";
import type { NetworkName } from "../src/swap/config";
import { createRecoveryKey } from "../src/recoveryKeys";
import { encryptCanonicalRecoveryForRecipient } from "../src/recoveryAgeContainer";
declare global { interface Window { reverseRecovery: typeof Recovery; reverseKeys: typeof Keys; reverseRecoveryReady: boolean;
  mountReverseRecovery: (data: Fixture) => () => void; reverseUi: { api: string; broadcast: string; current: boolean } } }
const BASE = "http://127.0.0.1:8091/api", BROADCAST = "http://127.0.0.1:8092/api";
interface Fixture { plaintext: string; identity: string; fundingTxHex: string; expectedNetwork: { name: NetworkName; genesis_hash: string }; record: { funding_history: { binding: { funding_txid: string; contract_vout: number } }[] } }
const fixture = (): Fixture => JSON.parse(readFileSync(new URL("../tmp/preview/test-only/reverse-recovery.json", import.meta.url), "utf8"));
async function ready(page: Page) { await page.goto("http://127.0.0.1:18765/test-only/reverse-recovery.html"); await page.waitForFunction(() => window.reverseRecoveryReady); }
async function api(page: Page) {
  const data = fixture(), txid = data.record.funding_history[0]!.binding.funding_txid; let posts = 0, acceptedTxid = "";
  await page.route(BASE + "/**", async (route) => {
    const values: Record<string, string> = { "block-height/0": data.expectedNetwork.genesis_hash, "blocks/tip/height": "200", "blocks/tip/hash": "a".repeat(64), "block-height/190": "d".repeat(64),
      [`tx/${txid}/hex`]: data.fundingTxHex, [`tx/${txid}/status`]: JSON.stringify({ confirmed: true, block_height: 190, block_hash: "d".repeat(64) }), [`tx/${txid}/outspend/0`]: '{"spent":false}' };
    const value = values[route.request().url().slice(BASE.length + 1)]; if (value === undefined) return route.abort();
    await route.fulfill({ status: 200, body: value, headers: { "Access-Control-Allow-Origin": "*" } });
  });
  await page.route(BROADCAST + "/**", async (route) => { posts++; if (acceptedTxid) await route.fulfill({ body: acceptedTxid, headers: { "Access-Control-Allow-Origin": "*" } }); else await route.abort(); });
  return { get posts() { return posts; }, set acceptedTxid(value: string) { acceptedTxid = value; } };
}
async function mountedClaim(page: Page) {
  await ready(page); const transport = await api(page); await page.evaluate((data) => window.mountReverseRecovery(data), fixture());
  await page.locator("#swap-reverse-recovery-fee").fill("100"); await page.locator("#swap-reverse-recovery-approved").check();
  await page.locator("#swap-reverse-recovery-prepare").click(); await expect(page.locator("#swap-reverse-recovery-claim-saved")).toBeEnabled(); return transport;
}
const prepare = (page: Page) => page.evaluate(async ({ data, api }) => Array.from(await window.reverseRecovery.prepareRecoveredReverseClaim(new TextEncoder().encode(data.plaintext), data.identity, data.expectedNetwork, api, 100n, () => {})), { data: fixture(), api: BASE });

test("missing browser history alone neither connects nor signs, explicit funded import grants claim-only authority", async ({ page }) => {
  await ready(page); const transport = await api(page);
  const absent = await page.evaluate(async (data) => { try { await window.reverseRecovery.loadBrowserReverseRecovery(new TextEncoder().encode(data.plaintext), data.identity, data.expectedNetwork); return false; } catch { return true; } }, fixture());
  expect(absent).toBe(true); expect(transport.posts).toBe(0);
  const encrypted = await prepare(page); expect(new TextDecoder().decode(Uint8Array.from(encrypted)).startsWith("age-encryption.org/v1\n")).toBe(true);
  const state = await page.evaluate(async (data) => {
    const result = await window.reverseRecovery.loadBrowserReverseRecovery(new TextEncoder().encode(data.plaintext), data.identity, data.expectedNetwork);
    const db = await new Promise<IDBDatabase>((resolve) => { const r = indexedDB.open("rillswap-reverse-execution"); r.onsuccess = () => resolve(r.result); });
    const payments = await new Promise<number>((resolve) => { const r = db.transaction("payments").objectStore("payments").count(); r.onsuccess = () => resolve(r.result); });
    db.close(); return { stage: result.stage, payments };
  }, fixture()); expect(state).toEqual({ stage: "claim-ready", payments: 0 });
  expect(transport.posts).toBe(0);
});

test("restored immutable fallback exports exactly once and later remains identical without another POST", async ({ page }) => {
  await ready(page); const transport = await api(page), encrypted = await prepare(page);
  await page.reload(); await page.waitForFunction(() => window.reverseRecoveryReady);
  const exported = await page.evaluate(async ({ data, api, broadcast, encrypted }) => {
    const fallback = await window.reverseKeys.decryptRecoveryContainer(Uint8Array.from(encrypted), data.identity);
    const doc = JSON.parse(new TextDecoder().decode(fallback)); fallback.fill(0);
    const claim = (await window.reverseRecovery.loadBrowserReverseRecovery(new TextEncoder().encode(data.plaintext), data.identity, data.expectedNetwork)).claimTxid!;
    const result = await window.reverseRecovery.exposeRecoveredReverseClaim(new TextEncoder().encode(data.plaintext), data.identity, data.expectedNetwork, api, broadcast, 100n, claim, "download", () => {});
    return { result, savedHex: doc.extensions["rillswap/reverse-claim-fallback"].transaction };
  }, { data: fixture(), api: BASE, broadcast: BROADCAST, encrypted });
  expect(exported.result.outcome).toBe("exported"); expect(exported.result.transactionHex).toBe(exported.savedHex);
  const again = await page.evaluate(async ({ data, api, broadcast }) => {
    const claim = (await window.reverseRecovery.loadBrowserReverseRecovery(new TextEncoder().encode(data.plaintext), data.identity, data.expectedNetwork)).claimTxid!;
    let refused = false; try { await window.reverseRecovery.exposeRecoveredReverseClaim(new TextEncoder().encode(data.plaintext), data.identity, data.expectedNetwork, api, broadcast, 100n, claim, "broadcast", () => {}); } catch { refused = true; }
    const result = await window.reverseRecovery.exposeRecoveredReverseClaim(new TextEncoder().encode(data.plaintext), data.identity, data.expectedNetwork, api, broadcast, 100n, claim, "download", () => {}); return { refused, result };
  }, { data: fixture(), api: BASE, broadcast: BROADCAST });
  expect(again.refused).toBe(true); expect(again.result.transactionHex).toBe(exported.savedHex); expect(transport.posts).toBe(0);
});

test("lost broadcast response stays UNKNOWN across reload, refusing another POST and another signing selection", async ({ page }) => {
  await ready(page); const transport = await api(page); await prepare(page);
  const result = await page.evaluate(async ({ data, api, broadcast }) => {
    const claim = (await window.reverseRecovery.loadBrowserReverseRecovery(new TextEncoder().encode(data.plaintext), data.identity, data.expectedNetwork)).claimTxid!;
    return window.reverseRecovery.exposeRecoveredReverseClaim(new TextEncoder().encode(data.plaintext), data.identity, data.expectedNetwork, api, broadcast, 100n, claim, "broadcast", () => {});
  }, { data: fixture(), api: BASE, broadcast: BROADCAST });
  expect(result.outcome).toBe("unknown"); expect(transport.posts).toBe(1);
  await page.reload(); await page.waitForFunction(() => window.reverseRecoveryReady);
  const refused = await page.evaluate(async ({ data, api, broadcast }) => {
    let post = false, changedFee = false;
    const claim = (await window.reverseRecovery.loadBrowserReverseRecovery(new TextEncoder().encode(data.plaintext), data.identity, data.expectedNetwork)).claimTxid!;
    try { await window.reverseRecovery.exposeRecoveredReverseClaim(new TextEncoder().encode(data.plaintext), data.identity, data.expectedNetwork, api, broadcast, 100n, claim, "broadcast", () => {}); post = true; } catch {}
    try { await window.reverseRecovery.prepareRecoveredReverseClaim(new TextEncoder().encode(data.plaintext), data.identity, data.expectedNetwork, api, 101n, () => {}); changedFee = true; } catch {}
    const local = await window.reverseRecovery.loadBrowserReverseRecovery(new TextEncoder().encode(data.plaintext), data.identity, data.expectedNetwork); return { post, changedFee, stage: local.stage };
  }, { data: fixture(), api: BASE, broadcast: BROADCAST }); expect(refused).toEqual({ post: false, changedFee: false, stage: "claim-unknown" }); expect(transport.posts).toBe(1);
});

test("interrupted reservation cannot resume under another identity or mix encrypted predecessors", async ({ page }) => {
  await ready(page); const transport = await api(page);
  const result = await page.evaluate(async ({ data, api }) => {
    let approvals = 0, interrupted = false;
    try { await window.reverseRecovery.prepareRecoveredReverseClaim(new TextEncoder().encode(data.plaintext), data.identity, data.expectedNetwork, api, 100n,
      () => { if (++approvals === 6) throw new Error("interrupted after reservation"); }); } catch { interrupted = true; }
    const before = await window.reverseRecovery.loadBrowserReverseRecovery(new TextEncoder().encode(data.plaintext), data.identity, data.expectedNetwork);
    const other = await window.reverseKeys.createRecoveryKey(); let refused = false;
    try { await window.reverseRecovery.prepareRecoveredReverseClaim(new TextEncoder().encode(data.plaintext), other.identity, data.expectedNetwork, api, 100n, () => {}); } catch { refused = true; }
    const after = await window.reverseRecovery.loadBrowserReverseRecovery(new TextEncoder().encode(data.plaintext), data.identity, data.expectedNetwork);
    return { interrupted, refused, before: { stage: before.stage, cipher: Array.from(before.ciphertext) }, after: { stage: after.stage, cipher: Array.from(after.ciphertext) } };
  }, { data: fixture(), api: BASE }); expect(result.interrupted).toBe(true); expect(result.refused).toBe(true); expect(result.before.stage).toBe("recovery-reserved"); expect(result.after).toEqual(result.before); expect(transport.posts).toBe(0);
});

test("concurrent different identities cannot choose a fallback encrypted apart from its retained predecessor", async ({ page }) => {
  await ready(page); const transport = await api(page);
  const result = await page.evaluate(async ({ data, api }) => {
    const other = await window.reverseKeys.createRecoveryKey(), identities = [data.identity, other.identity];
    let emptyLookups = 0; const original = IDBObjectStore.prototype.get;
    IDBObjectStore.prototype.get = function(...args) { const request = original.apply(this, args); if (this.name === "claims") request.addEventListener("success", () => { if (request.result === undefined) emptyLookups++; }); return request; };
    let results: PromiseSettledResult<Uint8Array>[];
    try { results = await Promise.allSettled(identities.map((identity) => window.reverseRecovery.prepareRecoveredReverseClaim(new TextEncoder().encode(data.plaintext), identity, data.expectedNetwork, api, 100n, () => {}))); }
    finally { IDBObjectStore.prototype.get = original; }
    const keys: boolean[] = [];
    for (const identity of identities) { try { const saved = await window.reverseRecovery.loadBrowserReverseRecovery(new TextEncoder().encode(data.plaintext), identity, data.expectedNetwork); keys.push(saved.stage === "claim-ready"); } catch { keys.push(false); } }
    return { emptyLookups, outcomes: results.map((r) => r.status), keys };
  }, { data: fixture(), api: BASE }); expect(result.emptyLookups).toBeGreaterThanOrEqual(2); expect(result.outcomes.filter((r) => r === "fulfilled")).toHaveLength(1);
  expect(result.keys.filter(Boolean)).toHaveLength(1); expect(transport.posts).toBe(0);
});

test("recovery preparation alone cannot expose a claim without separate exact-backup acknowledgment", async ({ page }) => {
  const transport = await mountedClaim(page);
  await page.locator("#swap-reverse-recovery-broadcast").click(); await expect(page.locator("#swap-reverse-recovery-message")).toContainText("blocked");
  expect(transport.posts).toBe(0); await expect(page.locator("#swap-reverse-recovery-broadcast")).toBeEnabled();
  await page.locator("#swap-reverse-recovery-claim-saved").check(); await page.locator("#swap-reverse-recovery-export").click();
  await expect(page.locator('a[download="rillswap-recovered-claim.hex"]')).toBeVisible(); await expect(page.locator("#swap-reverse-recovery-broadcast")).toBeDisabled();
  await page.locator("#swap-reverse-recovery-export").click(); await expect(page.locator('a[download="rillswap-recovered-claim.hex"]')).toHaveCount(2); expect(transport.posts).toBe(0);
});

for (const change of ["acknowledgment", "fee", "api", "file", "key", "network"]) {
  test(`changing ${change} during deferred recovery exposure prevents private export and POST`, async ({ page }) => {
    const transport = await mountedClaim(page); await page.locator("#swap-reverse-recovery-claim-saved").check();
    let arrived!: () => void, release!: () => void;
    const pending = new Promise<void>((resolve) => { arrived = resolve; }), held = new Promise<void>((resolve) => { release = resolve; });
    await page.route(BASE + "/tx/*/outspend/*", async (route) => { arrived(); await held; await route.fulfill({ body: '{"spent":false}', headers: { "Access-Control-Allow-Origin": "*" } }); });
    await page.locator("#swap-reverse-recovery-export").click(); await pending;
    if (change === "acknowledgment") await page.locator("#swap-reverse-recovery-claim-saved").uncheck();
    else if (change === "fee") await page.locator("#swap-reverse-recovery-fee").fill("101");
    else if (change === "api") await page.evaluate(() => { window.reverseUi.api = "http://127.0.0.1:18091/api"; });
    else await page.evaluate(() => { window.reverseUi.current = false; });
    release(); await expect(page.locator("#swap-reverse-recovery-message")).toContainText("blocked");
    await expect(page.locator('a[download="rillswap-recovered-claim.hex"]')).toHaveCount(0); expect(transport.posts).toBe(0);
  });
}
test("ambiguous recovery broadcast stays visibly disabled while exact manual export remains available", async ({ page }) => {
  const transport = await mountedClaim(page); await page.locator("#swap-reverse-recovery-claim-saved").check();
  await page.locator("#swap-reverse-recovery-broadcast").click(); await expect(page.locator("#swap-reverse-recovery-message")).toContainText("Claim unknown:");
  await expect(page.locator("#swap-reverse-recovery-broadcast")).toBeDisabled(); expect(transport.posts).toBe(1);
  await page.locator("#swap-reverse-recovery-export").click(); await expect(page.locator('a[download="rillswap-recovered-claim.hex"]')).toBeVisible(); expect(transport.posts).toBe(1);
});
test("accepted recovery broadcast also stays disabled and exact claim acknowledgment cannot name another transaction", async ({ page }) => {
  const transport = await mountedClaim(page);
  const metadata = await page.evaluate(async (data) => {
    const bytes = new TextEncoder().encode(data.plaintext); let refused = false;
    try { await window.reverseRecovery.exposeRecoveredReverseClaim(bytes, data.identity, data.expectedNetwork, "http://127.0.0.1:8091/api", "http://127.0.0.1:8092/api", 100n, "0".repeat(64), "broadcast", () => {}); } catch { refused = true; }
    return { refused, saved: await window.reverseRecovery.loadBrowserReverseRecovery(bytes, data.identity, data.expectedNetwork) };
  }, fixture()); expect(metadata.refused).toBe(true); expect(metadata.saved.stage).toBe("claim-ready"); expect(transport.posts).toBe(0);
  transport.acceptedTxid = metadata.saved.claimTxid!;
  await page.locator("#swap-reverse-recovery-claim-saved").check(); await page.locator("#swap-reverse-recovery-broadcast").click();
  await expect(page.locator("#swap-reverse-recovery-message")).toContainText("Claim accepted:"); await expect(page.locator("#swap-reverse-recovery-broadcast")).toBeDisabled(); expect(transport.posts).toBe(1);
});

for (const change of ["file", "key", "network"]) {
  test(`actual recovery panel ${change} control invalidates an in-flight reverse claim exposure`, async ({ page }) => {
    const data = fixture(), key = await createRecoveryKey(), other = await createRecoveryKey();
    const encrypted = await encryptCanonicalRecoveryForRecipient(new TextEncoder().encode(data.plaintext), key.recipient);
    const payload = (bytes: Uint8Array, name: string) => ({ name, mimeType: "application/octet-stream", buffer: Buffer.from(bytes) });
    await page.goto("http://127.0.0.1:18765/test-only/swap.html"); const transport = await api(page);
    await page.locator("#swap-recovery summary").first().click(); await page.locator("#swap-recovery-file").setInputFiles(payload(encrypted, "original.age"));
    await page.locator("#swap-recovery-key-file").setInputFiles(payload(key.file, "original.key")); await page.locator("#swap-recovery-inspect").click();
    await expect(page.locator("#swap-recovery-result h3")).toHaveText("Lightning to Bitcoin recovery verified");
    await page.locator("#swap-reverse-recovery-fee").fill("100"); await page.locator("#swap-reverse-recovery-approved").check();
    await page.locator("#swap-reverse-recovery-prepare").click(); await expect(page.locator("#swap-reverse-recovery-claim-saved")).toBeEnabled(); await page.locator("#swap-reverse-recovery-claim-saved").check();
    let arrived!: () => void, release!: () => void, done!: () => void;
    const pending = new Promise<void>((resolve) => { arrived = resolve; }), held = new Promise<void>((resolve) => { release = resolve; }), completed = new Promise<void>((resolve) => { done = resolve; });
    let observations = 0;
    await page.route(BASE + "/tx/*/outspend/*", async (route) => { arrived(); await held; await route.fulfill({ body: '{"spent":false}', headers: { "Access-Control-Allow-Origin": "*" } }); if (++observations === 2) done(); });
    await page.locator("#swap-reverse-recovery-broadcast").click(); await pending;
    if (change === "file") await page.locator("#swap-recovery-file").setInputFiles(payload(encrypted, "different.age"));
    else if (change === "key") await page.locator("#swap-recovery-key-file").setInputFiles(payload(other.file, "different.key"));
    else { await page.locator("#swap-settings-toggle").click(); await page.locator("#swap-network").selectOption("signet"); await page.locator("#swap-settings-close").click(); }
    release(); await completed;
    // Wait for the immutable encrypted state read after the completed observer,
    // rather than sleeping or confusing the harness callback with real controls.
    const stage = await page.evaluate(async ({ data, identity }) => {
      const path = "/test-only/browserReverseRecovery.js", module = await import(path) as typeof Recovery;
      return (await module.loadBrowserReverseRecovery(new TextEncoder().encode(data.plaintext), identity, data.expectedNetwork)).stage;
    }, { data, identity: key.identity }); expect(stage).toBe("claim-ready");
    await expect(page.locator('a[download="rillswap-recovered-claim.hex"]')).toHaveCount(0); expect(transport.posts).toBe(0);
  });
}
