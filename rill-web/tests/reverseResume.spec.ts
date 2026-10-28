import { expect, test } from "./fixtures/swapPage";
import type { Page } from "@playwright/test";
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import canonicalize from "canonicalize";
import { encryptCanonicalRecoveryForRecipient } from "../src/recoveryAgeContainer";
import type { reverseCase } from "../unit/fixtures/reverseRecoveryCases";
import type * as Journal from "../src/browserReverseJournal";
import type * as Recovery from "../src/browserReverseRecovery";
import type * as Keys from "../src/recoveryKeys";
import type { NetworkName } from "../src/swap/config";
import type { NostrEvent } from "nostr-tools";

const PAGE = "http://127.0.0.1:18765/test-only/swap.html", API = "http://127.0.0.1:8091/api", BROADCAST = "http://127.0.0.1:8092/api";
const fixture = (): ReturnType<typeof reverseCase> & { expectedNetwork: { name: NetworkName; genesis_hash: string }; archiveEvent: NostrEvent } =>
  JSON.parse(readFileSync(new URL("../tmp/preview/test-only/reverse-resume.json", import.meta.url), "utf8"));

/** Shown invoice text for seeded external-wallet payments; Resume never decodes it, the journal binds it by hash. */
const INVOICE = "lnbcrt511u1savedinvoicefixture";

/** The seeded external-wallet payment keeps its shown invoice text, as every saved record does. */
async function seedFunded(page: Page, paymentUnknown = false, bolt11 = INVOICE): Promise<void> {
  await page.goto(PAGE);
  const recipient = await page.evaluate(async () => {
    const wallet = await window.uiFixture.wallet.open();
    try { const key = await wallet.recoveryKey(); key.file.fill(0); return key.recipient; } finally { wallet.close(); }
  });
  const data = fixture(), terms = { ...data.record, funding_history: [] };
  const termsFile = Array.from(await encryptCanonicalRecoveryForRecipient(new TextEncoder().encode(canonicalize(terms)!), recipient));
  const fundedFile = Array.from(await encryptCanonicalRecoveryForRecipient(new TextEncoder().encode(canonicalize(data.record)!), recipient));
  const shown = { bolt11, sha256: createHash("sha256").update(bolt11).digest("hex") };
  await page.evaluate(async ({ data, termsFile, fundedFile, paymentUnknown, shown }) => {
    const url = "/test-only/browserReverseJournal.js", { BrowserReverseJournal } = await import(url) as typeof Journal;
    const t = data.record.contract_terms, v = data.record.verification_context;
    // The synthetic signed binding hashes no real text; Resume checks only its payment hash against the journal.
    const binding = { ...t.invoice_binding, bolt11_sha256: shown.sha256 };
    const journal = await BrowserReverseJournal.open();
    try {
      let record = await journal.createFresh({ networkIdentity: data.expectedNetwork, sessionId: v.handshake_init.session_id,
        clientSessionKey: v.client_session_xonly_key, providerSessionKey: v.provider_session_xonly_key, providerIdentity: t.provider_identity_key,
        deadlineAt: t.terms_expiry, request: { kind: "ln-to-btc", mode: "firm", nominal_payout_sat: t.economics.nominal_payout_sat,
          payment_hash: t.invoice_binding.payment_hash, client_contract_compressed_key: t.client_contract_compressed_key,
          recovery_authorization_xonly_key: t.recovery_authorization_xonly_key, client_destination_script: t.client_destination_script,
          limits: { max_success_fee_sat: t.economics.success_fee_sat, min_claim_fee_reserve_sat: t.economics.claim_fee_reserve_sat,
            max_claim_fee_sat: t.max_claim_fee_sat, min_refund_lock_height: t.refund_lock_height, max_incoming_htlc_expiry_height: 300 }, extensions: {} } }, Uint8Array.from(termsFile));
      record = await journal.saveTerms(record, Uint8Array.from(termsFile));
      record = await journal.exposeInvoice(record, binding, Uint8Array.from(termsFile), shown.bolt11);
      if (!paymentUnknown) await journal.saveFunding(record, Uint8Array.from(fundedFile));
    } finally { journal.close(); }
  }, { data, termsFile, fundedFile, paymentUnknown, shown });
}

/** `mempool`: the provider's funding stays unconfirmed, below the signed depth. */
async function chain(page: Page, uncertain = false, mempool = false) {
  const data = fixture(), funding = data.record.funding_history[0]!.binding.funding_txid;
  let posts = 0, reads = 0, claimTxid = "";
  await page.route(API + "/**", async (route) => {
    reads++;
    const path = route.request().url().slice(API.length + 1);
    const values: Record<string, string> = { "block-height/0": data.expectedNetwork.genesis_hash, "blocks/tip/height": "200",
      "blocks/tip/hash": "a".repeat(64), "block-height/190": "d".repeat(64), [`tx/${funding}/hex`]: data.fundingTxHex,
      [`tx/${funding}/status`]: JSON.stringify(mempool ? { confirmed: false } : { confirmed: true, block_height: 190, block_hash: "d".repeat(64) }),
      [`tx/${funding}/outspend/0`]: '{"spent":false}' };
    if (claimTxid && path === `tx/${claimTxid}/status`) values[path] = JSON.stringify({ confirmed: !uncertain, block_height: 190, block_hash: "d".repeat(64) });
    if (values[path] === undefined) return route.abort();
    await route.fulfill({ body: values[path], headers: { "Access-Control-Allow-Origin": "*" } });
  });
  await page.route(BROADCAST + "/tx", async (route) => {
    posts++;
    const { parseTransaction } = await import("../src/swap/transaction");
    claimTxid = parseTransaction(Buffer.from(route.request().postData()!, "hex")).txid;
    if (uncertain) return route.abort();
    await route.fulfill({ body: claimTxid, headers: { "Access-Control-Allow-Origin": "*" } });
  });
  return { get posts() { return posts; }, get reads() { return reads; } };
}

async function resume(page: Page): Promise<void> {
  await page.goto(PAGE); // deliberately no file and no recovery fragment
  await page.locator("#swap-saved-recoveries summary").click();
  await expect(page.locator("#swap-saved-recoveries-list")).toContainText("Lightning to Bitcoin");
  await page.getByRole("button", { name: "Resume", exact: true }).click();
}

test("a funded reverse swap resumes and automatically claims using only browser storage", async ({ page }) => {
  await seedFunded(page); const transport = await chain(page);
  await page.reload();
  await expect(page.locator("#swap-saved-recoveries-list")).toContainText("funded");
  expect(transport.posts).toBe(0); expect(transport.reads).toBe(0);
  await resume(page);
  await expect(page.locator("#swap-reverse-steps h2")).toHaveText("Bitcoin received");
  expect(transport.posts).toBe(1);
  await page.locator("#swap-reverse-advanced summary").click();
  await expect(page.locator("#swap-reverse-backups a")).toHaveCount(1);
  await expect(page.locator("#swap-reverse-backups a")).toHaveText("Download swap backup");
  await expect(page.locator("#swap-reverse-payment-notes")).toContainText("Your claim lets the provider settle this payment");
  await page.locator("#swap-reverse-payment-details summary").click();
  await expect(page.locator("#swap-reverse-payment-hash")).toHaveText(fixture().record.contract_terms.invoice_binding.payment_hash);
  await expect(page.locator("#swap-reverse-payment-invoice")).toHaveText(INVOICE);
});

test("a funded external-wallet swap shows its invoice on Resume and claims from the mempool only by explicit choice", async ({ page }) => {
  await seedFunded(page, false, INVOICE); const transport = await chain(page, false, true);
  await resume(page);
  await expect(page.locator("#swap-reverse-payment-notes")).toContainText("so it holds your payment");
  await expect(page.locator("#swap-reverse-payment-notes")).toContainText("Do not pay again");
  await page.locator("#swap-reverse-payment-details summary").click();
  await expect(page.locator("#swap-reverse-payment-invoice")).toHaveText(INVOICE);
  await expect(page.locator("#swap-reverse-payment-uri")).toHaveAttribute("href", `lightning:${INVOICE}`);
  // The funding is only in the mempool, below the signed depth: Resume waits.
  await expect(page.locator("#swap-reverse-message")).toContainText("Waiting for confirmation data");
  expect(transport.posts).toBe(0);
  await page.locator("#swap-reverse-advanced summary").click();
  await expect(page.locator("#swap-reverse-claim-now-warning")).toContainText("unconfirmed funding, below the provider's signed 1");
  await expect(page.locator("#swap-reverse-claim-now")).toBeDisabled();
  await page.locator("#swap-reverse-claim-now-consent").check();
  await page.locator("#swap-reverse-claim-now").click();
  await expect(page.locator("#swap-reverse-steps h2")).toHaveText("Bitcoin received", { timeout: 10000 });
  expect(transport.posts).toBe(1);
  await expect(page.locator("#swap-log")).toContainText("claim now: claiming from the mempool by your choice");
  await expect(page.locator("#swap-reverse-claim-now-controls")).toBeHidden();
});

test("a pending external-wallet payment resumes with its saved invoice open and pay-once guidance", async ({ page }) => {
  // No archived funding on the relay: the provider has not locked the Bitcoin.
  await page.routeWebSocket("ws://127.0.0.1:7777/", (socket) => {
    socket.onMessage((message) => { const frame = JSON.parse(String(message)); if (frame[0] === "REQ") socket.send(JSON.stringify(["EOSE", frame[1]])); });
  });
  await seedFunded(page, true, INVOICE); const transport = await chain(page);
  await resume(page);
  await expect(page.locator("#swap-reverse-payment-invoice")).toBeVisible();
  await expect(page.locator("#swap-reverse-payment-invoice")).toHaveText(INVOICE);
  await expect(page.locator("#swap-reverse-payment-qr")).toBeVisible();
  await expect(page.locator("#swap-reverse-payment-notes")).toContainText("pay it once before");
  await expect(page.locator("#swap-reverse-claim-now-controls")).toHaveJSProperty("hidden", true);
  expect(transport.posts).toBe(0);
});

test("a pending payment resumes original-session archived funding without publishing or paying again", async ({ page }) => {
  const data = fixture(); let archiveReads = 0, publications = 0;
  await page.routeWebSocket("ws://127.0.0.1:7777/", (socket) => {
    socket.onMessage((message) => {
      const frame = JSON.parse(String(message));
      if (frame[0] === "EVENT") { publications++; return; }
      if (frame[0] !== "REQ") return;
      const filter = frame[2];
      if (filter.kinds.includes(1059)) {
        expect(filter["#p"]).toEqual([data.record.verification_context.client_session_xonly_key]);
        archiveReads++; socket.send(JSON.stringify(["EVENT", frame[1], data.archiveEvent]));
      }
      socket.send(JSON.stringify(["EOSE", frame[1]]));
    });
  });
  await seedFunded(page, true); const transport = await chain(page);
  await page.reload();
  await expect(page.locator("#swap-saved-recoveries-list")).toContainText("payment-unknown");
  expect(archiveReads).toBe(0); expect(transport.posts).toBe(0);
  await resume(page);
  await expect(page.locator("#swap-reverse-steps h2")).toHaveText("Bitcoin received");
  expect(archiveReads).toBe(1); expect(publications).toBe(0); expect(transport.posts).toBe(1);
});

test("an uncertain claim remains read-only across file-free Resume", async ({ page }) => {
  await seedFunded(page); const transport = await chain(page, true);
  await resume(page);
  await expect(page.locator("#swap-status")).toContainText("Claim unknown:");
  expect(transport.posts).toBe(1);
  await resume(page);
  await expect(page.locator("#swap-reverse-steps h2")).toHaveText("Confirming your claim");
  await page.locator("#swap-reverse-advanced summary").click();
  await page.locator("#swap-reverse-funding").click();
  await expect(page.locator("#swap-reverse-export")).toBeEnabled();
  expect(transport.posts).toBe(1);
});

test("a prepared claim survives interruption and resumes the saved fallback once", async ({ page }) => {
  await seedFunded(page); const transport = await chain(page);
  await page.evaluate(async (data) => {
    const journalUrl = "/test-only/browserReverseJournal.js", recoveryUrl = "/test-only/browserReverseRecovery.js", keysUrl = "/test-only/recoveryKeys.js";
    const { BrowserReverseJournal } = await import(journalUrl) as typeof Journal;
    const recovery = await import(recoveryUrl) as typeof Recovery, keys = await import(keysUrl) as typeof Keys;
    const wallet = await window.uiFixture.wallet.open(), journal = await BrowserReverseJournal.open();
    try {
      const record = (await journal.list())[0]!, key = await wallet.recoveryKey(); key.file.fill(0);
      const cipher = record.snapshots.at(-1)!.ciphertextHex.match(/../g)!.map((b) => Number.parseInt(b, 16));
      const plaintext = await keys.decryptRecoveryContainer(Uint8Array.from(cipher), key.identity);
      try {
        const e = await recovery.resumeBrowserReverseExecution(plaintext, key.identity, data.expectedNetwork, [], () => {});
        try { await e.prepareClaim("http://127.0.0.1:8091/api", 100n, () => {}); } finally { e.dispose(); }
      } finally { plaintext.fill(0); }
    } finally { journal.close(); wallet.close(); }
  }, fixture());
  expect(transport.posts).toBe(0);
  await resume(page);
  await expect(page.locator("#swap-reverse-steps h2")).toHaveText("Bitcoin received");
  expect(transport.posts).toBe(1);
});
