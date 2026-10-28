import { expect, test } from "@playwright/test";
import { readFileSync } from "node:fs";
import type * as ClaimActions from "../src/swap/reverseClaim";
import type { BrowserReverseJournal, ReverseIntentContext } from "../src/browserReverseJournal";
import type { NetworkName } from "../src/swap/config";
import type { ReverseFixtureRecord } from "../unit/fixtures/reverseRecoveryCases";

declare global { interface Window {
  BrowserReverseJournal: typeof BrowserReverseJournal;
  reverseClaimActions: typeof ClaimActions;
  reverseClaimReady: boolean;
  finishCooperation: () => Promise<void>;
} }
const API = "http://127.0.0.1:8091/api", BROADCAST = "http://127.0.0.1:8092/api";
interface Fixture { plaintext: string; fundingTxHex: string; expectedNetwork: { name: NetworkName; genesis_hash: string }; record: ReverseFixtureRecord }
const fixture = (): Fixture => JSON.parse(readFileSync(new URL("../tmp/preview/test-only/reverse-recovery.json", import.meta.url), "utf8"));

// Real claim orchestration and IndexedDB; the cooperation seam controls whether publication was possible.
// Unit execution tests separately exercise the real cooperative transport's deadline checks.
for (const [published, crossedCutoff] of [[false, false], [false, true], [true, true]] as const) {
  test(`durable claim election, publication ${published}, crossed cutoff ${crossedCutoff}`, async ({ page }) => {
    const data = fixture(), binding = data.record.funding_history[0]!.binding;
    let tip = 218, posts = 0, acceptedTxid = "";
    await page.route(API + "/**", async (route) => {
      const values: Record<string, string> = { "block-height/0": data.expectedNetwork.genesis_hash,
        "blocks/tip/height": String(tip), "blocks/tip/hash": "a".repeat(64), "block-height/190": "d".repeat(64),
        [`tx/${binding.funding_txid}/hex`]: data.fundingTxHex,
        [`tx/${binding.funding_txid}/status`]: JSON.stringify({ confirmed: true, block_height: 190, block_hash: "d".repeat(64) }),
        [`tx/${binding.funding_txid}/outspend/0`]: '{"spent":false}' };
      const body = values[route.request().url().slice(API.length + 1)];
      if (body === undefined) return route.abort();
      await route.fulfill({ body, headers: { "Access-Control-Allow-Origin": "*" } });
    });
    await page.route(BROADCAST + "/tx", async (route) => {
      posts++; await route.fulfill({ body: acceptedTxid, headers: { "Access-Control-Allow-Origin": "*" } });
    });
    await page.exposeFunction("finishCooperation", () => { if (crossedCutoff) tip = 219; });
    await page.goto("http://127.0.0.1:18765/test-only/reverse-claim.html");
    await page.waitForFunction(() => window.reverseClaimReady);
    const prepared = await page.evaluate(async ({ data, api }) => {
      const journal = await window.BrowserReverseJournal.open(), doc = data.record, terms = doc.contract_terms, verification = doc.verification_context;
      const context: ReverseIntentContext = { networkIdentity: data.expectedNetwork, sessionId: verification.handshake_init.session_id,
        clientSessionKey: verification.client_session_xonly_key, providerSessionKey: verification.provider_session_xonly_key,
        providerIdentity: terms.provider_identity_key, deadlineAt: terms.terms_expiry,
        request: { kind: "ln-to-btc", mode: "firm", nominal_payout_sat: terms.economics.nominal_payout_sat, payment_hash: terms.invoice_binding.payment_hash,
          client_contract_compressed_key: terms.client_contract_compressed_key, recovery_authorization_xonly_key: terms.recovery_authorization_xonly_key,
          client_destination_script: terms.client_destination_script, limits: { max_success_fee_sat: terms.economics.success_fee_sat,
            min_claim_fee_reserve_sat: terms.economics.claim_fee_reserve_sat, max_claim_fee_sat: terms.max_claim_fee_sat,
            min_refund_lock_height: terms.refund_lock_height, max_incoming_htlc_expiry_height: terms.timing_policy.min_incoming_htlc_expiry_height }, extensions: {} } };
      const cipher = new TextEncoder().encode("age-encryption.org/v1\n" + "public-test-only-placeholder".repeat(4));
      try {
        const fresh = await journal.createFresh(context, cipher), saved = await journal.saveTerms(fresh, cipher);
        const paid = await journal.exposeInvoice(saved, terms.invoice_binding, cipher), funded = await journal.saveFunding(paid, cipher);
        const claim = await window.reverseClaimActions.prepareJournaledReverseClaim({ plaintext: new TextEncoder().encode(data.plaintext),
          record: funded, journal, network: data.expectedNetwork, assertCurrent: () => {} }, api, 100n, async () => cipher, () => {});
        return { context, plaintext: Array.from(claim.plaintext), record: claim.record };
      } finally { journal.close(); }
    }, { data, api: API });
    acceptedTxid = prepared.record.claim!.txid;
    const result = await page.evaluate(async ({ prepared, network, api, broadcast, published }) => {
      const journal = await window.BrowserReverseJournal.open(); let electionStage = "", outcome = "";
      try {
        try {
          const result = await window.reverseClaimActions.exposeJournaledReverseClaim({ plaintext: Uint8Array.from(prepared.plaintext),
            record: prepared.record, journal, network, assertCurrent: () => {} }, api, broadcast, "broadcast", () => {},
          async (_tip, beforeDisclosure, onDisclosure) => {
            await beforeDisclosure();
            electionStage = (await journal.get(network, prepared.context.sessionId))!.stage;
            if (published) onDisclosure();
            await window.finishCooperation(); throw new Error("cooperation ended");
          });
          outcome = result.exposure.outcome;
        } catch (error) { outcome = (error as Error).message; }
        return { electionStage, outcome, stored: (await journal.get(network, prepared.context.sessionId))! };
      } finally { journal.close(); }
    }, { prepared, network: data.expectedNetwork, api: API, broadcast: BROADCAST, published });
    const refused = !published && crossedCutoff;
    expect(result.electionStage).toBe("claim-unknown");
    if (refused) expect(result.outcome).toContain("Reverse claim refused"); else expect(result.outcome).toBe("accepted");
    expect(posts).toBe(refused ? 0 : 1); expect(result.stored.stage).toBe(refused ? "claim-unknown" : "accepted");
    await page.reload(); await page.waitForFunction(() => window.reverseClaimReady);
    const restored = await page.evaluate(async ({ prepared, network, api, broadcast }) => {
      const journal = await window.BrowserReverseJournal.open();
      try {
        const record = (await journal.get(network, prepared.context.sessionId))!, context = { plaintext: Uint8Array.from(prepared.plaintext), record, journal, network, assertCurrent: () => {} };
        let replay = false;
        try { await window.reverseClaimActions.exposeJournaledReverseClaim(context, api, broadcast, "broadcast", () => {}); replay = true; } catch {}
        const exported = await window.reverseClaimActions.exposeJournaledReverseClaim(context, api, broadcast, "download", () => {});
        const doc = JSON.parse(new TextDecoder().decode(context.plaintext));
        return { replay, identical: exported.exposure.transactionHex === doc.extensions["rillswap/reverse-claim-fallback"].transaction };
      } finally { journal.close(); }
    }, { prepared, network: data.expectedNetwork, api: API, broadcast: BROADCAST });
    expect(restored).toEqual({ replay: false, identical: true }); expect(posts).toBe(refused ? 0 : 1);
  });
}
