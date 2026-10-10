import { expect, test } from "@playwright/test";
import canonicalize from "canonicalize";
import { readFileSync } from "node:fs";
import type { constructSelectedRecoveryRefund } from "../src/recoveryInspection";
import type { RecoveryRefundCase } from "../unit/fixtures/recoveryRefundCases";

declare global {
  interface Window { constructSelectedRecoveryRefund: typeof constructSelectedRecoveryRefund }
}

test("disconnected browser refund construction uses Web Crypto, accepts the parity corpus, and has no storage or network effects", async ({ page }) => {
  const requests: string[] = [], sockets: string[] = [];
  page.on("request", (request) => requests.push(request.url()));
  page.on("websocket", (socket) => sockets.push(socket.url()));
  await page.goto("http://127.0.0.1:18765/test-only/recovery-admission.html");
  await page.waitForFunction(() => window.recoveryAdmissionReady);
  const cases = JSON.parse(readFileSync(new URL("../tmp/preview/test-only/recovery-refund-cases.json", import.meta.url), "utf8")) as RecoveryRefundCase[];
  const vectors = cases.map(({ record, ...item }) => ({ ...item, plaintext: canonicalize(record)! }));
  const results = await page.evaluate((vectors) => {
    let sideEffects = 0;
    const refuse = (): never => { sideEffects++; throw new Error("side effect attempted"); };
    Object.defineProperty(window, "fetch", { value: refuse });
    Object.defineProperty(window, "WebSocket", { value: class { constructor() { refuse(); } } });
    indexedDB.open = refuse; Storage.prototype.setItem = refuse;
    const hex = (text: string): Uint8Array => Uint8Array.from(text.match(/../g)!, (part) => parseInt(part, 16));
    const args = (item: typeof vectors[number]) => ({ fundingAttemptId: item.fundingAttemptId, bindingRevision: item.bindingRevision,
      rawFundingTransaction: hex(item.fundingTxHex), sampledTipHeight: item.tipHeight, feeSat: BigInt(item.feeSat) });
    const outcomes = vectors.map((item) => {
      try {
        const result = window.constructSelectedRecoveryRefund(new TextEncoder().encode(item.plaintext), item.expectedNetwork, args(item));
        return { name: item.name, accepted: true, frozen: Object.isFrozen(result), feeSat: result.feeSat };
      } catch (error) { return { name: item.name, accepted: false, error: (error as Error).message }; }
    });
    // Internal fresh auxiliary randomness changes the witness but not the txid.
    const first = vectors[0]!;
    const one = window.constructSelectedRecoveryRefund(new TextEncoder().encode(first.plaintext), first.expectedNetwork, args(first));
    const two = window.constructSelectedRecoveryRefund(new TextEncoder().encode(first.plaintext), first.expectedNetwork, args(first));
    return { outcomes, sideEffects, freshWitness: one.transactionHex !== two.transactionHex, sameTxid: one.txid === two.txid };
  }, vectors);
  expect(results.sideEffects).toBe(0); expect(results.freshWitness).toBe(true); expect(results.sameTxid).toBe(true);
  for (const [i, outcome] of results.outcomes.entries()) {
    expect(outcome.accepted, outcome.name).toBe(cases[i]!.accepted);
    if (outcome.accepted) { expect(outcome.frozen).toBe(true); expect(outcome.feeSat).toBe(cases[i]!.feeSat); }
    else expect(outcome.error).toBe("Recovery refund construction refused");
  }
  expect(sockets).toEqual([]);
  for (const url of requests) expect(new URL(url).host).toBe("127.0.0.1:18765");
});
