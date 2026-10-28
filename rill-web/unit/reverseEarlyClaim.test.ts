/** LN to BTC claims below the signed funding depth: an explicit, warned, live-session client choice. */
import { expect, spyOn, test } from "bun:test";
import canonicalize from "canonicalize";
import { schnorr } from "@noble/curves/secp256k1.js";
import { hexToBytes } from "@noble/hashes/utils.js";
import { executionFixture } from "./fixtures/reverseExecutionFixture";
import { reverseCase } from "./fixtures/reverseRecoveryCases";
import { constructSelectedReverseClaim } from "../src/recoveryInspection";
import { observeReverseRecoveryFunding, RecoveryFundingUnavailableError } from "../src/recoveryFunding";
import { effectiveClaimDepth } from "../src/swap/reverseClaim";
import { earlyClaimWarning } from "../src/reverseExecutionUi";
import { parseTransaction } from "../src/swap/transaction";
import type { ChainFetch } from "../src/swap/chainTip";
import type { NetworkName } from "../src/swap/config";

const API = "http://127.0.0.1:8091/api", BROADCAST = "http://127.0.0.1:8092/api";
const bytes = (record: unknown): Uint8Array => new TextEncoder().encode(canonicalize(record)!);

test("the claim depth lowers but never raises the signed depth", () => {
  expect(effectiveClaimDepth(2)).toBe(2);
  expect(effectiveClaimDepth(2, 0)).toBe(0);
  expect(effectiveClaimDepth(3, 1)).toBe(1);
  expect(effectiveClaimDepth(1, 5)).toBe(1);
  for (const [signed, requested] of [[2, -1], [2, 1.5], [2, Number.NaN], [0, 0], [1.5, 0]] as const) {
    expect(() => effectiveClaimDepth(signed, requested)).toThrow();
  }
});

test("the warning names the depth and the double-spend risk, only below the signed depth", () => {
  expect(earlyClaimWarning(1, 1)).toBeNull();
  expect(earlyClaimWarning(2, 1)).toBeNull();
  expect(earlyClaimWarning(0, 1)).toContain("unconfirmed funding, below the provider's signed 1");
  expect(earlyClaimWarning(0, 1)).toContain("double-spend");
  expect(earlyClaimWarning(1, 3)).toContain("funding at 1 confirmation, below the provider's signed 3");
  expect(earlyClaimWarning(2, 3)).toContain("funding at 2 confirmations");
});

test("claim construction accepts unconfirmed funding only on an explicit lower depth", () => {
  const item = reverseCase(), input = { fundingAttemptId: item.fundingAttemptId, bindingRevision: item.bindingRevision,
    rawFundingTransaction: hexToBytes(item.fundingTxHex), sampledTipHeight: item.tipHeight, confirmations: 0, feeSat: BigInt(item.feeSat) };
  const sign = spyOn(schnorr, "sign");
  try {
    // Signed depth 1: the default refuses 0 confirmations (the pre-existing fixture also pins this).
    expect(() => constructSelectedReverseClaim(bytes(item.record), item.expectedNetwork, input)).toThrow();
    for (const minimum of [-1, 2, 0.5, Number.NaN]) {
      expect(() => constructSelectedReverseClaim(bytes(item.record), item.expectedNetwork, { ...input, minFundingConfirmations: minimum })).toThrow();
    }
    expect(sign).not.toHaveBeenCalled();
    const claim = constructSelectedReverseClaim(bytes(item.record), item.expectedNetwork, { ...input, minFundingConfirmations: 0 });
    expect(parseTransaction(hexToBytes(claim.transactionHex)).inputs[0]!.witness).toHaveLength(4);
  } finally { sign.mockRestore(); }
});

function reverseChain(status: () => object) {
  const item = reverseCase(), binding = item.record.funding_history[0]!.binding;
  const network = item.expectedNetwork as { name: NetworkName; genesis_hash: string };
  const responses = new Map([
    ["block-height/0", network.genesis_hash], ["blocks/tip/height", "200"], ["blocks/tip/hash", "a".repeat(64)],
    ["block-height/190", "d".repeat(64)], [`tx/${binding.funding_txid}/hex`, item.fundingTxHex],
    [`tx/${binding.funding_txid}/outspend/${binding.contract_vout}`, '{"spent":false}'],
  ]);
  const fetch: ChainFetch = async (url) => {
    const path = String(url).slice(API.length + 1);
    const answer = path === `tx/${binding.funding_txid}/status` ? JSON.stringify(status()) : responses.get(path);
    if (answer === undefined) throw new Error("unexpected endpoint");
    return new Response(answer);
  };
  const run = (allowUnconfirmed?: boolean) => observeReverseRecoveryFunding(bytes(item.record), network,
    { fundingAttemptId: item.fundingAttemptId, bindingRevision: item.bindingRevision }, API, { fetch, ...(allowUnconfirmed === undefined ? {} : { allowUnconfirmed }) });
  return { run };
}

test("mempool funding is 0 confirmations only when explicitly allowed", async () => {
  const chain = reverseChain(() => ({ confirmed: false }));
  await expect(chain.run()).rejects.toBeInstanceOf(RecoveryFundingUnavailableError);
  await expect(chain.run(false)).rejects.toBeInstanceOf(RecoveryFundingUnavailableError);
  expect(await chain.run(true)).toMatchObject({ confirmations: 0, fundingBlockHeight: null, fundingBlockHash: null, tipHeight: 200 });
  // Allowing the mempool changes nothing for confirmed funding.
  expect(await reverseChain(() => ({ confirmed: true, block_height: 190, block_hash: "d".repeat(64) })).run(true))
    .toMatchObject({ confirmations: 11, fundingBlockHeight: 190, fundingBlockHash: "d".repeat(64) });
});

test("funding that confirms between the two observation passes is unknown, not mixed", async () => {
  let reads = 0;
  const chain = reverseChain(() => ++reads === 1 ? { confirmed: false } : { confirmed: true, block_height: 190, block_hash: "d".repeat(64) });
  await expect(chain.run(true)).rejects.toBeInstanceOf(RecoveryFundingUnavailableError);
});

test("a live session claims unconfirmed funding cooperatively at depth 0", async () => {
  const f = await executionFixture("signed"), e = await f.prepare({ claimConfirmations: 0 }), transport = spyOn(globalThis, "fetch").mockImplementation(f.fetch);
  try {
    expect(e.claimDepth).toBe(0); expect(f.terms.funding_confirmations).toBe(1);
    await e.accept(f.assertCurrent); await e.exposeInvoice(f.assertCurrent); await e.receiveFunding();
    f.unconfirmed = true;
    expect(await e.fundingDepth(API)).toBe(0);
    const prepared = await e.prepareClaim(API, 100n, f.assertCurrent);
    const result = await e.exposeClaim(API, BROADCAST, "broadcast", f.assertCurrent);
    expect(result.outcome).toBe("accepted"); expect(result.txid).toBe(prepared.claim.txid); expect(f.posts).toBe(1);
    expect(f.events).toContain("action:cooperative_claim_complete");
    expect(parseTransaction(hexToBytes(f.postedTransactions[0]!)).inputs[0]!.witness).toHaveLength(1); // key path
  } finally { transport.mockRestore(); e.dispose(); }
});

test("without the choice, unconfirmed funding is never claimed", async () => {
  const f = await executionFixture(), e = await f.prepare(), transport = spyOn(globalThis, "fetch").mockImplementation(f.fetch);
  const sign = spyOn(schnorr, "sign");
  try {
    expect(e.claimDepth).toBe(1);
    await e.accept(f.assertCurrent); await e.exposeInvoice(f.assertCurrent); await e.receiveFunding();
    f.unconfirmed = true; sign.mockClear();
    await expect(e.fundingDepth(API)).rejects.toBeInstanceOf(RecoveryFundingUnavailableError);
    await expect(e.prepareClaim(API, 100n, f.assertCurrent)).rejects.toThrow();
    expect(sign).not.toHaveBeenCalled(); expect(f.posts).toBe(0);
  } finally { sign.mockRestore(); transport.mockRestore(); e.dispose(); }
});

test("a choice above the signed depth waits for the signed depth", async () => {
  const f = await executionFixture(), e = await f.prepare({ claimConfirmations: 6 });
  try { expect(e.claimDepth).toBe(1); } finally { e.dispose(); }
});

for (const value of [-1, 1.5, Number.NaN, Number.POSITIVE_INFINITY]) {
  test(`a malformed claim depth (${value}) is refused before any secret is stored or request sent`, async () => {
    const f = await executionFixture();
    await expect(f.prepare({ claimConfirmations: value })).rejects.toThrow();
    expect(f.events).toEqual([]);
  });
}
