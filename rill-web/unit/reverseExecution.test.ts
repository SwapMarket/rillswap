import { expect, spyOn, test } from "bun:test";
import { schnorr } from "@noble/curves/secp256k1.js";
import { executionFixture } from "./fixtures/reverseExecutionFixture";
import { inspectReverseRecoveryPlaintext } from "../src/recoveryInspection";
import { parseTransaction } from "../src/swap/transaction";
import { hexToBytes } from "@noble/hashes/utils.js";

const API = "http://127.0.0.1:8091/api", BROADCAST = "http://127.0.0.1:8092/api", NODE = "http://127.0.0.1:8093";
async function paidFixture() {
  const f = await executionFixture(), execution = await f.prepare();
  await execution.accept(f.assertCurrent); const plan = await execution.planPayment(f.payer, NODE, 10n, f.assertCurrent);
  await execution.pay(f.payer, plan, NODE, f.assertCurrent); return { f, execution };
}
test("secrets precede firm request, durable authenticated terms precede acceptance/invoice exposure, payment precedes one dispatch", async () => {
  const f = await executionFixture(), e = await f.prepare();
  expect(f.events).toEqual(["secrets-ready", "send:quote_request", "terms-ready"]);
  expect(Object.keys(e)).not.toContain("holdInvoice"); await expect(e.planPayment(f.payer, NODE, 10n, f.assertCurrent)).rejects.toThrow();
  const plaintext = await f.decrypt(e.recoveryFile); try { expect(inspectReverseRecoveryPlaintext(plaintext, f.request.network).fundingHistory).toEqual([]); } finally { plaintext.fill(0); }
  await e.accept(f.assertCurrent); await expect(e.accept(f.assertCurrent)).rejects.toThrow();
  const plan = await e.planPayment(f.payer, NODE, 10n, f.assertCurrent); expect(f.events).toContain("plan");
  expect(await e.pay(f.payer, plan, NODE, f.assertCurrent)).toBe("IN_FLIGHT");
  expect(f.events.slice(-2)).toEqual(["payment-unknown", "payment-post"]); await expect(e.pay(f.payer, plan, NODE, f.assertCurrent)).rejects.toThrow(); e.dispose();
});
test("the default path exposes the authenticated invoice after acceptance, journals it first, and excludes the node path", async () => {
  const f = await executionFixture(), e = await f.prepare();
  await expect(e.exposeInvoice(f.assertCurrent)).rejects.toThrow(); // acceptance first
  await e.accept(f.assertCurrent);
  const exposure = await e.exposeInvoice(f.assertCurrent);
  expect(f.events.slice(-1)).toEqual(["payment-unknown"]); expect(f.record.payment).toMatchObject({ state: "external-wallet", paymentHash: f.terms.invoice_binding.payment_hash });
  expect(exposure.bolt11.startsWith("lnbcrt")).toBe(true); expect(exposure.expiresAt).toBe(f.terms.invoice_binding.expires_at);
  // The invoice is the one bound by the signed terms, so the wallet pays the hash whose preimage this page holds.
  expect(f.record.payment?.state === "external-wallet" && f.record.payment.invoiceBinding).toEqual(f.terms.invoice_binding);
  await expect(e.exposeInvoice(f.assertCurrent)).rejects.toThrow(); // shown once
  await expect(e.planPayment(f.payer, NODE, 10n, f.assertCurrent)).rejects.toThrow(); expect(f.events).not.toContain("plan");
  const file = await e.receiveFunding(); expect(f.events.slice(-1)).toEqual(["funded"]); expect(file.length).toBeGreaterThan(0); e.dispose();
});
test("a storage refusal while exposing the invoice keeps it private", async () => {
  const f = await executionFixture(), e = await f.prepare(); await e.accept(f.assertCurrent); f.fail = "payment-unknown";
  await expect(e.exposeInvoice(f.assertCurrent)).rejects.toThrow("storage unavailable");
  await expect(e.receiveFunding()).rejects.toThrow(); e.dispose();
});
for (const stage of ["secrets-ready", "terms-ready"]) {
  test(`storage refusal at ${stage} prevents later external effects`, async () => {
    const f = await executionFixture(); f.fail = stage; await expect(f.prepare()).rejects.toThrow();
    expect(f.events).not.toContain("send:terms_accept"); expect(f.events).not.toContain("payment-post");
    if (stage === "secrets-ready") expect(f.events).not.toContain("send:quote_request"); expect(f.session.secret.every((x) => x === 0)).toBe(true);
  });
}
test("lost payment commitment approval preserves UNKNOWN but dispatches nothing and never retries", async () => {
  const f = await executionFixture(), e = await f.prepare(); await e.accept(f.assertCurrent);
  const plan = await e.planPayment(f.payer, NODE, 10n, f.assertCurrent); f.callback = (stage) => { if (stage === "payment-unknown") f.approved = false; };
  await expect(e.pay(f.payer, plan, NODE, f.assertCurrent)).rejects.toThrow(); expect(f.record.stage).toBe("payment-unknown"); expect(f.events).not.toContain("payment-post");
  f.approved = true; await expect(e.pay(f.payer, plan, NODE, f.assertCurrent)).rejects.toThrow(); e.dispose();
});
test("authenticated funding is independently durable before fallback, payment UNKNOWN persists and one broadcast is elected", async () => {
  const { f, execution: e } = await paidFixture(), transport = spyOn(globalThis, "fetch").mockImplementation(f.fetch);
  try {
    const fundedFile = await e.receiveFunding(), funded = await f.decrypt(fundedFile);
    expect(f.record.stage).toBe("funded"); expect(f.record.payment?.state).toBe("submission-unknown");
    const result = await e.prepareClaim(API, 100n, f.assertCurrent); expect(result.claim.outputValueSat).toBe("50900"); expect(result.claim).not.toHaveProperty("transactionHex");
    const fallback = await f.decrypt(result.recoveryFile); expect(inspectReverseRecoveryPlaintext(fallback, f.request.network).fallbackTxid).toBe(result.claim.txid);
    expect(inspectReverseRecoveryPlaintext(funded, f.request.network).fallbackTxid).toBeNull(); funded.fill(0); fallback.fill(0);
    expect((await e.exposeClaim(API, BROADCAST, "broadcast", f.assertCurrent)).outcome).toBe("accepted"); expect(f.posts).toBe(1); expect(f.record.stage).toBe("accepted");
    await expect(e.exposeClaim(API, BROADCAST, "broadcast", f.assertCurrent)).rejects.toThrow(); expect(f.posts).toBe(1);
  } finally { transport.mockRestore(); e.dispose(); }
});
for (const state of ["spent", "margin", "approval", "storage"]) {
  test(`claim refuses ${state} without exposing a preimage or permitting another signing attempt`, async () => {
    const { f, execution: e } = await paidFixture(), transport = spyOn(globalThis, "fetch").mockImplementation(f.fetch);
    await e.receiveFunding(); if (state === "spent") f.spent = true; if (state === "margin") f.tipHeight = 219;
    if (state === "approval") f.approved = false; if (state === "storage") f.fail = "claim-ready";
    const sign = spyOn(schnorr, "sign");
    try {
      await expect(e.prepareClaim(API, 100n, f.assertCurrent)).rejects.toThrow(); expect(f.posts).toBe(0);
      if (state !== "storage") expect(sign).not.toHaveBeenCalled(); else expect(sign).toHaveBeenCalledTimes(1);
      f.approved = true; await expect(e.exposeClaim(API, BROADCAST, "broadcast", f.assertCurrent)).rejects.toThrow(); expect(f.posts).toBe(0);
    } finally { sign.mockRestore(); transport.mockRestore(); e.dispose(); }
  });
}
test("exposure readback/approval failure never dispatches and is not replayable", async () => {
  const { f, execution: e } = await paidFixture(), transport = spyOn(globalThis, "fetch").mockImplementation(f.fetch);
  try {
    await e.receiveFunding(); await e.prepareClaim(API, 100n, f.assertCurrent);
    f.callback = (stage) => { if (stage === "claim-unknown") f.approved = false; };
    expect((await e.exposeClaim(API, BROADCAST, "broadcast", f.assertCurrent)).outcome).toBe("unknown"); expect(f.record.stage).toBe("claim-unknown"); expect(f.posts).toBe(0);
    f.approved = true; await expect(e.exposeClaim(API, BROADCAST, "broadcast", f.assertCurrent)).rejects.toThrow(); expect(f.posts).toBe(0);
  } finally { transport.mockRestore(); e.dispose(); }
});
test("a downloaded claim cannot later acquire POST authority", async () => {
  const { f, execution: e } = await paidFixture(), transport = spyOn(globalThis, "fetch").mockImplementation(f.fetch);
  try {
    await e.receiveFunding(); await e.prepareClaim(API, 100n, f.assertCurrent);
    const exported = await e.exposeClaim(API, BROADCAST, "download", f.assertCurrent); expect(exported.transactionHex).toBeDefined(); expect(exported.outcome).toBe("exported");
    await expect(e.exposeClaim(API, BROADCAST, "broadcast", f.assertCurrent)).rejects.toThrow(); expect(f.posts).toBe(0);
    expect((await e.exposeClaim(API, BROADCAST, "download", f.assertCurrent)).transactionHex).toBe(exported.transactionHex); expect(f.posts).toBe(0);
  } finally { transport.mockRestore(); e.dispose(); }
});

test("the journal and approval bind the actual immutable payer endpoint", async () => {
  const f = await executionFixture(), e = await f.prepare(); await e.accept(f.assertCurrent);
  await expect(e.planPayment(f.payer, "http://127.0.0.1:9000", 10n, f.assertCurrent)).rejects.toThrow(); expect(f.events).not.toContain("plan");
  const plan = await e.planPayment(f.payer, NODE, 10n, f.assertCurrent);
  await expect(e.pay(f.payer, plan, "http://127.0.0.1:9000", f.assertCurrent)).rejects.toThrow(); expect(f.events).not.toContain("payment-unknown");
  await e.pay(f.payer, plan, NODE, f.assertCurrent); expect(f.record.payment?.state === "submission-unknown" && f.record.payment.endpoint).toBe(f.payer.endpoint); e.dispose();
});
test("payment election committed then rejected readback never renews dispatch authority", async () => {
  const f = await executionFixture(), e = await f.prepare(); await e.accept(f.assertCurrent);
  const plan = await e.planPayment(f.payer, NODE, 10n, f.assertCurrent); f.rejectReadback = "payment-unknown";
  await expect(e.pay(f.payer, plan, NODE, f.assertCurrent)).rejects.toThrow(); expect(f.record.stage).toBe("payment-unknown");
  f.rejectReadback = ""; await expect(e.pay(f.payer, plan, NODE, f.assertCurrent)).rejects.toThrow(); expect(f.events).not.toContain("payment-post"); e.dispose();
});
test("claim election committed then rejected readback never renews exposure or signing authority", async () => {
  const { f, execution: e } = await paidFixture(), transport = spyOn(globalThis, "fetch").mockImplementation(f.fetch);
  try {
    await e.receiveFunding(); await e.prepareClaim(API, 100n, f.assertCurrent); f.rejectReadback = "claim-unknown";
    await expect(e.exposeClaim(API, BROADCAST, "broadcast", f.assertCurrent)).rejects.toThrow(); expect(f.record.stage).toBe("claim-unknown");
    f.rejectReadback = ""; await expect(e.exposeClaim(API, BROADCAST, "broadcast", f.assertCurrent)).rejects.toThrow();
    const sign = spyOn(schnorr, "sign"); try { await expect(e.prepareClaim(API, 100n, f.assertCurrent)).rejects.toThrow(); expect(sign).not.toHaveBeenCalled(); } finally { sign.mockRestore(); }
    expect(f.posts).toBe(0);
  } finally { transport.mockRestore(); e.dispose(); }
});

for (const cooperation of ["signed", "declined", "bad partial"] as const) {
  test(`reverse ${cooperation} cooperation preserves the fallback and elects one claim broadcast`, async () => {
    const f = await executionFixture(cooperation), e = await f.prepare(), transport = spyOn(globalThis, "fetch").mockImplementation(f.fetch);
    try {
      await e.accept(f.assertCurrent); await e.exposeInvoice(f.assertCurrent); await e.receiveFunding();
      const prepared = await e.prepareClaim(API, 100n, f.assertCurrent);
      const result = await e.exposeClaim(API, BROADCAST, "broadcast", f.assertCurrent);
      expect(result.outcome).toBe("accepted"); expect(result.txid).toBe(prepared.claim.txid); expect(f.posts).toBe(1);
      expect(parseTransaction(hexToBytes(f.postedTransactions[0]!)).inputs[0]!.witness).toHaveLength(cooperation === "signed" ? 1 : 4);
      expect(f.events.indexOf("claim-ready")).toBeLessThan(f.events.indexOf("cooperation-burn"));
      expect(f.events.indexOf("cooperation-burn")).toBeLessThan(f.events.indexOf("cooperation-nonce"));
      if (cooperation === "signed") expect(f.events).toContain("action:cooperative_claim_complete");
      else expect(f.events).not.toContain("action:cooperative_claim_complete");
      // Recovery exports the durable script-path witness even after a key-path POST with the same txid.
      const fallback = await e.exposeClaim(API, BROADCAST, "download", f.assertCurrent);
      expect(fallback.txid).toBe(result.txid); expect(parseTransaction(hexToBytes(fallback.transactionHex!)).inputs[0]!.witness).toHaveLength(4);
      await expect(e.exposeClaim(API, BROADCAST, "broadcast", f.assertCurrent)).rejects.toThrow(); expect(f.posts).toBe(1);
    } finally { transport.mockRestore(); e.dispose(); }
  });
}

for (const [cooperation, expected] of [["signed", "the provider cosigned; claiming with the private key-path transaction"],
  ["declined", "the provider declined; claiming with the signed script-path transaction"]] as const) {
  test(`the swap log names the ${cooperation} cooperation outcome`, async () => {
    const f = await executionFixture(cooperation), lines: string[] = [], e = await f.prepare({ report: (line) => lines.push(line) });
    const transport = spyOn(globalThis, "fetch").mockImplementation(f.fetch);
    try {
      await e.accept(f.assertCurrent); await e.exposeInvoice(f.assertCurrent); await e.receiveFunding();
      await e.prepareClaim(API, 100n, f.assertCurrent);
      expect((await e.exposeClaim(API, BROADCAST, "broadcast", f.assertCurrent)).outcome).toBe("accepted");
      expect(lines).toEqual([`cooperation: ${expected}`]);
    } finally { transport.mockRestore(); e.dispose(); }
  });
}

test("cooperation still runs when the lockup confirms long after the quote deadline", async () => {
  const f = await executionFixture("signed"), e = await f.prepare(), transport = spyOn(globalThis, "fetch").mockImplementation(f.fetch);
  const proposals: Record<string, unknown>[] = [], send = f.session.send.bind(f.session);
  f.session.send = async (envelope, key, authorize) => {
    if (envelope.payload.action === "cooperative_claim_propose") proposals.push(envelope.payload);
    return send(envelope, key, authorize);
  };
  try {
    await e.accept(f.assertCurrent); await e.exposeInvoice(f.assertCurrent);
    // Two confirmations take minutes to an hour; the terms (80 s) and the page's quote deadline are long gone.
    f.now.seconds += 3600; expect(f.now.seconds).toBeGreaterThan(e.deadlineAt);
    await e.receiveFunding(); await e.prepareClaim(API, 100n, f.assertCurrent);
    const result = await e.exposeClaim(API, BROADCAST, "broadcast", f.assertCurrent);
    expect(proposals).toHaveLength(1); expect(proposals[0]!.deadline_at).toBe(f.now.seconds + 30);
    expect(result.outcome).toBe("accepted"); expect(f.posts).toBe(1);
    expect(parseTransaction(hexToBytes(f.postedTransactions[0]!)).inputs[0]!.witness).toHaveLength(1);
  } finally { transport.mockRestore(); e.dispose(); }
});

test("a transient post-cooperation read retries the fallback without another proposal or POST authority", async () => {
  const f = await executionFixture("signed"), e = await f.prepare(), transport = spyOn(globalThis, "fetch").mockImplementation(f.fetch);
  try {
    await e.accept(f.assertCurrent); await e.exposeInvoice(f.assertCurrent); await e.receiveFunding();
    await e.prepareClaim(API, 100n, f.assertCurrent); f.failFreshAfterCooperation = true;
    await expect(e.exposeClaim(API, BROADCAST, "broadcast", f.assertCurrent)).rejects.toThrow();
    expect(e.record.stage).toBe("claim-ready"); expect(f.posts).toBe(0);
    expect((await e.exposeClaim(API, BROADCAST, "broadcast", f.assertCurrent)).outcome).toBe("accepted");
    expect(parseTransaction(hexToBytes(f.postedTransactions[0]!)).inputs[0]!.witness).toHaveLength(4);
    expect(f.events.filter((event) => event === "action:cooperative_claim_propose")).toHaveLength(1);
    expect(f.events.filter((event) => event === "cooperation-nonce")).toHaveLength(1);
    expect(f.posts).toBe(1);
  } finally { transport.mockRestore(); e.dispose(); }
});
