import { expect, spyOn, test } from "bun:test";
import { schnorr } from "@noble/curves/secp256k1.js";
import { executionFixture } from "./fixtures/reverseExecutionFixture";
import { inspectReverseRecoveryPlaintext } from "../src/recoveryInspection";

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
  await e.pay(f.payer, plan, NODE, f.assertCurrent); expect(f.record.payment?.endpoint).toBe(f.payer.endpoint); e.dispose();
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
