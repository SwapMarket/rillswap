import { expect, test } from "bun:test";
import { Wallet } from "ethers";
import { ed25519 } from "@noble/curves/ed25519.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { createNativeSandboxCheckout, type NativeSandboxCheckpoint, type NativeSandboxWallet } from "../src/nativeSdk";
import { parseNativeSandboxTerms, signNativeSandboxReceipt, type NativeSandboxView } from "../src/nativeContract";
import type { CheckoutStore } from "../src/sdk";

function fixture() {
  const token = "0x" + "1".repeat(40), recipient = "0x" + "2".repeat(40), hash = "0x" + "8".repeat(64), genesis = "0x" + "0".repeat(64);
  const terms = parseNativeSandboxTerms({ version: "native-sandbox-checkout/1", merchantOrigin: "https://sandbox.invalid", intentId: "native_sdk_intent_001", attemptId: "native_sdk_attempt_01",
    asset: { id: `eip155:31337/erc20:${token}`, chainId: "31337", genesisHash: genesis, token, decimals: 6, behavior: "standard_erc20", runtimeCodeHash: "0x" + "3".repeat(64),
      implementation: null, historicalStateVerified: true, behaviorConformanceVerified: true, localSandbox: { version: "anvil-local/1", namespace: "native_sdk_fixture_01", confirmations: 6 } },
    recipient, amountBaseUnits: "1000000", createdAt: 1000, expiresAt: 2000 });
  const walletKey = new Wallet("0x" + "0".repeat(63) + "1"), signingKey = new Uint8Array(32).fill(5);
  const records = new Map<string, NativeSandboxCheckpoint>(), operations = new Map<string, string>();
  const store: CheckoutStore<NativeSandboxCheckpoint> = { load: async (id) => records.get(id) ?? null,
    begin: async (record) => { if (records.has(record.attemptId)) return false; records.set(record.attemptId, structuredClone(record)); return true; },
    update: async (record) => { records.set(record.attemptId, structuredClone(record)); } };
  let now = 1100, walletCalls = 0, dispatches = 0, serverPreparation: string | null = null, lostResponse = false, nonce = "2";
  let beforeDispatch: (() => void) | null = null;
  let current: NativeSandboxView = { version: "native-sandbox-view/1", terms, status: "awaiting_funds", evidence: "none_recorded", receipt: null, event: null };
  const hints: string[] = [];
  const wallet: NativeSandboxWallet = { version: "native-sandbox-wallet/1", durableOperationIdentity: true, guardedFeeCaps: true,
    identity: async () => { walletCalls++; return { chainId: "31337", genesisHash: genesis, sourceWallet: walletKey.address.toLowerCase(), sourceNonce: nonce }; },
    signBinding: async (_operationId, _binding, typed) => { walletCalls++; return walletKey.signTypedData(typed.domain, typed.types, typed.value); },
    dispatch: async (id, request, guard) => { beforeDispatch?.(); await guard("sign"); await guard("broadcast"); dispatches++;
      expect(request.value).toBe("0"); expect(request.to).toBe(token); expect(request.nonce).toBe(2); expect(request.maxFeePerGasWei).toBe("1");
      operations.set(id, hash); if (lostResponse) throw new Error("broadcast response lost"); return hash; },
    lookup: async (id) => operations.get(id) ?? null,
  };
  const request = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const url = String(input);
    if (url.endsWith("/prepare")) {
      const key = (init?.headers as Record<string, string>)["Idempotency-Key"]!;
      if (serverPreparation !== null && serverPreparation !== key) return Response.json({}, { status: 409 }); serverPreparation = key;
      const body = JSON.parse(init?.body as string);
      return Response.json({ version: "native-sandbox-preparation/1", terms, prepared: { ...body, preparedAt: now, preparedBlockNumber: 40, preparedBlockHash: "0x" + "4".repeat(64) } });
    }
    if (url.endsWith("/observe")) hints.push(JSON.parse(init?.body as string).txHash);
    return Response.json(current);
  };
  const options = { intentUrl: terms.merchantOrigin + "/v1/native-sandbox/intents/" + terms.intentId, paymentCapability: "payment_capability_fixture_000001", terms,
    merchantPublicKey: bytesToHex(ed25519.getPublicKey(signingKey)), maxTokenBaseUnits: "1000000", gasLimit: "100000", maxFeePerGasWei: "1", maxPriorityFeePerGasWei: "0", maxGasCostWei: "100000",
    wallet, recoveryStore: store, fetch: request, now: () => now };
  const recorded = () => {
    const receipt = { assetId: terms.asset.id, quantityBaseUnits: terms.amountBaseUnits, recipient, transactionHash: hash, logIndex: 7, deduplicationKey: `31337:${genesis}:sandbox:native_sdk_fixture_01:${hash}:7`,
      blockHash: "0x" + "6".repeat(64), blockNumber: 42, blockTimestamp: 1200, finality: "local_sandbox_confirmed" as const, timing: "timely" as const };
    current = { version: "native-sandbox-view/1", terms, status: "sandbox_receipt_recorded", evidence: "recorded_local_confirmations", receipt,
      event: signNativeSandboxReceipt({ version: "native-sandbox-event/1", type: "sandbox.receipt_recorded", scope: "local_sandbox_only", id: "native_sdk_event_0001", terms, receipt, recordedAt: 1300 }, signingKey) };
  };
  return { options, records, operations, store, hints, hash, walletCalls: () => walletCalls, dispatches: () => dispatches, recorded,
    setView: (value: NativeSandboxView) => { current = value; }, getView: () => current,
    clock: (value: number) => { now = value; }, advanceNonce: () => { nonce = "3"; }, loseResponse: () => { lostResponse = true; }, beforeDispatch: (callback: () => void) => { beforeDispatch = callback; } };
}
test("native atomic reservation permits one cross-client dispatch, never payment from wallet success", async () => {
  const f = fixture(), first = createNativeSandboxCheckout(f.options), second = createNativeSandboxCheckout(f.options);
  expect((await first.open()).recovery).toBe("explicit_payment_required"); expect(f.walletCalls()).toBe(0);
  const results = await Promise.allSettled([first.pay(), second.pay()]); expect(results.filter((result) => result.status === "fulfilled")).toHaveLength(1);
  expect(f.dispatches()).toBe(1); expect(f.records.get(f.options.terms.attemptId)?.stage).toBe("observing");
  await expect(second.pay()).rejects.toThrow("reserved"); expect((await second.open()).view.status).toBe("awaiting_funds"); expect(f.dispatches()).toBe(1);
});
test("ambiguous publication recovers the same private operation after expiry and nonce advance without dispatch", async () => {
  const f = fixture(); f.loseResponse(); await expect(createNativeSandboxCheckout(f.options).pay()).rejects.toThrow("lost");
  const checkpoint = f.records.get(f.options.terms.attemptId)!; expect(checkpoint.stage).toBe("ambiguous"); expect(checkpoint.transactionHash).toBeNull();
  f.clock(3000); f.advanceNonce(); const client = createNativeSandboxCheckout(f.options); const recovered = await client.open();
  expect(recovered.recovery).toBe("tracking"); expect(f.hints).toEqual([f.hash]); expect(f.dispatches()).toBe(1);
  expect(f.records.get(checkpoint.attemptId)).toEqual(checkpoint); await expect(client.pay()).rejects.toThrow();
});
test("erased browser metadata cannot bypass merchant preparation or trigger a second funded operation", async () => {
  const f = fixture(); await createNativeSandboxCheckout(f.options).pay(); f.records.clear();
  const recovered = createNativeSandboxCheckout(f.options); expect((await recovered.open()).recovery).toBe("explicit_payment_required");
  await expect(recovered.pay()).rejects.toThrow("refused"); expect(f.dispatches()).toBe(1); expect(f.records.get(f.options.terms.attemptId)?.stage).toBe("ambiguous");
});
test("checkpoint failure/expiry before authorization and delayed wallet commitment retain conservative reservations", async () => {
  const failed = fixture(); let writes = 0;
  const broken = { ...failed.store, begin: async () => { throw new Error("storage refused"); }, update: async () => { writes++; } };
  await expect(createNativeSandboxCheckout({ ...failed.options, recoveryStore: broken }).pay()).rejects.toThrow("storage refused"); expect(writes).toBe(0); expect(failed.walletCalls()).toBe(0);
  const expired = fixture(); const slowStore = { ...expired.store, begin: async (record: NativeSandboxCheckpoint) => { const result = await expired.store.begin(record); expired.clock(2000); return result; } };
  await expect(createNativeSandboxCheckout({ ...expired.options, recoveryStore: slowStore }).pay()).rejects.toThrow("deadline"); expect(expired.walletCalls()).toBe(0); expect(expired.records.get(expired.options.terms.attemptId)?.stage).toBe("ambiguous");
  const delayed = fixture(); delayed.beforeDispatch(() => delayed.clock(2000)); await expect(createNativeSandboxCheckout(delayed.options).pay()).rejects.toThrow("deadline"); expect(delayed.dispatches()).toBe(0);
});
test("old, partial or foreign checkpoint metadata remains reserved and never invokes the wallet", async () => {
  for (const bad of [{ version: "checkout-checkpoint/1" }, { version: "native-sandbox-checkpoint/0" }, { version: "native-sandbox-checkpoint/1", operationId: 1234567890123456 }]) {
    const f = fixture(); f.records.set(f.options.terms.attemptId, bad as unknown as NativeSandboxCheckpoint); const original = f.records.get(f.options.terms.attemptId);
    await expect(createNativeSandboxCheckout(f.options).open()).rejects.toThrow(); await expect(createNativeSandboxCheckout(f.options).pay()).rejects.toThrow();
    expect(f.records.get(f.options.terms.attemptId)).toBe(original!); expect(f.dispatches()).toBe(0); expect(f.walletCalls()).toBe(0);
  }
});
test("only an independently key-and-terms-bound signed local event can report sandbox receipt", async () => {
  const f = fixture(); f.recorded(); const client = createNativeSandboxCheckout(f.options); expect((await client.open()).view.status).toBe("sandbox_receipt_recorded");
  await expect(client.pay()).rejects.toThrow("not payable"); expect(f.dispatches()).toBe(0);
  const forged = f.getView(); f.setView({ ...forged, event: { ...forged.event!, publicKey: "1".repeat(64) } }); await expect(client.open()).rejects.toThrow("event");
  expect(() => createNativeSandboxCheckout({ ...f.options, maxGasCostWei: "1" })).toThrow("policy");
});
test("contradictory funding responses at load or commitment and mismatched signed/outer receipts fail closed", async () => {
  const initial = fixture(); initial.setView({ ...initial.getView(), evidence: "recorded_impairment" });
  await expect(createNativeSandboxCheckout(initial.options).pay()).rejects.toThrow("Contradictory"); expect(initial.walletCalls()).toBe(0);
  const delayed = fixture(); delayed.beforeDispatch(() => delayed.setView({ ...delayed.getView(), evidence: "recorded_impairment" }));
  await expect(createNativeSandboxCheckout(delayed.options).pay()).rejects.toThrow("Contradictory"); expect(delayed.dispatches()).toBe(0);
  const mismatch = fixture(); mismatch.recorded(); const current = mismatch.getView();
  mismatch.setView({ ...current, receipt: { ...current.receipt!, blockHash: "0x" + "7".repeat(64) } });
  await expect(createNativeSandboxCheckout(mismatch.options).open()).rejects.toThrow("event");
});
test("preparation binding equality ignores JSON property order but rejects changed debit identity", async () => {
  for (const change of [false, true]) {
    const f = fixture(); const reordered = async (input: RequestInfo | URL, init?: RequestInit) => {
      const response = await f.options.fetch(input, init); if (!String(input).endsWith("/prepare")) return response;
      const body = await response.json(); body.prepared.binding = Object.fromEntries(Object.entries(body.prepared.binding).reverse());
      if (change) body.prepared.binding.sourceNonce = "3"; return Response.json(body);
    };
    const client = createNativeSandboxCheckout({ ...f.options, fetch: reordered });
    if (change) { await expect(client.pay()).rejects.toThrow("mismatch"); expect(f.dispatches()).toBe(0); }
    else { await client.pay(); expect(f.dispatches()).toBe(1); }
  }
});
