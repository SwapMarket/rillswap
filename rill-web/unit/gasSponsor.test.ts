import { describe, expect, test } from "bun:test";
import { hexToBytes } from "@noble/hashes/utils.js";
import { EvmRpc } from "../src/swap/evmHtlc";
import {
  GasSponsor, SPONSOR_ABI, authorizationDigest, eip191Digest, encodeExecuteBatch, newStagingSecret, signDigest, signPreparedCalls,
  stagingAddress, userOpHash, verifyPreparedCalls, type PreparedExpectation, type SponsorConfig,
} from "../src/swap/gasSponsor";
import vectors from "./fixtures/gasSponsorVectors.json";

const secret = hexToBytes(vectors.secret.slice(2));
const config: SponsorConfig = { url: "http://sponsor.test/", chainId: vectors.chainId, entryPoint: vectors.entryPoint, delegate: vectors.delegate };
const expectation = (overrides: Partial<PreparedExpectation> = {}): PreparedExpectation => ({
  sender: vectors.address, callData: vectors.callData, authorizationNonce: 7n, accountSequence: async (key) => (key === 1n ? 0n : 99n), ...overrides,
});
const prepared = (op: Record<string, unknown> = vectors.userOp, auth = true): Record<string, unknown> => {
  const opEntry = { type: "user-operation-v070", chainId: "0x7a69", data: op, signatureRequest: { type: "personal_sign", data: { raw: userOpHash(vectors.entryPoint, vectors.chainId, op as never) } }, feePayment: { sponsored: true, tokenAddress: "0x0000000000000000000000000000000000000000", maxAmount: "0x0" } };
  if (!auth) return opEntry;
  return { type: "array", data: [
    { type: "authorization", chainId: "0x7a69", data: { address: vectors.delegate, nonce: "0x7" }, signatureRequest: { type: "eip7702Auth", rawPayload: vectors.authorization.digest } },
    opEntry,
  ] };
};

describe("gas sponsor primitives (vectors from eth-account/eth-abi)", () => {
  test("staging address and selectors", () => {
    expect(stagingAddress(secret)).toBe(vectors.address);
    expect(SPONSOR_ABI.executeBatch).toBe("34fcd5be");
    expect(stagingAddress(newStagingSecret())).toMatch(/^0x[0-9a-f]{40}$/);
  });
  test("executeBatch encoding matches eth-abi", () => {
    expect(encodeExecuteBatch(vectors.calls)).toBe(vectors.callData);
    expect(() => encodeExecuteBatch([])).toThrow("empty call batch");
  });
  test("EIP-7702 authorization digest and raw signature", () => {
    const digest = authorizationDigest({ chainId: vectors.chainId, address: vectors.delegate, nonce: 7n });
    expect(digest).toBe(vectors.authorization.digest);
    expect(signDigest(secret, digest)).toBe(vectors.authorization.signature);
    expect(() => authorizationDigest({ chainId: 0, address: vectors.delegate, nonce: 0n })).toThrow("positive integer");
  });
  test("EntryPoint v0.7 user operation hash, with and without a paymaster", () => {
    expect(userOpHash(vectors.entryPoint, vectors.chainId, vectors.userOp)).toBe(vectors.userOpHash);
    expect(userOpHash(vectors.entryPoint, vectors.chainId, vectors.sponsoredUserOp)).toBe(vectors.sponsoredUserOpHash);
    expect(userOpHash(vectors.entryPoint, 1, vectors.userOp)).not.toBe(vectors.userOpHash);
  });
  test("EIP-191 signature over the user operation hash", () => {
    expect(signDigest(secret, eip191Digest(vectors.userOpHash))).toBe(vectors.userOpSignature);
  });
});

describe("prepared-call verification", () => {
  test("accepts the exact user operation plus the required delegation and signs both", async () => {
    const verified = await verifyPreparedCalls(config, prepared(), expectation());
    expect(verified.userOpHash).toBe(vectors.userOpHash);
    expect(verified.authorization?.digest).toBe(vectors.authorization.digest);
    expect(verified.sponsored).toBe(true);
    const signed = signPreparedCalls(verified, secret) as { type: string; data: { type: string; signature: { data: string } }[] };
    expect(signed.type).toBe("array");
    expect(signed.data[0]!.signature.data).toBe(vectors.authorization.signature);
    expect(signed.data[1]!.signature.data).toBe(vectors.userOpSignature);
  });
  test("accepts a bare user operation when the account is already delegated", async () => {
    const verified = await verifyPreparedCalls(config, prepared(vectors.userOp, false), expectation({ authorizationNonce: null }));
    expect(verified.authorization).toBeNull();
    expect((signPreparedCalls(verified, secret) as { type: string }).type).toBe("user-operation-v070");
  });
  test("accepts the executeUserOp wrapper around the same batch", async () => {
    const op = { ...vectors.userOp, callData: `0x${SPONSOR_ABI.executeUserOp}${vectors.callData.slice(2)}` };
    await expect(verifyPreparedCalls(config, prepared(op), expectation())).resolves.toBeDefined();
  });
  const rejects = async (result: unknown, message: string, overrides: Partial<PreparedExpectation> = {}): Promise<void> => {
    await expect(verifyPreparedCalls(config, result, expectation(overrides))).rejects.toThrow(message);
  };
  test("rejects changed calls, sender, deployment code, or a stale nonce", async () => {
    await rejects(prepared({ ...vectors.userOp, callData: `${vectors.callData}00` }), "changed the calls");
    await rejects(prepared({ ...vectors.userOp, sender: vectors.delegate }), "sender");
    await rejects(prepared({ ...vectors.userOp, factory: vectors.delegate, factoryData: "0x01" }), "deployment code");
    await rejects(prepared({ ...vectors.userOp, nonce: "0x10000000000000001" }), "stale account nonce");
    await rejects(prepared({ ...vectors.userOp, nonce: "0x0" }), "stale account nonce"); // key 0 sequence is 99 in the fake
  });
  test("rejects an operation the account would pay for", async () => {
    await rejects(prepared({ ...vectors.userOp, maxFeePerGas: "0x1" }), "not paying for gas");
    await expect(verifyPreparedCalls(config, prepared(vectors.sponsoredUserOp), expectation())).resolves.toBeDefined();
    // A token paymaster would charge the account, which holds the payout.
    const charged = prepared(vectors.sponsoredUserOp, false);
    await rejects({ ...charged, feePayment: { sponsored: false, tokenAddress: `0x${"12".repeat(20)}`, maxAmount: "0x10" } }, "not paying for gas");
  });
  test("tolerates Alchemy's extra metadata fields", async () => {
    const op = prepared(vectors.userOp, false);
    const extra = { ...op, details: { type: "user-operation", data: { hash: "0x00", calls: [] } },
      signatureRequest: { ...(op.signatureRequest as Record<string, unknown>), rawPayload: `0x${"55".repeat(32)}` } };
    await expect(verifyPreparedCalls(config, extra, expectation({ authorizationNonce: null }))).resolves.toBeDefined();
  });
  test("rejects wrong chains, foreign signature requests, and delegation mismatches", async () => {
    const wrongChain = prepared() as { data: Record<string, unknown>[] };
    wrongChain.data[1] = { ...wrongChain.data[1], chainId: "0x1" };
    await rejects(wrongChain, "another chain");
    const typed = prepared() as { data: Record<string, unknown>[] };
    typed.data[1] = { ...typed.data[1], signatureRequest: { type: "eth_signTypedData_v4", data: {} } };
    await rejects(typed, "something other than the user operation");
    const swapped = prepared() as { data: Record<string, unknown>[] };
    swapped.data[1] = { ...swapped.data[1], signatureRequest: { type: "personal_sign", data: { raw: vectors.sponsoredUserOpHash } } };
    await rejects(swapped, "something other than the user operation");
    const otherDelegate = prepared() as { data: Record<string, unknown>[] };
    otherDelegate.data[0] = { ...otherDelegate.data[0], data: { address: vectors.address, nonce: "0x7" } };
    await rejects(otherDelegate, "another delegate");
    const otherNonce = prepared() as { data: Record<string, unknown>[] };
    otherNonce.data[0] = { ...otherNonce.data[0], data: { address: vectors.delegate, nonce: "0x8" } };
    await rejects(otherNonce, "another delegate");
    const anyChain = prepared() as { data: Record<string, unknown>[] };
    anyChain.data[0] = { ...anyChain.data[0], chainId: "0x0" };
    await rejects(anyChain, "another delegate");
    const badPayload = prepared() as { data: Record<string, unknown>[] };
    badPayload.data[0] = { ...badPayload.data[0], signatureRequest: { type: "eip7702Auth", rawPayload: vectors.userOpHash } };
    await rejects(badPayload, "does not match the pinned delegation");
    await rejects(prepared(), "does not need", { authorizationNonce: null });
    await rejects(prepared(vectors.userOp, false), "did not include the required delegation");
    await rejects({ type: "array", data: [prepared(vectors.userOp, false), prepared(vectors.userOp, false)] }, "unexpected set");
    await rejects({ type: "user-operation-v060", data: vectors.userOp, chainId: "0x7a69" }, "unexpected set");
  });
});

describe("GasSponsor client", () => {
  const rpcAnswers: Record<string, unknown> = {
    eth_getCode: "0x", eth_getTransactionCount: "0x7", eth_call: "0x0000000000000000000000000000000000000001" + "0".repeat(16),
  };
  const fakeFetch = (handler: (method: string, params: unknown[]) => unknown) => async (_url: string, init: RequestInit): Promise<Response> => {
    const { method, params } = JSON.parse(init.body as string) as { method: string; params: unknown[] };
    const result = handler(method, params);
    return new Response(JSON.stringify(result instanceof Error ? { error: { message: result.message } } : { result }), { status: 200 });
  };
  const rpc = new EvmRpc("http://rpc.test/", fakeFetch((method) => rpcAnswers[method]));

  test("submits a verified, signed batch and reports the sponsor's call id", async () => {
    const seen: { method: string; params: unknown[] }[] = [];
    const sponsor = new GasSponsor(config, fakeFetch((method, params) => {
      seen.push({ method, params });
      if (method === "wallet_prepareCalls") return prepared();
      if (method === "wallet_sendPreparedCalls") return { preparedCallIds: ["call-1"] };
      if (method === "wallet_getCallsStatus") return { status: 200, receipts: [{ transactionHash: `0x${"ab".repeat(32)}` }] };
      return new Error("unexpected");
    }));
    const { callId, userOpHash: hash } = await sponsor.submit(rpc, secret, vectors.calls);
    expect(callId).toBe("call-1"); expect(hash).toBe(vectors.userOpHash);
    const request = (seen[0]!.params[0] as { from: string; chainId: string; calls: unknown[]; capabilities: unknown });
    expect(request.from).toBe(vectors.address); expect(request.chainId).toBe("0x7a69"); expect(request.calls).toHaveLength(2);
    expect(request.capabilities).toEqual({ eip7702Auth: true });  // a proxy applies its own policy
    const sent = seen[1]!.params[0] as { type: string; data: { signature: { data: string } }[] };
    expect(sent.data[1]!.signature.data).toBe(vectors.userOpSignature);
    await expect(sponsor.awaitInclusion("call-1")).resolves.toBe("ab".repeat(32));
  });
  test("refuses a staging account delegated elsewhere and reports sponsor failures", async () => {
    const sponsor = new GasSponsor(config, fakeFetch((method) => (method === "wallet_getCallsStatus" ? { status: 500 } : new Error("down"))));
    const foreign = new EvmRpc("http://rpc.test/", fakeFetch(() => "0xef0100" + vectors.address.slice(2)));
    await expect(sponsor.submit(foreign, secret, vectors.calls)).rejects.toThrow("unknown contract");
    await expect(sponsor.submit(rpc, secret, vectors.calls)).rejects.toThrow("down");
    await expect(sponsor.awaitInclusion("call-2")).rejects.toThrow("status 500");
    const delegated = new EvmRpc("http://rpc.test/", fakeFetch((method) => (method === "eth_getCode" ? "0xef0100" + vectors.delegate.slice(2) : rpcAnswers[method])));
    await expect(sponsor.delegationNonce(delegated, vectors.address)).resolves.toBeNull();
  });
  test("sends the configured Alchemy policy and prefers the current send result id", async () => {
    let capabilities: unknown;
    const policyId = "0b1e8f2a-3c4d-4e5f-8a9b-0c1d2e3f4a5b";
    const sponsor = new GasSponsor({ ...config, policyId }, fakeFetch((method, params) => {
      if (method === "wallet_prepareCalls") { capabilities = (params[0] as { capabilities: unknown }).capabilities; return prepared(); }
      if (method === "wallet_sendPreparedCalls") return { id: "call-new", preparedCallIds: ["call-old"] };
      return new Error("unexpected");
    }));
    await expect(sponsor.submit(rpc, secret, vectors.calls)).resolves.toMatchObject({ callId: "call-new" });
    expect(capabilities).toEqual({ eip7702Auth: true, paymasterService: { policyId } });
  });
  test("failed preconfirmations fail, preconfirmed keeps waiting for 200", async () => {
    for (const status of [115, 116, 400, 600]) {
      const sponsor = new GasSponsor(config, fakeFetch(() => ({ status, receipts: [{ transactionHash: `0x${"ab".repeat(32)}` }] })));
      await expect(sponsor.status("call")).resolves.toEqual({ state: "failed", status });
    }
    for (const status of [100, 110]) {
      await expect(new GasSponsor(config, fakeFetch(() => ({ status }))).status("call")).resolves.toEqual({ state: "pending" });
    }
  });
  test("pending status keeps polling until the deadline", async () => {
    const sponsor = new GasSponsor(config, fakeFetch(() => ({ status: 100 })));
    await expect(sponsor.awaitInclusion("call-3", { intervalMs: 1, timeoutMs: 5 })).rejects.toThrow("still pending");
  });
});
