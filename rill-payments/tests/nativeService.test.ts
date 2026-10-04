import { afterEach, expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { resolve } from "node:path";
import { ed25519 } from "@noble/curves/ed25519.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { Interface, Wallet, keccak256 } from "ethers";
import { NativeReceiptLedger } from "../src/nativeLedger";
import { createNativeSandboxService } from "../src/nativeServer";
import { parseNativeSandboxTerms, verifyNativeSandboxReceipt, type NativeSandboxTerms, type NativeSandboxView, type SignedNativeSandboxReceipt } from "../src/nativeContract";
import { receiptBindingTypedData, type EvmReader, type EvmReceiptBinding } from "../src/evmReceipt";

const cleanup: (() => void)[] = []; afterEach(() => { for (const close of cleanup.splice(0)) close(); });
const blockHash = (height: number): string => "0x" + height.toString(16).padStart(64, "0");
function fixture() {
  mkdirSync("tmp", { recursive: true }); const directory = mkdtempSync(resolve("tmp/native-api-")), path = directory + "/native.sqlite";
  const token = "0x" + "1".repeat(40), recipient = "0x" + "2".repeat(40), wallet = new Wallet("0x" + "0".repeat(63) + "1");
  const abi = new Interface(["function transfer(address,uint256) returns(bool)", "function decimals() view returns(uint8)", "event Transfer(address indexed from,address indexed to,uint256 value)"]);
  const config = { origin: "https://sandbox.invalid", recipient, inventoryCapBaseUnits: "10000000", asset: {
    id: `eip155:31337/erc20:${token}`, chainId: "31337", genesisHash: blockHash(0), token, decimals: 6, behavior: "standard_erc20" as const,
    runtimeCodeHash: keccak256("0x60016000"), implementation: null, historicalStateVerified: true as const, behaviorConformanceVerified: true as const,
    localSandbox: { version: "anvil-local/1" as const, namespace: "sandbox_api_fixture_01", confirmations: 6 as const },
  } };
  const ledger = NativeReceiptLedger.provision(path, config); cleanup.push(() => { ledger.close(); rmSync(directory, { recursive: true, force: true }); });
  const adminToken = "native_admin_secret_fixture_00001", capabilityKey = new Uint8Array(32).fill(1), eventSigningKey = new Uint8Array(32).fill(2);
  let now = 1100, receiptTime = 1200, head = 40, settled = false, rpcCalls = 0;
  const transactionHash = "0x" + "8".repeat(64), log = abi.encodeEventLog(abi.getEvent("Transfer")!, [wallet.address, recipient, 1000000n]);
  const provider: EvmReader = {
    getNetwork: async () => { rpcCalls++; return { chainId: 31337n }; }, getBlock: async (tag) => {
      rpcCalls++; if (tag === "finalized") throw new Error("Sandbox may not query finalized");
      if (tag === "latest") return { number: head, hash: blockHash(head), timestamp: head === 40 ? 1000 : 1300 };
      return { number: tag, hash: blockHash(tag), timestamp: tag === 0 ? 0 : tag === 40 ? 1000 : tag === 42 ? receiptTime : 1300 };
    }, getCode: async (account) => { rpcCalls++; return account === token ? "0x60016000" : "0x"; }, getStorage: async () => { rpcCalls++; return blockHash(0); },
    call: async () => { rpcCalls++; return abi.encodeFunctionResult("decimals", [6]); }, getTransactionCount: async () => { rpcCalls++; return 2; }, getLogs: async () => { rpcCalls++; return []; },
    getTransaction: async () => { rpcCalls++; return { hash: transactionHash, chainId: 31337n, nonce: 2, from: wallet.address, to: token, value: 0n, data: abi.encodeFunctionData("transfer", [recipient, 1000000n]) }; },
    getTransactionReceipt: async () => { rpcCalls++; return settled ? { hash: transactionHash, status: 1, blockHash: blockHash(42), blockNumber: 42, logs: [{ address: token, topics: log.topics, data: log.data, index: 7 }] } : null; },
  };
  const options = { ledger, provider, adminToken, capabilityKey, eventSigningKey, now: () => now };
  const service = createNativeSandboxService(options);
  const request = async (route: string, bearer = adminToken, method = "GET", body?: unknown, headers: Record<string, string> = {}) => service.fetch(new Request(config.origin + route,
    { method, headers: { Authorization: "Bearer " + bearer, ...(body === undefined ? {} : { "Content-Type": "application/json" }), ...headers }, body: body === undefined ? undefined : JSON.stringify(body) }));
  const create = async () => { const result = await request("/v1/native-sandbox/intents", adminToken, "POST", { orderRef: "sandbox-order-one", amountBaseUnits: "1000000", expiresAt: 2000 }, { "Idempotency-Key": "native_api_intent_01" });
    expect(result.status).toBe(201); return await result.json() as { view: NativeSandboxView; readCapability: string; paymentCapability: string }; };
  const sign = async (terms: NativeSandboxTerms) => {
    const binding: EvmReceiptBinding = { version: "evm-receipt-binding/1", merchantOrigin: terms.merchantOrigin, intentId: terms.intentId, attemptId: terms.attemptId, assetId: terms.asset.id,
      sourceWallet: wallet.address.toLowerCase(), sourceNonce: "2", recipient, amountBaseUnits: terms.amountBaseUnits, validAfter: terms.createdAt, validBefore: terms.expiresAt };
    const typed = receiptBindingTypedData(config.asset, binding); return { binding, signature: await wallet.signTypedData(typed.domain, typed.types, typed.value) };
  };
  return { ledger, config, options, service, request, create, sign, transactionHash, publicKey: bytesToHex(ed25519.getPublicKey(eventSigningKey)), rpcCalls: () => rpcCalls,
    settle: (late = false) => { settled = true; head = 47; now = late ? 2100 : 1300; if (late) receiptTime = 2000; },
    open: () => { const reopened = NativeReceiptLedger.open(path, config); cleanup.unshift(() => reopened.close()); return createNativeSandboxService({ ...options, ledger: reopened }); } };
}

test("native mounting rejects canonical ledgers, missing private keys and unpinned transports", () => {
  const f = fixture();
  expect(() => createNativeSandboxService({ ...f.options, transportOrigin: "http://merchant.example" })).toThrow("transport");
  expect(() => createNativeSandboxService({ ...f.options, capabilityKey: new Uint8Array(0) })).toThrow("private keys");
  expect(() => createNativeSandboxService({ ...f.options, ledger: { config: { ...f.config, asset: { ...f.config.asset, chainId: "11155111", localSandbox: undefined } } } as NativeReceiptLedger })).toThrow();
});
test("admin creation is idempotent; read and payment capabilities are distinct and scope one intent", async () => {
  const f = fixture(), created = await f.create(), repeated = await f.create(); expect(repeated).toEqual(created);
  expect(created.readCapability).not.toBe(created.paymentCapability); const path = "/v1/native-sandbox/intents/" + created.view.terms.intentId;
  expect((await f.request(path, created.readCapability)).status).toBe(200);
  expect((await f.request(path + "other", created.readCapability)).status).toBe(404);
  const denied = await f.request(path + "/prepare", created.readCapability, "POST", { binding: {} }); expect(denied.status).toBe(403); expect(f.rpcCalls()).toBe(0);
  for (const bearer of [created.readCapability, f.options.adminToken]) for (const action of ["prepare", "observe"]) {
    expect((await f.request(path + "/" + action, bearer, "POST", {})).status).toBe(403);
  }
  expect(f.rpcCalls()).toBe(0);
  expect((await f.request("/v1/native-sandbox/intents", created.paymentCapability, "POST", {})).status).toBe(401);
  const status = await (await f.request(path, created.paymentCapability)).json(); expect(JSON.stringify(status)).not.toContain(created.paymentCapability); expect(JSON.stringify(status)).not.toContain(created.readCapability);
});
test("authenticated prebinding and receipt hints produce only sandbox-specific signed historical evidence", async () => {
  const f = fixture(), created = await f.create(), path = "/v1/native-sandbox/intents/" + created.view.terms.intentId, signed = await f.sign(created.view.terms);
  const prepared = await f.request(path + "/prepare", created.paymentCapability, "POST", signed, { "Idempotency-Key": "native_api_prepare_01" }); expect(prepared.status).toBe(201);
  expect(f.ledger.inventory().reserved).toBe("1000000");
  expect((await f.request(path + "/observe", created.paymentCapability, "POST", { txHash: f.transactionHash, accepted: true })).status).toBe(400);
  const pending = await (await f.request(path + "/observe", created.paymentCapability, "POST", { txHash: f.transactionHash })).json() as NativeSandboxView;
  expect(pending.status).toBe("awaiting_funds"); expect(pending.event).toBeNull(); f.settle();
  const recorded = await (await f.request(path + "/observe", created.paymentCapability, "POST", { txHash: f.transactionHash })).json() as NativeSandboxView;
  expect(recorded.status).toBe("sandbox_receipt_recorded"); expect(recorded.receipt?.finality).toBe("local_sandbox_confirmed"); expect(recorded.event?.event.scope).toBe("local_sandbox_only");
  expect(verifyNativeSandboxReceipt(recorded.event!, f.publicKey, created.view.terms)).toBe(true);
  f.ledger.acknowledgeEvent(recorded.event!.event.id); expect(f.ledger.pendingEvents()).toHaveLength(0);
  const reopened = f.open(), status = await reopened.fetch(new Request(f.config.origin + path, { headers: { Authorization: "Bearer " + created.readCapability } }));
  expect((await status.json() as NativeSandboxView).event).toEqual(recorded.event);
  expect(JSON.stringify(recorded)).not.toContain(signed.signature); expect(JSON.stringify(recorded)).not.toContain("sourceNonce");
  f.ledger.recordReorg(recorded.receipt!.deduplicationKey);
  const impaired = await (await f.request(path, created.readCapability)).json() as NativeSandboxView;
  expect(impaired.status).toBe("sandbox_evidence_impaired"); expect(impaired.evidence).toBe("recorded_impairment"); expect(impaired.event).toEqual(recorded.event);
  expect(f.ledger.getIntent(created.view.terms.intentId).status).toBe("paid");
});
test("late receipt survives the nullable outbox join and never creates a signed acceptance event", async () => {
  const f = fixture(), created = await f.create(), path = "/v1/native-sandbox/intents/" + created.view.terms.intentId, signed = await f.sign(created.view.terms);
  await f.request(path + "/prepare", created.paymentCapability, "POST", signed, { "Idempotency-Key": "native_api_prepare_01" }); f.settle(true);
  const result = await (await f.request(path + "/observe", created.paymentCapability, "POST", { txHash: f.transactionHash })).json() as NativeSandboxView;
  expect(result.status).toBe("sandbox_reconciliation"); expect(result.receipt?.timing).toBe("late"); expect(result.event).toBeNull(); expect(f.ledger.pendingEvents()).toHaveLength(0);
  expect(f.ledger.getReceiptRecord(created.view.terms.intentId)?.acceptance).toBeNull();
});
test("sandbox event verification rejects key substitution, other terms and every unsigned extra field", async () => {
  const f = fixture(), created = await f.create(), path = "/v1/native-sandbox/intents/" + created.view.terms.intentId;
  await f.request(path + "/prepare", created.paymentCapability, "POST", await f.sign(created.view.terms), { "Idempotency-Key": "native_api_prepare_01" }); f.settle();
  const view = await (await f.request(path + "/observe", created.paymentCapability, "POST", { txHash: f.transactionHash })).json() as NativeSandboxView;
  const envelope = view.event!;
  expect(verifyNativeSandboxReceipt(envelope, "1".repeat(64), created.view.terms)).toBe(false);
  for (const terms of [{ ...created.view.terms, amountBaseUnits: "1" }, { ...created.view.terms, recipient: "0x" + "3".repeat(40) },
    { ...created.view.terms, asset: { ...created.view.terms.asset, runtimeCodeHash: "0x" + "f".repeat(64) } }]) expect(verifyNativeSandboxReceipt(envelope, f.publicKey, terms)).toBe(false);
  for (const invalid of [
    { ...envelope, accepted: true }, { ...envelope, event: { ...envelope.event, accepted: true } },
    { ...envelope, event: { ...envelope.event, receipt: { ...envelope.event.receipt, accepted: true } } },
    { ...envelope, event: { ...envelope.event, receipt: { ...envelope.event.receipt, finality: "ethereum_l1_finalized" } } },
  ]) expect(verifyNativeSandboxReceipt(invalid as SignedNativeSandboxReceipt, f.publicKey, created.view.terms)).toBe(false);
  expect(() => parseNativeSandboxTerms({ ...created.view.terms, amountMsat: "1000000" })).toThrow();
  const profile = created.view.terms.asset.localSandbox!;
  const reordered = { ...created.view.terms, asset: { ...created.view.terms.asset, localSandbox: { confirmations: profile.confirmations, namespace: profile.namespace, version: profile.version } } };
  expect(verifyNativeSandboxReceipt(envelope, f.publicKey, reordered)).toBe(true);
  expect(verifyNativeSandboxReceipt({ ...envelope, event: { ...envelope.event, terms: reordered } }, f.publicKey, created.view.terms)).toBe(true);
});
test("another order's authenticated binding cannot reserve the target intent", async () => {
  const f = fixture(), created = await f.create(), signed = await f.sign(created.view.terms);
  const second = await f.request("/v1/native-sandbox/intents", f.options.adminToken, "POST", { orderRef: "sandbox-order-two", amountBaseUnits: "1000000", expiresAt: 2000 }, { "Idempotency-Key": "native_api_intent_02" });
  const other = await second.json() as Awaited<ReturnType<typeof f.create>>;
  const path = "/v1/native-sandbox/intents/" + other.view.terms.intentId;
  expect((await f.request(path + "/prepare", created.paymentCapability, "POST", signed, { "Idempotency-Key": "native_api_prepare_01" })).status).toBe(404);
  expect((await f.request(path + "/prepare", other.paymentCapability, "POST", signed, { "Idempotency-Key": "native_api_prepare_02" })).status).toBe(409);
  expect(f.ledger.inventory().reserved).toBe("0"); expect(f.rpcCalls()).toBe(0);
});
test("origin, query, method, malformed bearer and streaming body guards precede authority changes", async () => {
  const f = fixture(), created = await f.create(), path = "/v1/native-sandbox/intents/" + created.view.terms.intentId;
  expect((await f.request(path, created.readCapability, "GET", undefined, { Origin: "https://other.example" })).status).toBe(403);
  expect((await f.request(path + "?token=" + created.readCapability, created.readCapability)).status).toBe(403);
  expect((await f.request(path, created.readCapability, "DELETE")).status).toBe(405);
  expect((await f.request(path, created.readCapability, "GET", undefined, { Authorization: "Bearer éééééééééééééééééééééééééééééééé" })).status).toBe(401);
  expect((await f.request(path + "/prepare", created.paymentCapability, "POST", { value: "x".repeat(9000) })).status).toBe(413);
  const response = await f.request(path, created.readCapability); expect(response.headers.get("Cache-Control")).toBe("no-store"); expect(response.headers.get("Referrer-Policy")).toBe("no-referrer");
  expect(f.rpcCalls()).toBe(0); expect(f.ledger.inventory().reserved).toBe("0");
});
test("service snapshots private key bytes instead of adopting later caller mutations", async () => {
  const f = fixture(), created = await f.create(); f.options.capabilityKey.fill(9); f.options.eventSigningKey.fill(8);
  expect(await f.create()).toEqual(created);
  const path = "/v1/native-sandbox/intents/" + created.view.terms.intentId;
  await f.request(path + "/prepare", created.paymentCapability, "POST", await f.sign(created.view.terms), { "Idempotency-Key": "native_api_prepare_01" }); f.settle();
  const view = await (await f.request(path + "/observe", created.paymentCapability, "POST", { txHash: f.transactionHash })).json() as NativeSandboxView;
  expect(verifyNativeSandboxReceipt(view.event!, f.publicKey, created.view.terms)).toBe(true);
});
