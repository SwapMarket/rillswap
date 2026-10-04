import { afterEach, expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { Database } from "bun:sqlite";
import { Interface, Wallet, keccak256 } from "ethers";
import { NativeReceiptLedger, type NativeIntent } from "../src/nativeLedger";
import { receiptBindingTypedData, type EvmReader, type EvmReceiptBinding, type EvmReceipt } from "../src/evmReceipt";

const cleanup: (() => void)[] = []; afterEach(() => { for (const close of cleanup.splice(0)) close(); });
const blockHash = (height: number) => "0x" + height.toString(16).padStart(64, "0");
function fixture(cap = "2000000") {
  mkdirSync("tmp", { recursive: true }); const directory = mkdtempSync(resolve("tmp/native-")), path = directory + "/native.sqlite";
  const token = "0x" + "1".repeat(40), recipient = "0x" + "2".repeat(40), wallet = new Wallet("0x" + "0".repeat(63) + "1");
  const abi = new Interface(["function transfer(address,uint256) returns(bool)", "function decimals() view returns(uint8)", "event Transfer(address indexed from,address indexed to,uint256 value)"]);
  const config = { origin: "https://merchant.example", recipient, inventoryCapBaseUnits: cap, asset: {
    id: `eip155:11155111/erc20:${token}`, chainId: "11155111", genesisHash: "0x25a5cc106eea7138acab33231d7160d69cb777ee0c2c553fcddf5138993e6dd9", token, decimals: 6,
    behavior: "standard_erc20" as const, runtimeCodeHash: keccak256("0x60016000"), implementation: null, historicalStateVerified: true as const, behaviorConformanceVerified: true as const,
  } };
  const ledger = NativeReceiptLedger.provision(path, config);
  cleanup.push(() => { try { ledger.close(); } catch {} rmSync(directory, { recursive: true, force: true }); });
  const receipts = new Map<string, EvmReceipt>(); const nonces = new Map<string, number>(); let receiptTime = 1200;
  const provider: EvmReader = {
    getNetwork: async () => ({ chainId: 11155111n }), getBlock: async (tag) => tag === 0 ? { number: 0, hash: config.asset.genesisHash, timestamp: 0 } :
      tag === "latest" || tag === 40 ? { number: 40, hash: blockHash(40), timestamp: 1000 } :
      tag === "finalized" || tag === 50 ? { number: 50, hash: blockHash(50), timestamp: 1800 } : { number: tag, hash: blockHash(tag), timestamp: receiptTime },
    getCode: async (account) => account === token ? "0x60016000" : "0x", getStorage: async () => blockHash(0),
    call: async () => abi.encodeFunctionResult("decimals", [6]), getTransactionCount: async () => 2,
    getTransaction: async (hash) => ({ hash, chainId: 11155111n, nonce: nonces.get(hash) ?? 2, from: wallet.address, to: token, value: 0n, data: abi.encodeFunctionData("transfer", [recipient, 1000000n]) }),
    getTransactionReceipt: async (hash) => receipts.get(hash) ?? null, getLogs: async () => [],
  };
  const sign = async (intent: NativeIntent, sourceNonce = "2") => {
    const binding: EvmReceiptBinding = { version: "evm-receipt-binding/1", merchantOrigin: config.origin, intentId: intent.intentId, attemptId: intent.attemptId, assetId: config.asset.id,
      sourceWallet: wallet.address.toLowerCase(), sourceNonce, recipient, amountBaseUnits: intent.amountBaseUnits, validAfter: intent.createdAt, validBefore: intent.expiresAt };
    const typed = receiptBindingTypedData(config.asset, binding); return { binding, signature: await wallet.signTypedData(typed.domain, typed.types, typed.value) };
  };
  const settle = (hash = "0x" + "8".repeat(64)) => { const event = abi.encodeEventLog(abi.getEvent("Transfer")!, [wallet.address, recipient, 1000000n]);
    receipts.set(hash, { hash, blockHash: blockHash(42), blockNumber: 42, status: 1, logs: [{ address: token, topics: event.topics, data: event.data, index: 7 }] }); return hash; };
  return { ledger, path, config, provider, sign, settle, late: () => { receiptTime = 2000; }, open: () => { const second = NativeReceiptLedger.open(path, config);
    cleanup.unshift(() => second.close()); return second; } };
}
test("absent/partial/foreign/schema-modified native stores never bootstrap themselves", () => {
  const f = fixture(); expect(() => NativeReceiptLedger.open(f.path + ".absent", f.config)).toThrow();
  writeFileSync(f.path + ".partial", "", { mode: 0o600 }); expect(() => NativeReceiptLedger.open(f.path + ".partial", f.config)).toThrow();
  expect(() => NativeReceiptLedger.provision(f.path, f.config)).toThrow();
  expect(() => NativeReceiptLedger.open(f.path, { ...f.config, origin: "https://other.example" })).toThrow("config mismatch");
  const db = new Database(f.path); db.exec("CREATE TRIGGER sqliteXerase AFTER INSERT ON outbox BEGIN DELETE FROM outbox; END;"); db.close();
  expect(() => NativeReceiptLedger.open(f.path, f.config)).toThrow("schema mismatch");
});
test("native prebinding atomically reserves capacity and globally unique debit nonce", async () => {
  const f = fixture("1000000"), second = f.open();
  const first = f.ledger.createIntent("one", "1000000", 2000, "native_intent_key_1", 1000), other = f.ledger.createIntent("two", "1000000", 2000, "native_intent_key_2", 1000);
  const a = await f.sign(first), b = await f.sign(other, "3");
  const results = await Promise.allSettled([f.ledger.prepare(first.intentId, a.binding, a.signature, "native_attempt_key_1", f.provider, () => 1100),
    second.prepare(other.intentId, b.binding, b.signature, "native_attempt_key_2", { ...f.provider, getTransactionCount: async () => 3 }, () => 1100)]);
  expect(results.filter((result) => result.status === "fulfilled")).toHaveLength(1); expect(f.ledger.inventory()).toEqual({ held: "0", reserved: "1000000", impaired: "0" });
  // Expiry does not prove no funding, so it must not release the liability.
  expect(f.ledger.inventory().reserved).toBe("1000000");
});
test("global debit nonce collision rejected even with remaining inventory capacity", async () => {
  const f = fixture(); const first = f.ledger.createIntent("one", "1000000", 2000, "native_intent_key_1", 1000), second = f.ledger.createIntent("two", "1000000", 2000, "native_intent_key_2", 1000);
  const a = await f.sign(first), b = await f.sign(second);
  await f.ledger.prepare(first.intentId, a.binding, a.signature, "native_attempt_key_1", f.provider, () => 1100);
  await expect(f.ledger.prepare(second.intentId, b.binding, b.signature, "native_attempt_key_2", f.provider, () => 1100)).rejects.toThrow();
  expect(f.ledger.inventory().reserved).toBe("1000000");
});
test("native receipt acceptance, inventory and stable event survive restart with idempotent replay", async () => {
  const f = fixture(); const intent = f.ledger.createIntent("one", "1000000", 2000, "native_intent_key_1", 1000), signed = await f.sign(intent);
  const original = await f.ledger.prepare(intent.intentId, signed.binding, signed.signature, "native_attempt_key_1", f.provider, () => 1100);
  const reopened = f.open();
  expect(await reopened.prepare(intent.intentId, signed.binding, signed.signature, "native_attempt_key_1", f.provider, () => 2100)).toEqual(original);
  const unrelated = reopened.createIntent("other", "1000000", 2000, "native_intent_key_2", 1000);
  await expect(reopened.prepare(unrelated.intentId, signed.binding, signed.signature, "native_attempt_key_1", f.provider, () => 1100)).rejects.toThrow("Conflicting");
  const txid = f.settle();
  const accepted = await Promise.all([reopened.observe(intent.attemptId, txid, f.provider, () => 1300), f.ledger.observe(intent.attemptId, txid, f.provider, () => 1300)]);
  expect(accepted.every((intent) => intent.status === "paid")).toBe(true);
  const event = reopened.pendingEvents()[0]!;
  expect(f.ledger.inventory()).toEqual({ held: "1000000", reserved: "0", impaired: "0" });
  await f.ledger.observe(intent.attemptId, txid, f.provider, () => 1400); expect(f.ledger.pendingEvents()).toEqual([event]);
  expect(f.ledger.createIntent("one", "1000000", 2000, "native_intent_key_1", 3000).intentId).toBe(intent.intentId);
  f.ledger.close(); reopened.close(); const restarted = f.open();
  expect(restarted.pendingEvents()).toEqual([event]); expect(restarted.inventory().held).toBe("1000000");
  restarted.acknowledgeEvent(event.id); expect(restarted.pendingEvents()).toHaveLength(0);
});
test("irrelevant buyer fields never change replay identity or persist adapter secrets", async () => {
  const f = fixture(); const intent = f.ledger.createIntent("one", "1000000", 2000, "native_intent_key_1", 1000), signed = await f.sign(intent);
  const extra = { ...signed.binding, secret: "do not persist", toJSON: () => ({ intentId: "overridden" }) };
  const prepared = await f.ledger.prepare(intent.intentId, extra, signed.signature, "native_attempt_key_1", f.provider, () => 1100);
  expect(await f.ledger.prepare(intent.intentId, signed.binding, signed.signature, "native_attempt_key_1", f.provider, () => 1100)).toEqual(prepared);
  expect(JSON.stringify(f.ledger.getPreparation(intent.attemptId))).not.toContain("secret");
});
test("late receipt held for reconciliation without acceptance or automatic conversion", async () => {
  const f = fixture(); const intent = f.ledger.createIntent("one", "1000000", 2000, "native_intent_key_1", 1000), signed = await f.sign(intent);
  await f.ledger.prepare(intent.intentId, signed.binding, signed.signature, "native_attempt_key_1", f.provider, () => 1100); f.late();
  expect((await f.ledger.observe(intent.attemptId, f.settle(), f.provider, () => 2200)).status).toBe("reconciliation");
  expect(f.ledger.inventory().held).toBe("1000000"); expect(f.ledger.pendingEvents()).toHaveLength(0);
});
test("future native receipt cannot allocate inventory or emit acceptance", async () => {
  const f = fixture(); const intent = f.ledger.createIntent("one", "1000000", 2000, "native_intent_key_1", 1000), signed = await f.sign(intent);
  await f.ledger.prepare(intent.intentId, signed.binding, signed.signature, "native_attempt_key_1", f.provider, () => 1100);
  await expect(f.ledger.observe(intent.attemptId, f.settle(), f.provider, () => 1100)).rejects.toThrow("future");
  expect(f.ledger.inventory()).toEqual({ held: "0", reserved: "1000000", impaired: "0" }); expect(f.ledger.pendingEvents()).toHaveLength(0);
});
test("recorded reorg impairs inventory, preserves paid history and blocks new admission", async () => {
  const f = fixture(); const intent = f.ledger.createIntent("one", "1000000", 2000, "native_intent_key_1", 1000), signed = await f.sign(intent);
  await f.ledger.prepare(intent.intentId, signed.binding, signed.signature, "native_attempt_key_1", f.provider, () => 1100);
  await f.ledger.observe(intent.attemptId, f.settle(), f.provider, () => 1300);
  const event = f.ledger.pendingEvents()[0]!; f.ledger.recordReorg(event.receiptKey);
  expect(f.ledger.getIntent(intent.intentId).status).toBe("paid"); expect(f.ledger.pendingEvents()).toEqual([event]);
  expect(f.ledger.inventory()).toEqual({ held: "0", reserved: "0", impaired: "1000000" });
  const other = f.ledger.createIntent("two", "1000000", 2000, "native_intent_key_2", 1000), binding = await f.sign(other, "3");
  await expect(f.ledger.prepare(other.intentId, binding.binding, binding.signature, "native_attempt_key_2", { ...f.provider, getTransactionCount: async () => 3 }, () => 1400)).rejects.toThrow("capacity");
});
test("a reorg recorded during overlapping observation cannot silently restore inventory", async () => {
  const f = fixture(); const intent = f.ledger.createIntent("one", "1000000", 2000, "native_intent_key_1", 1000), signed = await f.sign(intent);
  await f.ledger.prepare(intent.intentId, signed.binding, signed.signature, "native_attempt_key_1", f.provider, () => 1100);
  const txid = f.settle(); await f.ledger.observe(intent.attemptId, txid, f.provider, () => 1300); const event = f.ledger.pendingEvents()[0]!;
  let release!: () => void, entered!: () => void; const started = new Promise<void>((resolve) => { entered = resolve; }); const blocked = new Promise<void>((resolve) => { release = resolve; });
  const observing = f.ledger.observe(intent.attemptId, txid, { ...f.provider, getTransactionReceipt: async (hash) => { entered(); await blocked; return f.provider.getTransactionReceipt(hash); } }, () => 1400);
  await started; f.ledger.recordReorg(event.receiptKey); release();
  await expect(observing).rejects.toThrow("reconciliation"); expect(f.ledger.inventory().impaired).toBe("1000000"); expect(f.ledger.getIntent(intent.intentId).status).toBe("paid");
});
