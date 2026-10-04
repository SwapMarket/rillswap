import { expect, test } from "bun:test";
import { Interface, Wallet, keccak256, type Provider } from "ethers";
import { observeEvmReceipt, prepareEvmBinding, receiptBindingTypedData, type EvmBlock, type EvmReader, type EvmReceiptBinding, type EvmReceiptIntent, type EvmTokenAsset } from "../src/evmReceipt";

const abi = new Interface(["function transfer(address,uint256) returns(bool)", "function decimals() view returns(uint8)", "event Transfer(address indexed from,address indexed to,uint256 value)"]);
const blockHash = (height: number) => "0x" + height.toString(16).padStart(64, "0");
const shape: (provider: Provider) => EvmReader = (provider) => provider; void shape;
async function fixture() {
  const wallet = new Wallet("0x" + "0".repeat(63) + "1"); // Public test key, never an application key.
  const token = "0x" + "1".repeat(40), recipient = "0x" + "2".repeat(40), code = "0x60016000";
  const asset: EvmTokenAsset = { id: `eip155:11155111/erc20:${token}`, chainId: "11155111", genesisHash: "0x25a5cc106eea7138acab33231d7160d69cb777ee0c2c553fcddf5138993e6dd9",
    token, decimals: 6, behavior: "standard_erc20", runtimeCodeHash: keccak256(code), implementation: null, historicalStateVerified: true, behaviorConformanceVerified: true };
  const binding: EvmReceiptBinding = { version: "evm-receipt-binding/1", merchantOrigin: "https://merchant.example", intentId: "native_intent_0001", attemptId: "native_attempt_001",
    assetId: asset.id, sourceWallet: wallet.address.toLowerCase(), sourceNonce: "2", recipient, amountBaseUnits: "1000000", validAfter: 1000, validBefore: 2000 };
  const intent: EvmReceiptIntent = { merchantOrigin: binding.merchantOrigin, intentId: binding.intentId, attemptId: binding.attemptId, assetId: asset.id,
    recipient, amountBaseUnits: binding.amountBaseUnits, createdAt: 1000, expiresAt: 2000 };
  const typed = receiptBindingTypedData(asset, binding); const signature = await wallet.signTypedData(typed.domain, typed.types, typed.value);
  const event = abi.encodeEventLog(abi.getEvent("Transfer")!, [wallet.address, recipient, 1000000n]);
  const transactionHash = "0x" + "8".repeat(64);
  const transaction = { hash: transactionHash, chainId: 11155111n, nonce: 2, from: wallet.address, to: token, value: 0n, data: abi.encodeFunctionData("transfer", [recipient, 1000000n]) };
  const receipt = { hash: transactionHash, blockHash: blockHash(42), blockNumber: 42, status: 1, logs: [{ address: token, topics: event.topics, data: event.data, index: 7 }] };
  let finalizedHeight: number | null = 50, timestamp = 1200, canonicalHash = blockHash(42);
  const historicalBlocks: number[] = [];
  const provider: EvmReader = {
    getNetwork: async () => ({ chainId: 11155111n }),
    getBlock: async (tag) => tag === "finalized" ? (finalizedHeight === null ? null : { number: finalizedHeight, hash: blockHash(finalizedHeight), timestamp: 1800 }) :
      tag === 0 ? { number: 0, hash: asset.genesisHash, timestamp: 0 } : tag === 42 ? { number: 42, hash: canonicalHash, timestamp } :
      tag === "latest" || tag === 40 ? { number: 40, hash: blockHash(40), timestamp: 1000 } : { number: tag, hash: blockHash(tag), timestamp: 1800 },
    getCode: async (account, block) => { if (block !== undefined) historicalBlocks.push(block); return account === token ? code : "0x"; },
    getStorage: async () => "0x" + "0".repeat(64),
    call: async (tx) => { expect(tx.blockTag).toBeDefined(); return abi.encodeFunctionResult("decimals", [6]); },
    getTransactionCount: async () => 2, getTransaction: async () => transaction, getTransactionReceipt: async () => receipt, getLogs: async () => [],
  };
  const prepared = await prepareEvmBinding(asset, intent, binding, signature, provider, () => 1100);
  return { asset, intent, binding, signature, provider, prepared, transactionHash, transaction, receipt, wallet, historicalBlocks,
    finalize: (height: number | null) => { finalizedHeight = height; }, reorg: () => { canonicalHash = blockHash(99); }, late: () => { timestamp = 2000; } };
}
test("authenticated prebound token receipt uses historical pins and exact unique subindex", async () => {
  const f = await fixture(); const receipt = await observeEvmReceipt(f.asset, f.intent, f.prepared, f.transactionHash, f.provider);
  expect(receipt?.quantityBaseUnits).toBe("1000000"); expect(receipt?.logIndex).toBe(7); expect(receipt?.timing).toBe("timely");
  expect(receipt?.deduplicationKey).toBe(`11155111:${f.asset.genesisHash}:${f.transactionHash}:7`);
  expect(f.historicalBlocks).toContain(40); expect(f.historicalBlocks).toContain(42);
});
test("known transaction hash without the debit wallet's signature creates no receipt right", async () => {
  const f = await fixture(), stranger = new Wallet("0x" + "0".repeat(63) + "2"); const typed = receiptBindingTypedData(f.asset, f.binding);
  const forged = await stranger.signTypedData(typed.domain, typed.types, typed.value);
  await expect(prepareEvmBinding(f.asset, f.intent, f.binding, forged, f.provider, () => 1100)).rejects.toThrow("Unauthorized");
  await expect(prepareEvmBinding(f.asset, { ...f.intent, amountBaseUnits: "1" }, f.binding, f.signature, f.provider, () => 1100)).rejects.toThrow("merchant terms");
  await expect(prepareEvmBinding(f.asset, { ...f.intent, recipient: stranger.address.toLowerCase() }, f.binding, f.signature, f.provider, () => 1100)).rejects.toThrow("merchant terms");
});
test("wrong token, network, sender, nonce or failed receipt cannot fulfill", async () => {
  for (const mutate of [
    (f: Awaited<ReturnType<typeof fixture>>) => { f.transaction.to = "0x" + "3".repeat(40); },
    (f: Awaited<ReturnType<typeof fixture>>) => { f.transaction.from = "0x" + "3".repeat(40); },
    (f: Awaited<ReturnType<typeof fixture>>) => { f.transaction.nonce++; },
    (f: Awaited<ReturnType<typeof fixture>>) => { f.transaction.chainId = 1n; },
    (f: Awaited<ReturnType<typeof fixture>>) => { f.receipt.status = 0; },
  ]) { const f = await fixture(); mutate(f); await expect(observeEvmReceipt(f.asset, f.intent, f.prepared, f.transactionHash, f.provider)).rejects.toThrow("prebound"); }
});
test("finalized policy never substitutes latest or bridge status", async () => {
  const f = await fixture(); f.finalize(null); expect(await observeEvmReceipt(f.asset, f.intent, f.prepared, f.transactionHash, f.provider)).toBeNull();
  f.finalize(41); expect(await observeEvmReceipt(f.asset, f.intent, f.prepared, f.transactionHash, f.provider)).toBeNull();
  f.finalize(50); f.reorg(); await expect(observeEvmReceipt(f.asset, f.intent, f.prepared, f.transactionHash, f.provider)).rejects.toThrow("reorged");
});
test("late deposits remain identifiable for reconciliation, never silently repriced", async () => {
  const f = await fixture(); f.late(); const receipt = await observeEvmReceipt(f.asset, f.intent, f.prepared, f.transactionHash, f.provider);
  expect(receipt?.timing).toBe("late"); expect(receipt?.quantityBaseUnits).toBe(f.intent.amountBaseUnits);
});
test("used nonce, smart accounts, missing conformance and stale preparation fail closed", async () => {
  const f = await fixture();
  await expect(prepareEvmBinding(f.asset, f.intent, f.binding, f.signature, { ...f.provider, getTransactionCount: async () => 3 }, () => 1100)).rejects.toThrow("nonce");
  await expect(prepareEvmBinding(f.asset, f.intent, f.binding, f.signature, { ...f.provider, getCode: async () => "0x60016000" }, () => 1100)).rejects.toThrow("sender");
  await expect(prepareEvmBinding({ ...f.asset, historicalStateVerified: false as true }, f.intent, f.binding, f.signature, f.provider, () => 1100)).rejects.toThrow("Unpinned");
  let now = 1100; await expect(prepareEvmBinding(f.asset, f.intent, f.binding, f.signature,
    { ...f.provider, getTransactionCount: async () => { now = 2000; return 2; } }, () => now)).rejects.toThrow("expired");
});
test("amount/instruction/log confusion, duplicate logs and token upgrade are rejected", async () => {
  const f = await fixture(); f.transaction.data = abi.encodeFunctionData("transfer", [f.binding.recipient, 2n]);
  await expect(observeEvmReceipt(f.asset, f.intent, f.prepared, f.transactionHash, f.provider)).rejects.toThrow("instructions");
  const duplicate = await fixture(); duplicate.receipt.logs.push({ ...duplicate.receipt.logs[0]!, index: 8 });
  await expect(observeEvmReceipt(duplicate.asset, duplicate.intent, duplicate.prepared, duplicate.transactionHash, duplicate.provider)).rejects.toThrow("Ambiguous");
  const changed = await fixture();
  await expect(observeEvmReceipt(changed.asset, changed.intent, changed.prepared, changed.transactionHash,
    { ...changed.provider, getCode: async (account) => account === changed.asset.token ? "0x60026000" : "0x" })).rejects.toThrow("code changed");
});
test("malformed finality evidence never yields a finalized receipt", async () => {
  for (const patch of [{ number: NaN }, { number: undefined }, { number: -1 }, { hash: null }, { hash: "0x01" }, { timestamp: NaN }]) {
    const f = await fixture();
    await expect(observeEvmReceipt(f.asset, f.intent, f.prepared, f.transactionHash, { ...f.provider, getBlock: async (tag) =>
      tag === "finalized" ? { number: 50, hash: blockHash(50), timestamp: 1800, ...patch } as unknown as EvmBlock : f.provider.getBlock(tag) })).rejects.toThrow("finalized checkpoint");
  }
});
test("canonical views are checked after finality and again after historical reads", async () => {
  for (const during of ["finality", "history"]) {
    const f = await fixture();
    await expect(observeEvmReceipt(f.asset, f.intent, f.prepared, f.transactionHash, { ...f.provider,
      getBlock: async (tag) => { if (tag === "finalized" && during === "finality") f.reorg(); return f.provider.getBlock(tag); },
      getCode: async (account, block) => { if (during === "history") f.reorg(); return f.provider.getCode(account, block); },
    })).rejects.toThrow(during === "finality" ? "reorged" : "chain view changed");
  }
});
test("trailing calldata and self-transfers do not match exact native receipt terms", async () => {
  const f = await fixture(); f.transaction.data += "deadbeef";
  await expect(observeEvmReceipt(f.asset, f.intent, f.prepared, f.transactionHash, f.provider)).rejects.toThrow("instructions");
  const self = { ...f.binding, recipient: f.binding.sourceWallet }; const typed = receiptBindingTypedData(f.asset, self);
  const signature = await f.wallet.signTypedData(typed.domain, typed.types, typed.value);
  await expect(prepareEvmBinding(f.asset, { ...f.intent, recipient: self.recipient }, self, signature, f.provider, () => 1100)).rejects.toThrow("Invalid receipt binding");
});
test("beacon proxies and same-block implementation upgrades require another observer", async () => {
  const f = await fixture();
  await expect(prepareEvmBinding(f.asset, f.intent, f.binding, f.signature, { ...f.provider, getStorage: async () => blockHash(1) }, () => 1100)).rejects.toThrow("Beacon");
  const implementation = { address: "0x" + "3".repeat(40), codeHash: keccak256("0x60036000") };
  const asset = { ...f.asset, implementation };
  await expect(observeEvmReceipt(asset, f.intent, f.prepared, f.transactionHash, { ...f.provider,
    getCode: async (account, block) => account === implementation.address ? "0x60036000" : f.provider.getCode(account, block),
    getStorage: async (_account, slot) => slot.startsWith("0x3608") ? "0x" + "0".repeat(24) + implementation.address.slice(2) : blockHash(0),
    getLogs: async () => [f.receipt.logs[0]!],
  })).rejects.toThrow("upgraded");
});
