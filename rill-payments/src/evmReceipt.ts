import { Interface, id, keccak256, verifyTypedData } from "ethers";

const ERC20 = new Interface(["function transfer(address to,uint256 amount) returns(bool)", "function decimals() view returns(uint8)", "event Transfer(address indexed from,address indexed to,uint256 value)"]);
const IMPLEMENTATION_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc";
const BEACON_SLOT = "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50";
const GENESIS: Readonly<Record<string, string>> = {
  "1": "0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3",
  "11155111": "0x25a5cc106eea7138acab33231d7160d69cb777ee0c2c553fcddf5138993e6dd9",
};
const address = (value: string): boolean => /^0x[0-9a-f]{40}$/.test(value);
const hash = (value: string): boolean => /^0x[0-9a-f]{64}$/.test(value);
const units = (value: string): bigint => {
  if (!/^[1-9][0-9]{0,77}$/.test(value) || BigInt(value) >= 1n << 256n) throw new Error("Invalid token quantity"); return BigInt(value);
};
export interface EvmTokenAsset {
  readonly id: string;
  readonly chainId: string;
  readonly genesisHash: string;
  readonly token: string;
  readonly decimals: number;
  readonly behavior: "standard_erc20";
  readonly runtimeCodeHash: string;
  readonly implementation: { readonly address: string; readonly codeHash: string } | null;
  readonly historicalStateVerified: true;
  readonly behaviorConformanceVerified: true;
}
export interface EvmReceiptBinding {
  readonly version: "evm-receipt-binding/1";
  readonly merchantOrigin: string;
  readonly intentId: string;
  readonly attemptId: string;
  readonly assetId: string;
  readonly sourceWallet: string;
  readonly sourceNonce: string;
  readonly recipient: string;
  readonly amountBaseUnits: string;
  readonly validAfter: number;
  readonly validBefore: number;
}
/** Independently loaded authoritative merchant terms, never copied from the buyer's binding. */
export interface EvmReceiptIntent {
  readonly merchantOrigin: string;
  readonly intentId: string;
  readonly attemptId: string;
  readonly assetId: string;
  readonly recipient: string;
  readonly amountBaseUnits: string;
  readonly createdAt: number;
  readonly expiresAt: number;
}
export interface PreparedEvmBinding {
  readonly binding: EvmReceiptBinding;
  readonly signature: string;
  readonly preparedAt: number;
  readonly preparedBlockNumber: number;
  readonly preparedBlockHash: string;
}
export interface EvmBlock { readonly number: number; readonly hash: string | null; readonly timestamp: number }
export interface EvmTransaction { readonly hash: string; readonly chainId: bigint; readonly nonce: number; readonly from: string; readonly to: string | null; readonly value: bigint; readonly data: string }
export interface EvmLog { readonly address: string; readonly topics: readonly string[]; readonly data: string; readonly index: number }
export interface EvmReceipt { readonly hash: string; readonly blockHash: string; readonly blockNumber: number; readonly status: number | null; readonly logs: readonly EvmLog[] }
/** Structurally compatible with ethers providers, but has no send/sign operation. */
export interface EvmReader {
  getNetwork(): Promise<{ chainId: bigint }>;
  getBlock(tag: number | "latest" | "finalized"): Promise<EvmBlock | null>;
  getCode(account: string, block?: number): Promise<string>;
  getStorage(account: string, slot: string, block?: number): Promise<string>;
  call(transaction: { to: string; data: string; blockTag?: number }): Promise<string>;
  getTransactionCount(account: string, tag: "pending"): Promise<number>;
  getTransaction(hash: string): Promise<EvmTransaction | null>;
  getTransactionReceipt(hash: string): Promise<EvmReceipt | null>;
  getLogs(filter: { address: string; fromBlock: number; toBlock: number; topics: (string | string[])[] }): Promise<readonly EvmLog[]>;
}
export interface VerifiedTokenReceipt {
  readonly assetId: string;
  readonly quantityBaseUnits: string;
  readonly recipient: string;
  readonly transactionHash: string;
  readonly logIndex: number;
  readonly deduplicationKey: string;
  readonly blockHash: string;
  readonly blockNumber: number;
  readonly finality: "ethereum_l1_finalized";
  readonly timing: "timely" | "late";
}
const BINDING_TYPES = { ReceiptBinding: [
  { name: "merchantOrigin", type: "string" }, { name: "intentId", type: "string" }, { name: "attemptId", type: "string" },
  { name: "assetId", type: "string" }, { name: "sourceWallet", type: "address" }, { name: "sourceNonce", type: "uint256" },
  { name: "recipient", type: "address" }, { name: "amountBaseUnits", type: "uint256" }, { name: "validAfter", type: "uint64" }, { name: "validBefore", type: "uint64" },
] };
export function receiptBindingTypedData(asset: EvmTokenAsset, binding: EvmReceiptBinding) {
  return { domain: { name: "RillSwap Checkout Receipt", version: "1", chainId: BigInt(asset.chainId), verifyingContract: asset.token },
    types: { ReceiptBinding: BINDING_TYPES.ReceiptBinding.map((field) => ({ ...field })) }, value: { merchantOrigin: binding.merchantOrigin, intentId: binding.intentId, attemptId: binding.attemptId,
      assetId: binding.assetId, sourceWallet: binding.sourceWallet, sourceNonce: binding.sourceNonce, recipient: binding.recipient,
      amountBaseUnits: binding.amountBaseUnits, validAfter: binding.validAfter, validBefore: binding.validBefore } };
}
function validate(asset: EvmTokenAsset, intent: EvmReceiptIntent, binding: EvmReceiptBinding, signature: string): void {
  if (!Object.hasOwn(GENESIS, asset.chainId) || asset.genesisHash !== GENESIS[asset.chainId] || asset.historicalStateVerified !== true || asset.behaviorConformanceVerified !== true ||
      asset.id !== `eip155:${asset.chainId}/erc20:${asset.token}` || !address(asset.token) || !hash(asset.genesisHash) ||
      !hash(asset.runtimeCodeHash) || !Number.isInteger(asset.decimals) || asset.decimals < 0 || asset.decimals > 36 || asset.behavior !== "standard_erc20" ||
      (asset.implementation !== null && (!address(asset.implementation.address) || !hash(asset.implementation.codeHash)))) throw new Error("Unpinned ERC20 asset");
  if (binding.version !== "evm-receipt-binding/1" || binding.assetId !== asset.id || !address(binding.sourceWallet) || !address(binding.recipient) || binding.sourceWallet === binding.recipient ||
      ![binding.intentId, binding.attemptId].every((value) => /^[A-Za-z0-9_-]{16,128}$/.test(value)) ||
      new URL(binding.merchantOrigin).origin !== binding.merchantOrigin || !binding.merchantOrigin.startsWith("https://") ||
      !/^(0|[1-9][0-9]{0,15})$/.test(binding.sourceNonce) || !Number.isSafeInteger(Number(binding.sourceNonce)) ||
      !Number.isSafeInteger(binding.validAfter) || !Number.isSafeInteger(binding.validBefore) || binding.validAfter < 0 || binding.validAfter >= binding.validBefore) throw new Error("Invalid receipt binding");
  units(binding.amountBaseUnits);
  if (binding.merchantOrigin !== intent.merchantOrigin || binding.intentId !== intent.intentId || binding.attemptId !== intent.attemptId || binding.assetId !== intent.assetId ||
      binding.recipient !== intent.recipient || binding.amountBaseUnits !== intent.amountBaseUnits || !Number.isSafeInteger(intent.createdAt) || !Number.isSafeInteger(intent.expiresAt) ||
      binding.validAfter < intent.createdAt || binding.validBefore > intent.expiresAt) throw new Error("Binding differs from merchant terms");
  const typed = receiptBindingTypedData(asset, binding);
  if (verifyTypedData(typed.domain, typed.types, typed.value, signature).toLowerCase() !== binding.sourceWallet) throw new Error("Unauthorized receipt binding");
}
async function deployment(asset: EvmTokenAsset, provider: EvmReader, block: number): Promise<void> {
  if ((await provider.getNetwork()).chainId !== BigInt(asset.chainId) || (await provider.getBlock(0))?.hash?.toLowerCase() !== asset.genesisHash) throw new Error("Wrong receipt network");
  const code = await provider.getCode(asset.token, block);
  if (code === "0x" || keccak256(code) !== asset.runtimeCodeHash) throw new Error("Token code changed");
  const slot = (await provider.getStorage(asset.token, IMPLEMENTATION_SLOT, block)).toLowerCase();
  const beacon = await provider.getStorage(asset.token, BEACON_SLOT, block);
  if (!hash(beacon.toLowerCase()) || BigInt(beacon) !== 0n) throw new Error("Beacon proxies require a dedicated adapter");
  if (!hash(slot)) throw new Error("Invalid implementation slot");
  if (asset.implementation) {
    if (slot !== "0x" + "0".repeat(24) + asset.implementation.address.slice(2) ||
        keccak256(await provider.getCode(asset.implementation.address, block)) !== asset.implementation.codeHash) throw new Error("Token implementation changed");
  } else if (BigInt(slot) !== 0n) throw new Error("Undeclared token proxy");
  const result = await provider.call({ to: asset.token, data: ERC20.encodeFunctionData("decimals"), blockTag: block });
  if (Number(ERC20.decodeFunctionResult("decimals", result)[0]) !== asset.decimals) throw new Error("Token decimals mismatch");
}

/** Call before funding; persist the result and globally reserve (network, wallet, nonce) before publishing instructions. */
export async function prepareEvmBinding(asset: EvmTokenAsset, intent: EvmReceiptIntent, input: EvmReceiptBinding, signature: string, provider: EvmReader, clock: () => number): Promise<PreparedEvmBinding> {
  const binding: EvmReceiptBinding = Object.freeze({ version: input.version, merchantOrigin: input.merchantOrigin, intentId: input.intentId, attemptId: input.attemptId,
    assetId: input.assetId, sourceWallet: input.sourceWallet, sourceNonce: input.sourceNonce, recipient: input.recipient, amountBaseUnits: input.amountBaseUnits,
    validAfter: input.validAfter, validBefore: input.validBefore });
  validate(asset, intent, binding, signature);
  if (!["1", "11155111"].includes(asset.chainId)) throw new Error("Unsupported finality profile");
  const checkTime = (): number => { const now = clock(); if (!Number.isSafeInteger(now) || now < binding.validAfter || now >= binding.validBefore) throw new Error("Receipt binding expired"); return now; };
  checkTime();
  const block = await provider.getBlock("latest");
  if (!block?.hash || !hash(block.hash.toLowerCase()) || !Number.isSafeInteger(block.number) || block.number < 0 || !Number.isSafeInteger(block.timestamp) || block.timestamp < 0) throw new Error("No preparation checkpoint");
  await deployment(asset, provider, block.number);
  if (await provider.getCode(binding.sourceWallet, block.number) !== "0x" || await provider.getTransactionCount(binding.sourceWallet, "pending") !== Number(binding.sourceNonce)) throw new Error("Unsupported sender or already used nonce");
  return Object.freeze({ binding, signature, preparedAt: checkTime(), preparedBlockNumber: block.number, preparedBlockHash: block.hash.toLowerCase() });
}

/** Independently observe a prebound direct EOA transfer. Does not allocate receipts or authorize fulfillment itself. */
export async function observeEvmReceipt(asset: EvmTokenAsset, intent: EvmReceiptIntent, prepared: PreparedEvmBinding, transactionHash: string, provider: EvmReader): Promise<VerifiedTokenReceipt | null> {
  validate(asset, intent, prepared.binding, prepared.signature);
  const binding = prepared.binding;
  // Only known Ethereum L1 finality semantics. L2s require their own explicit observer/profile.
  if (!["1", "11155111"].includes(asset.chainId) || !hash(transactionHash) || !Number.isSafeInteger(prepared.preparedAt) || prepared.preparedAt < binding.validAfter || prepared.preparedAt >= binding.validBefore ||
      !Number.isSafeInteger(prepared.preparedBlockNumber) || !hash(prepared.preparedBlockHash)) throw new Error("Unsupported finality profile or checkpoint");
  const receipt = await provider.getTransactionReceipt(transactionHash);
  if (!receipt) return null;
  const transaction = await provider.getTransaction(transactionHash);
  if (!transaction || receipt.status !== 1 || receipt.hash.toLowerCase() !== transactionHash || transaction.hash.toLowerCase() !== transactionHash ||
      transaction.chainId !== BigInt(asset.chainId) || transaction.from.toLowerCase() !== binding.sourceWallet || transaction.nonce !== Number(binding.sourceNonce) ||
      transaction.to?.toLowerCase() !== asset.token || transaction.value !== 0n || !Number.isSafeInteger(receipt.blockNumber) || receipt.blockNumber <= prepared.preparedBlockNumber || !hash(receipt.blockHash.toLowerCase())) throw new Error("Receipt is not the prebound token debit");
  const finalized = await provider.getBlock("finalized");
  if (!finalized) return null;
  if (!Number.isSafeInteger(finalized.number) || finalized.number < 0 || !Number.isSafeInteger(finalized.timestamp) || finalized.timestamp < 0 ||
      !finalized.hash || !hash(finalized.hash.toLowerCase())) throw new Error("Invalid finalized checkpoint");
  if (receipt.blockNumber > finalized.number) return null;
  const canonical = await provider.getBlock(receipt.blockNumber), anchor = await provider.getBlock(prepared.preparedBlockNumber);
  if (!canonical || canonical.number !== receipt.blockNumber || !Number.isSafeInteger(canonical.timestamp) || canonical.timestamp < 0 || canonical.hash?.toLowerCase() !== receipt.blockHash.toLowerCase() ||
      anchor?.number !== prepared.preparedBlockNumber || anchor.hash?.toLowerCase() !== prepared.preparedBlockHash) throw new Error("Receipt or preparation reorged");
  if (canonical.timestamp < prepared.preparedAt || canonical.timestamp < binding.validAfter) throw new Error("Receipt predates binding");
  await deployment(asset, provider, receipt.blockNumber);
  if (asset.implementation && (await provider.getLogs({ address: asset.token, fromBlock: receipt.blockNumber, toBlock: receipt.blockNumber,
    topics: [[id("Upgraded(address)"), id("BeaconUpgraded(address)"), id("AdminChanged(address,address)")]] })).length !== 0) throw new Error("Token upgraded during receipt block");
  if (await provider.getCode(binding.sourceWallet, receipt.blockNumber) !== "0x") throw new Error("Unsupported debit signer");
  const transfer = ERC20.parseTransaction({ data: transaction.data, value: transaction.value });
  if (transfer?.name !== "transfer" || String(transfer.args[0]).toLowerCase() !== binding.recipient || BigInt(transfer.args[1]) !== units(binding.amountBaseUnits) ||
      transaction.data.toLowerCase() !== ERC20.encodeFunctionData("transfer", [binding.recipient, units(binding.amountBaseUnits)]).toLowerCase()) throw new Error("Wrong transfer instructions");
  const matched = receipt.logs.filter((log) => {
    if (log.address.toLowerCase() !== asset.token) return false;
    const event = ERC20.parseLog({ topics: [...log.topics], data: log.data });
    return event?.name === "Transfer" && String(event.args[0]).toLowerCase() === binding.sourceWallet && String(event.args[1]).toLowerCase() === binding.recipient && BigInt(event.args[2]) === units(binding.amountBaseUnits);
  });
  if (matched.length !== 1 || !Number.isSafeInteger(matched[0]!.index) || matched[0]!.index < 0) throw new Error("Ambiguous token receipt");
  // Historical reads are height-addressed, so verify their branch has not changed.
  for (const expected of [anchor, canonical, finalized]) {
    const current = await provider.getBlock(expected.number);
    if (current?.number !== expected.number || current.hash?.toLowerCase() !== expected.hash?.toLowerCase() || current.timestamp !== expected.timestamp) throw new Error("Receipt chain view changed");
  }
  const logIndex = matched[0]!.index;
  return Object.freeze({ assetId: asset.id, quantityBaseUnits: binding.amountBaseUnits, recipient: binding.recipient, transactionHash, logIndex,
    deduplicationKey: `${asset.chainId}:${asset.genesisHash}:${transactionHash}:${logIndex}`, blockHash: receipt.blockHash.toLowerCase(), blockNumber: receipt.blockNumber,
    finality: "ethereum_l1_finalized", timing: canonical.timestamp < binding.validBefore ? "timely" : "late" });
}
