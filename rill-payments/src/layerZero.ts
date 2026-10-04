import { Interface, concat, getBytes, hexlify, keccak256, solidityPackedKeccak256 } from "ethers";
import type { EvmReader, EvmReceipt } from "./evmReceipt";

export const LAYERZERO_SOURCE_PINS = Object.freeze({ protocol: "9c741e7f9790639537b1710a203bcdfd73b0b9ac", oft: "4973ba8bef7b0fdf7268469abea3ea50dbd4bbd8" });
const endpointAbi = new Interface([
  "function eid() view returns(uint32)", "function inboundPayloadHash(address,uint32,bytes32,uint64) view returns(bytes32)",
  "function lazyInboundNonce(address,uint32,bytes32) view returns(uint64)", "function getReceiveLibrary(address,uint32) view returns(address,bool)",
  "function lzReceive((uint32 srcEid,bytes32 sender,uint64 nonce),address,bytes32,bytes,bytes) payable",
  "event PacketSent(bytes encodedPayload,bytes options,address sendLibrary)",
  "event PacketDelivered((uint32 srcEid,bytes32 sender,uint64 nonce) origin,address receiver)",
]);
const oftAbi = new Interface(["function endpoint() view returns(address)", "function peers(uint32) view returns(bytes32)", "function token() view returns(address)",
  "function sharedDecimals() view returns(uint8)", "function decimalConversionRate() view returns(uint256)",
  "function oftVersion() pure returns(bytes4,uint64)", "event OFTReceived(bytes32 indexed guid,uint32 srcEid,address indexed toAddress,uint256 amountReceivedLD)"]);
const tokenAbi = new Interface(["function decimals() view returns(uint8)", "event Transfer(address indexed from,address indexed to,uint256 value)"]);
const genesis: Readonly<Record<string, string>> = { "1": "0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3", "11155111": "0x25a5cc106eea7138acab33231d7160d69cb777ee0c2c553fcddf5138993e6dd9" };
const address = (value: string): boolean => /^0x[0-9a-f]{40}$/.test(value) && BigInt(value) !== 0n;
const bytes32 = (value: string): boolean => /^0x[0-9a-f]{64}$/.test(value);
const padded = (value: string): string => "0x" + "0".repeat(24) + value.slice(2);
function unpad(value: string): string {
  if (!/^0x0{24}[0-9a-f]{40}$/.test(value) || !address("0x" + value.slice(26))) throw new Error("Noncanonical EVM packet address"); return "0x" + value.slice(26);
}
export interface OftDeployment {
  readonly chainId: string; readonly genesisHash: string; readonly eid: number;
  readonly endpoint: string; readonly endpointCodeHash: string; readonly oft: string; readonly oftCodeHash: string;
  readonly token: string; readonly tokenCodeHash: string; readonly tokenDecimals: number; readonly sharedDecimals: number;
  readonly messageLibrary: string; readonly messageLibraryCodeHash: string;
}
export interface OftPathway {
  readonly version: "oft-pathway/1";
  readonly sourcePin: typeof LAYERZERO_SOURCE_PINS;
  readonly source: OftDeployment;
  readonly destination: OftDeployment;
  readonly deploymentConformanceVerified: true;
  readonly zeroValueDirectCreditVerified: true;
  readonly nonUpgradeableVerified: true;
}
export interface OftPacket {
  readonly encoded: string; readonly nonce: string; readonly srcEid: number; readonly dstEid: number;
  readonly sender: string; readonly receiver: string; readonly recipient: string;
  readonly guid: string; readonly message: string; readonly amountShared: string; readonly payloadHash: string;
}
export function decodeOftPacket(encoded: string): OftPacket {
  const bytes = getBytes(encoded);
  if (bytes.length !== 153 || bytes[0] !== 1) throw new Error("Only PacketV1 40-byte noncompose OFT messages are supported");
  const number = (start: number, end: number): bigint => BigInt(hexlify(bytes.slice(start, end)));
  const nonce = number(1, 9), srcEid = Number(number(9, 13)), sender = hexlify(bytes.slice(13, 45)), dstEid = Number(number(45, 49)), receiver = hexlify(bytes.slice(49, 81));
  const guid = hexlify(bytes.slice(81, 113)), message = hexlify(bytes.slice(113)), recipient = unpad(hexlify(bytes.slice(113, 145))), amountShared = number(145, 153);
  unpad(sender); unpad(receiver);
  if (nonce === 0n || srcEid === 0 || dstEid === 0 || amountShared === 0n || guid !== solidityPackedKeccak256(["uint64", "uint32", "bytes32", "uint32", "bytes32"], [nonce, srcEid, sender, dstEid, receiver])) throw new Error("Invalid OFT packet identity");
  return Object.freeze({ encoded: hexlify(bytes), nonce: nonce.toString(), srcEid, dstEid, sender, receiver, recipient, guid, message, amountShared: amountShared.toString(), payloadHash: keccak256(concat([guid, message])) });
}
function validatePath(path: OftPathway, packet: OftPacket): void {
  if (path.version !== "oft-pathway/1" || path.sourcePin.protocol !== LAYERZERO_SOURCE_PINS.protocol || path.sourcePin.oft !== LAYERZERO_SOURCE_PINS.oft ||
      path.deploymentConformanceVerified !== true || path.zeroValueDirectCreditVerified !== true || path.nonUpgradeableVerified !== true) throw new Error("OFT pathway lacks conformance evidence");
  for (const side of [path.source, path.destination]) {
    if (!Object.hasOwn(genesis, side.chainId) || side.genesisHash !== genesis[side.chainId] || !Number.isSafeInteger(side.eid) || side.eid <= 0 || side.eid >= 2 ** 32 ||
        ![side.endpoint, side.oft, side.token, side.messageLibrary].every(address) || ![side.endpointCodeHash, side.oftCodeHash, side.tokenCodeHash, side.messageLibraryCodeHash].every(bytes32) ||
        !Number.isInteger(side.tokenDecimals) || !Number.isInteger(side.sharedDecimals) || side.sharedDecimals < 0 || side.sharedDecimals > side.tokenDecimals || side.tokenDecimals > 36) throw new Error("Unpinned OFT deployment");
  }
  if (path.source.eid === path.destination.eid || packet.srcEid !== path.source.eid || packet.dstEid !== path.destination.eid || packet.sender !== padded(path.source.oft) || packet.receiver !== padded(path.destination.oft) ||
      path.source.sharedDecimals !== path.destination.sharedDecimals) throw new Error("OFT packet differs from approved direction");
}
async function read(provider: EvmReader, target: string, abi: Interface, name: string, args: readonly unknown[], block: number) {
  return abi.decodeFunctionResult(name, await provider.call({ to: target, data: abi.encodeFunctionData(name, args), blockTag: block }));
}
async function verifyDeployment(side: OftDeployment, peer: OftDeployment, provider: EvmReader, block: number): Promise<void> {
  if ((await provider.getNetwork()).chainId !== BigInt(side.chainId) || (await provider.getBlock(0))?.hash?.toLowerCase() !== side.genesisHash) throw new Error("Wrong OFT network");
  for (const [account, expected] of [[side.endpoint, side.endpointCodeHash], [side.oft, side.oftCodeHash], [side.token, side.tokenCodeHash], [side.messageLibrary, side.messageLibraryCodeHash]]) {
    const code = await provider.getCode(account!, block); if (code === "0x" || keccak256(code) !== expected) throw new Error("OFT deployment changed");
    for (const slot of ["0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc", "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50"]) {
      const value = await provider.getStorage(account!, slot, block); if (!bytes32(value.toLowerCase()) || BigInt(value) !== 0n) throw new Error("Upgradeable OFT deployments require dedicated version/implementation pins");
    }
  }
  if (Number((await read(provider, side.endpoint, endpointAbi, "eid", [], block))[0]) !== side.eid ||
      String((await read(provider, side.oft, oftAbi, "endpoint", [], block))[0]).toLowerCase() !== side.endpoint ||
      String((await read(provider, side.oft, oftAbi, "token", [], block))[0]).toLowerCase() !== side.token ||
      String((await read(provider, side.oft, oftAbi, "peers", [peer.eid], block))[0]).toLowerCase() !== padded(peer.oft) ||
      Number((await read(provider, side.oft, oftAbi, "sharedDecimals", [], block))[0]) !== side.sharedDecimals ||
      BigInt((await read(provider, side.oft, oftAbi, "decimalConversionRate", [], block))[0]) !== 10n ** BigInt(side.tokenDecimals - side.sharedDecimals) ||
      Number((await read(provider, side.token, tokenAbi, "decimals", [], block))[0]) !== side.tokenDecimals) throw new Error("OFT endpoint, peer or units changed");
  const version = await read(provider, side.oft, oftAbi, "oftVersion", [], block);
  if (version[0] !== "0x02e49c2c" || BigInt(version[1]) !== 1n) throw new Error("Unsupported OFT message version");
}
async function finalizedReceipt(provider: EvmReader, hash: string): Promise<EvmReceipt | null> {
  if (!bytes32(hash)) throw new Error("Invalid transport transaction hash"); const receipt = await provider.getTransactionReceipt(hash); if (!receipt) return null;
  if (receipt.hash.toLowerCase() !== hash || receipt.status !== 1 || !Number.isSafeInteger(receipt.blockNumber) || receipt.blockNumber < 0 || !bytes32(receipt.blockHash.toLowerCase())) throw new Error("Invalid transport receipt");
  const finalized = await provider.getBlock("finalized"); if (!finalized) return null;
  if (!Number.isSafeInteger(finalized.number) || finalized.number < 0 || !Number.isSafeInteger(finalized.timestamp) || finalized.timestamp < 0 || !finalized.hash || !bytes32(finalized.hash.toLowerCase())) throw new Error("Invalid transport finality");
  if (receipt.blockNumber > finalized.number) return null;
  const canonical = await provider.getBlock(receipt.blockNumber); if (canonical?.number !== receipt.blockNumber || !Number.isSafeInteger(canonical.timestamp) || canonical.timestamp < 0 || canonical.hash?.toLowerCase() !== receipt.blockHash.toLowerCase()) throw new Error("Transport receipt reorged");
  const finalAnchor = await provider.getBlock(finalized.number); if (finalAnchor?.number !== finalized.number || finalAnchor.hash?.toLowerCase() !== finalized.hash.toLowerCase()) throw new Error("Transport finality changed");
  return receipt;
}

/** Authenticated source PacketSent evidence only, not independently verified payer debit or order acceptance. */
export async function readSourceOftPacket(path: OftPathway, transactionHash: string, logIndex: number, provider: EvmReader): Promise<OftPacket | null> {
  const receipt = await finalizedReceipt(provider, transactionHash); if (!receipt) return null;
  const log = receipt.logs.find((entry) => entry.index === logIndex && entry.address.toLowerCase() === path.source.endpoint);
  if (!log) throw new Error("Missing source endpoint packet"); const event = endpointAbi.parseLog({ topics: [...log.topics], data: log.data });
  if (event?.name !== "PacketSent" || String(event.args[2]).toLowerCase() !== path.source.messageLibrary) throw new Error("Wrong source messaging library");
  const packet = decodeOftPacket(event.args[0]); validatePath(path, packet); await verifyDeployment(path.source, path.destination, provider, receipt.blockNumber);
  const after = await finalizedReceipt(provider, transactionHash);
  if (!after || after.blockHash !== receipt.blockHash || after.blockNumber !== receipt.blockNumber) throw new Error("Source finality lost"); return packet;
}
export type OftReceiveState = "payload_committed" | "nilified" | "unresolved" | "destination_credit_finalized";
export async function observeOftReceive(path: OftPathway, encodedPacket: string, provider: EvmReader, destinationTransactionHash?: string): Promise<{ state: OftReceiveState; packet: OftPacket; destinationQuantityBaseUnits: string }> {
  const packet = decodeOftPacket(encodedPacket); validatePath(path, packet); const side = path.destination;
  const block = await provider.getBlock("latest"); if (!block?.hash || !bytes32(block.hash.toLowerCase()) || !Number.isSafeInteger(block.number) || block.number < 0 || !Number.isSafeInteger(block.timestamp) || block.timestamp < 0) throw new Error("OFT observer unavailable");
  await verifyDeployment(side, path.source, provider, block.number);
  const library = String((await read(provider, side.endpoint, endpointAbi, "getReceiveLibrary", [side.oft, path.source.eid], block.number))[0]).toLowerCase();
  if (library !== side.messageLibrary) throw new Error("OFT receive library changed");
  const amount = (BigInt(packet.amountShared) * 10n ** BigInt(side.tokenDecimals - side.sharedDecimals)).toString();
  let state: OftReceiveState = "unresolved";
  const committed = String((await read(provider, side.endpoint, endpointAbi, "inboundPayloadHash", [side.oft, packet.srcEid, packet.sender, packet.nonce], block.number))[0]).toLowerCase();
  if (committed === packet.payloadHash) state = "payload_committed";
  else if (committed === "0x" + "f".repeat(64)) state = "nilified";
  else if (committed !== "0x" + "0".repeat(64)) throw new Error("Destination payload differs from packet");
  if (destinationTransactionHash) {
    const receipt = await finalizedReceipt(provider, destinationTransactionHash);
    if (receipt) {
      await verifyDeployment(side, path.source, provider, receipt.blockNumber);
      const received = receipt.logs.filter((log) => { if (log.address.toLowerCase() !== side.oft) return false;
        const event = oftAbi.parseLog({ topics: [...log.topics], data: log.data }); return event?.name === "OFTReceived" && event.args[0] === packet.guid && Number(event.args[1]) === packet.srcEid && String(event.args[2]).toLowerCase() === packet.recipient && BigInt(event.args[3]).toString() === amount; });
      const credits = receipt.logs.filter((log) => { if (log.address.toLowerCase() !== side.token) return false;
        const event = tokenAbi.parseLog({ topics: [...log.topics], data: log.data }); return event?.name === "Transfer" && String(event.args[1]).toLowerCase() === packet.recipient && BigInt(event.args[2]).toString() === amount; });
      const delivered = receipt.logs.filter((log) => { if (log.address.toLowerCase() !== side.endpoint) return false;
        const event = endpointAbi.parseLog({ topics: [...log.topics], data: log.data }); return event?.name === "PacketDelivered" && Number(event.args[0][0]) === packet.srcEid && event.args[0][1] === packet.sender && BigInt(event.args[0][2]).toString() === packet.nonce && String(event.args[1]).toLowerCase() === side.oft; });
      if (received.length !== 1 || credits.length !== 1 || delivered.length !== 1) throw new Error("Endpoint consumption does not prove exact OFT token credit");
      const after = await finalizedReceipt(provider, destinationTransactionHash);
      if (!after || after.blockHash !== receipt.blockHash || after.blockNumber !== receipt.blockNumber) throw new Error("Destination finality lost"); state = "destination_credit_finalized";
    }
  }
  const snapshot = await provider.getBlock(block.number);
  if (snapshot?.number !== block.number || snapshot.hash?.toLowerCase() !== block.hash.toLowerCase()) throw new Error("OFT snapshot reorged");
  return Object.freeze({ state, packet, destinationQuantityBaseUnits: amount });
}
export interface OftRetryReader extends EvmReader {
  call(transaction: { to: string; data: string; blockTag?: number; from?: string; value?: bigint; gasLimit?: bigint }): Promise<string>;
  estimateGas(transaction: { from: string; to: string; data: string; value: bigint }): Promise<bigint>;
}
/** Creates an unsigned, expiring zero-value direct receive retry. It never signs, sends, refunds or claims merchant acceptance. */
export async function buildOftRetry(path: OftPathway, encodedPacket: string, payer: string, provider: OftRetryReader, clock: () => number, maxGasLimit: bigint, maxFeePerGasWei: bigint) {
  if (!address(payer) || typeof maxGasLimit !== "bigint" || typeof maxFeePerGasWei !== "bigint" || maxGasLimit <= 0n || maxGasLimit > 10_000_000n || maxFeePerGasWei <= 0n || maxGasLimit * maxFeePerGasWei >= 1n << 256n) throw new Error("Invalid retry authority or gas cap");
  const observed = await observeOftReceive(path, encodedPacket, provider); if (observed.state !== "payload_committed") throw new Error("OFT retry requires the exact destination commitment");
  const { packet } = observed, side = path.destination;
  const nonce = BigInt(packet.nonce);
  const checkNonceWindow = async (): Promise<void> => {
    const block = await provider.getBlock("latest");
    if (!block?.hash || !bytes32(block.hash.toLowerCase()) || !Number.isSafeInteger(block.number) || block.number < 0 || !Number.isSafeInteger(block.timestamp) || block.timestamp < 0) throw new Error("Missing retry snapshot");
    const lazy = BigInt((await read(provider, side.endpoint, endpointAbi, "lazyInboundNonce", [side.oft, packet.srcEid, packet.sender], block.number))[0]);
    if (nonce > lazy + 64n) throw new Error("OFT nonce gap needs bounded intervention");
    for (let current = lazy + 1n; current < nonce; current++) {
      if (BigInt((await read(provider, side.endpoint, endpointAbi, "inboundPayloadHash", [side.oft, packet.srcEid, packet.sender, current], block.number))[0]) === 0n) throw new Error("OFT preceding nonce has not been verified");
    }
    const snapshot = await provider.getBlock(block.number);
    if (snapshot?.number !== block.number || snapshot.hash?.toLowerCase() !== block.hash.toLowerCase()) throw new Error("OFT retry snapshot reorged");
  };
  await checkNonceWindow();
  const data = endpointAbi.encodeFunctionData("lzReceive", [[packet.srcEid, packet.sender, nonce], side.oft, packet.guid, packet.message, "0x"]);
  const transaction = { from: payer, to: side.endpoint, data, value: 0n };
  if (await provider.call({ ...transaction, gasLimit: maxGasLimit }) !== "0x") throw new Error("Invalid OFT retry simulation");
  const gas = await provider.estimateGas(transaction);
  if (typeof gas !== "bigint" || gas <= 0n || gas > maxGasLimit) throw new Error("OFT retry exceeds gas budget");
  // A changing commitment/config during simulation must not publish a stale executable hint.
  if ((await observeOftReceive(path, encodedPacket, provider)).state !== "payload_committed") throw new Error("OFT retry state changed");
  await checkNonceWindow();
  const createdAt = clock(); if (!Number.isSafeInteger(createdAt) || createdAt < 0 || !Number.isSafeInteger(createdAt + 60)) throw new Error("Invalid retry clock");
  return Object.freeze({ version: "oft-retry/1" as const, chainId: side.chainId, genesisHash: side.genesisHash, ...transaction, value: "0" as const,
    gasLimit: maxGasLimit.toString(), maxFeePerGasWei: maxFeePerGasWei.toString(), maxGasCostWei: (maxGasLimit * maxFeePerGasWei).toString(), estimatedGas: gas.toString(), createdAt, expiresAt: createdAt + 60, guid: packet.guid });
}
