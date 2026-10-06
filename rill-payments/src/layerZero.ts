import { AbiCoder, Interface, concat, getBytes, hexlify, keccak256, solidityPackedKeccak256 } from "ethers";
import type { EvmReader, EvmReceipt } from "./evmReceipt";

export const LAYERZERO_SOURCE_PINS = Object.freeze({ protocol: "9c741e7f9790639537b1710a203bcdfd73b0b9ac", oft: "4973ba8bef7b0fdf7268469abea3ea50dbd4bbd8" });
const endpointAbi = new Interface([
  "function eid() view returns(uint32)", "function inboundPayloadHash(address,uint32,bytes32,uint64) view returns(bytes32)",
  "function lazyInboundNonce(address,uint32,bytes32) view returns(uint64)", "function getReceiveLibrary(address,uint32) view returns(address,bool)",
  "function getSendLibrary(address,uint32) view returns(address)",
  "function receiveLibraryTimeout(address,uint32) view returns(address,uint256)",
  "function defaultReceiveLibraryTimeout(uint32) view returns(address,uint256)",
  "function getConfig(address,address,uint32,uint32) view returns(bytes)",
  "function lzReceive((uint32 srcEid,bytes32 sender,uint64 nonce),address,bytes32,bytes,bytes) payable",
  "event PacketSent(bytes encodedPayload,bytes options,address sendLibrary)",
  "event PacketDelivered((uint32 srcEid,bytes32 sender,uint64 nonce) origin,address receiver)",
]);
const oftAbi = new Interface(["function endpoint() view returns(address)", "function peers(uint32) view returns(bytes32)", "function token() view returns(address)",
  "function sharedDecimals() view returns(uint8)", "function decimalConversionRate() view returns(uint256)",
  "function oftVersion() pure returns(bytes4,uint64)", "event OFTReceived(bytes32 indexed guid,uint32 srcEid,address indexed toAddress,uint256 amountReceivedLD)"]);
const sendParam = "(uint32 dstEid,bytes32 to,uint256 amountLD,uint256 minAmountLD,bytes extraOptions,bytes composeMsg,bytes oftCmd)";
const quoteAbi = new Interface([
  `function quoteOFT(${sendParam}) view returns((uint256 minAmountLD,uint256 maxAmountLD),(int256 feeAmountLD,string description)[],(uint256 amountSentLD,uint256 amountReceivedLD))`,
  `function quoteSend(${sendParam},bool) view returns((uint256 nativeFee,uint256 lzTokenFee))`,
  "function combineOptions(uint32,uint16,bytes) view returns(bytes)",
]);
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

export interface Uln302ConfigurationRequest {
  readonly version: "layerzero-uln302-observation/1";
  readonly chainId: string; readonly genesisHash: string; readonly eid: number; readonly remoteEid: number;
  readonly endpoint: { readonly address: string; readonly codeHash: string };
  readonly oapp: { readonly address: string; readonly codeHash: string };
  /** Caller-recognized profile and runtime pins, not discovered from version(). */
  readonly library: { readonly address: string; readonly codeHash: string; readonly kind: "send" | "receive" };
  readonly block: { readonly number: number; readonly hash: string };
}
export type Uln302ConfigurationReader = Pick<EvmReader, "getNetwork" | "getBlock" | "getCode" | "call">;
export interface Uln302ConfigurationObservation {
  readonly version: "layerzero-uln302-observation/1"; readonly authority: "none";
  readonly abiSourcePin: string; readonly request: Readonly<Uln302ConfigurationRequest>;
  readonly blockTimestamp: number;
  readonly uln: { readonly confirmations: string; readonly requiredDVNs: readonly string[];
    readonly optionalDVNs: readonly string[]; readonly optionalDVNThreshold: number };
  readonly executor: { readonly maxMessageSize: number; readonly address: string; readonly configured: boolean } | null;
  readonly receive: { readonly isDefault: boolean; readonly timeoutLibrary: string; readonly expiryBlock: string;
    readonly withinWindow: boolean; readonly nonzeroLibraryWithinWindow: boolean; readonly timeoutLibraryConfiguration: "not_observed" } | null;
}
const libraryAbi = new Interface(["function version() pure returns(uint64,uint8,uint8)"]);
const ulnType = "tuple(uint64 confirmations,uint8 requiredDVNCount,uint8 optionalDVNCount,uint8 optionalDVNThreshold,address[] requiredDVNs,address[] optionalDVNs)";
const executorType = "tuple(uint32 maxMessageSize,address executor)";
const configurationCoder = AbiCoder.defaultAbiCoder();
const zeroAddress = "0x" + "0".repeat(40);

/** Explicit, read-only observation of one caller-recognized ULN302 direction.
 * Pins and RPC consistency are not independent source, policy, upgrade or route
 * conformance proof. This never grants execution, acceptance or recovery rights.
 */
export async function observeUln302Configuration(input: Uln302ConfigurationRequest, provider: Uln302ConfigurationReader): Promise<Uln302ConfigurationObservation> {
  try {
    const request: Uln302ConfigurationRequest = Object.freeze({ version: input.version, chainId: input.chainId, genesisHash: input.genesisHash,
      eid: input.eid, remoteEid: input.remoteEid, endpoint: Object.freeze({ address: input.endpoint.address, codeHash: input.endpoint.codeHash }),
      oapp: Object.freeze({ address: input.oapp.address, codeHash: input.oapp.codeHash }),
      library: Object.freeze({ address: input.library.address, codeHash: input.library.codeHash, kind: input.library.kind }),
      block: Object.freeze({ number: input.block.number, hash: input.block.hash }) });
    const nonzeroHash = (value: string) => typeof value === "string" && bytes32(value) && BigInt(value) !== 0n;
    const eid = (value: number) => Number.isSafeInteger(value) && value > 0 && value < 2 ** 32;
    if (request.version !== "layerzero-uln302-observation/1" || typeof request.chainId !== "string" || !/^[1-9][0-9]{0,77}$/.test(request.chainId) || BigInt(request.chainId) >= 1n << 256n ||
        !nonzeroHash(request.genesisHash) || !eid(request.eid) || !eid(request.remoteEid) || request.eid === request.remoteEid ||
        ![request.endpoint, request.oapp, request.library].every((pin) => typeof pin.address === "string" && address(pin.address) && nonzeroHash(pin.codeHash)) ||
        !["send", "receive"].includes(request.library.kind) || !Number.isSafeInteger(request.block.number) || request.block.number < 0 || !nonzeroHash(request.block.hash)) throw new Error();
    const network = provider.getNetwork.bind(provider), block = provider.getBlock.bind(provider), code = provider.getCode.bind(provider), call = provider.call.bind(provider);
    const anchor = async () => {
      const actual = await block(request.block.number);
      if ((await network()).chainId !== BigInt(request.chainId) || (await block(0))?.hash?.toLowerCase() !== request.genesisHash ||
          actual?.number !== request.block.number || actual.hash?.toLowerCase() !== request.block.hash ||
          !Number.isSafeInteger(actual.timestamp) || actual.timestamp < 0) throw new Error();
      return actual.timestamp;
    };
    const timestamp = await anchor();
    for (const pin of [request.endpoint, request.oapp, request.library]) {
      const runtime = await code(pin.address, request.block.number);
      if (runtime === "0x" || keccak256(runtime) !== pin.codeHash) throw new Error();
    }
    const decoded = async (abi: Interface, target: string, name: string, args: readonly unknown[]) => {
      const raw = await call({ to: target, data: abi.encodeFunctionData(name, args), blockTag: request.block.number });
      // Bound both dynamic ABI layers before decoding, allowing the full pinned
      // protocol's two 127-address DVN arrays plus wrapping and headroom.
      if (!/^0x(?:[0-9a-fA-F]{2})*$/.test(raw) || raw.length > 2 + 2 * 33_024) throw new Error();
      const value = abi.decodeFunctionResult(name, raw);
      if (abi.encodeFunctionResult(name, value) !== raw.toLowerCase()) throw new Error();
      return value;
    };
    if (Number((await decoded(endpointAbi, request.endpoint.address, "eid", []))[0]) !== request.eid) throw new Error();
    const selected = await decoded(endpointAbi, request.endpoint.address, request.library.kind === "send" ? "getSendLibrary" : "getReceiveLibrary", [request.oapp.address, request.remoteEid]);
    if (String(selected[0]).toLowerCase() !== request.library.address) throw new Error();
    const version = await decoded(libraryAbi, request.library.address, "version", []);
    if (BigInt(version[0]) !== 3n || Number(version[1]) !== 0 || Number(version[2]) !== 2) throw new Error();
    const config = async (type: string, configType: number) => {
      const encoded = String((await decoded(endpointAbi, request.endpoint.address, "getConfig", [request.oapp.address, request.library.address, request.remoteEid, configType]))[0]);
      if (encoded.length > 2 + 2 * 32_768) throw new Error();
      const value = configurationCoder.decode([type], encoded);
      if (configurationCoder.encode([type], value) !== encoded.toLowerCase()) throw new Error();
      return value[0];
    };
    const effective = await config(ulnType, 2);
    const dvns = (values: readonly string[], count: bigint): readonly string[] => {
      if (count > 127n || BigInt(values.length) !== count) throw new Error();
      const result = values.map((value) => value.toLowerCase());
      if (result.some((value, index) => !address(value) || (index > 0 && BigInt(value) <= BigInt(result[index - 1]!)))) throw new Error();
      return Object.freeze(result);
    };
    const requiredDVNs = dvns(effective.requiredDVNs, BigInt(effective.requiredDVNCount)), optionalDVNs = dvns(effective.optionalDVNs, BigInt(effective.optionalDVNCount));
    const threshold = Number(effective.optionalDVNThreshold);
    if ((optionalDVNs.length ? threshold < 1 || threshold > optionalDVNs.length : threshold !== 0) || requiredDVNs.length + optionalDVNs.length === 0 || BigInt(effective.confirmations) === (1n << 64n) - 1n) throw new Error();
    const uln = Object.freeze({ confirmations: BigInt(effective.confirmations).toString(), requiredDVNs, optionalDVNs, optionalDVNThreshold: threshold });
    let executor: Uln302ConfigurationObservation["executor"] = null, receive: Uln302ConfigurationObservation["receive"] = null;
    if (request.library.kind === "send") {
      const value = await config(executorType, 1), maxMessageSize = Number(value.maxMessageSize), executorAddress = String(value.executor).toLowerCase();
      executor = Object.freeze({ maxMessageSize, address: executorAddress, configured: maxMessageSize > 0 && executorAddress !== zeroAddress });
    } else {
      const isDefault = selected[1] as boolean;
      const timeout = await decoded(endpointAbi, request.endpoint.address, isDefault ? "defaultReceiveLibraryTimeout" : "receiveLibraryTimeout", isDefault ? [request.remoteEid] : [request.oapp.address, request.remoteEid]);
      const timeoutLibrary = String(timeout[0]).toLowerCase(), expiry = BigInt(timeout[1]), withinWindow = expiry > BigInt(request.block.number);
      receive = Object.freeze({ isDefault, timeoutLibrary, expiryBlock: expiry.toString(), withinWindow,
        nonzeroLibraryWithinWindow: withinWindow && timeoutLibrary !== zeroAddress, timeoutLibraryConfiguration: "not_observed" });
    }
    if (await anchor() !== timestamp) throw new Error();
    return Object.freeze({ version: "layerzero-uln302-observation/1", authority: "none", abiSourcePin: LAYERZERO_SOURCE_PINS.protocol,
      request, blockTimestamp: timestamp, uln, executor, receive });
  } catch { throw new Error("LayerZero configuration observation refused"); }
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
function validatePathway(path: OftPathway): void {
  if (path.version !== "oft-pathway/1" || path.sourcePin.protocol !== LAYERZERO_SOURCE_PINS.protocol || path.sourcePin.oft !== LAYERZERO_SOURCE_PINS.oft ||
      path.deploymentConformanceVerified !== true || path.zeroValueDirectCreditVerified !== true || path.nonUpgradeableVerified !== true) throw new Error("OFT pathway lacks conformance evidence");
  for (const side of [path.source, path.destination]) {
    if (!Object.hasOwn(genesis, side.chainId) || side.genesisHash !== genesis[side.chainId] || !Number.isSafeInteger(side.eid) || side.eid <= 0 || side.eid >= 2 ** 32 ||
        ![side.endpoint, side.oft, side.token, side.messageLibrary].every(address) || ![side.endpointCodeHash, side.oftCodeHash, side.tokenCodeHash, side.messageLibraryCodeHash].every(bytes32) ||
        !Number.isInteger(side.tokenDecimals) || !Number.isInteger(side.sharedDecimals) || side.sharedDecimals < 0 || side.sharedDecimals > side.tokenDecimals || side.tokenDecimals > 36) throw new Error("Unpinned OFT deployment");
  }
  if (path.source.eid === path.destination.eid || path.source.sharedDecimals !== path.destination.sharedDecimals) throw new Error("OFT packet differs from approved direction");
}
function validatePath(path: OftPathway, packet: OftPacket): void {
  validatePathway(path);
  if (packet.srcEid !== path.source.eid || packet.dstEid !== path.destination.eid || packet.sender !== padded(path.source.oft) || packet.receiver !== padded(path.destination.oft)) throw new Error("OFT packet differs from approved direction");
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
export interface OftQuoteReader extends EvmReader {
  call(transaction: { to: string; data: string; blockTag?: number; from?: string }): Promise<string>;
}
export interface OftSendQuoteRequest {
  readonly sourceWallet: string; readonly recipient: string;
  readonly amountLD: string; readonly minAmountLD: string;
  readonly extraOptions: string; readonly nativeFeeCapWei: string; readonly maxReceiveGas: string;
}
function quoteUint(value: string, bits = 256): bigint {
  if (typeof value !== "string" || !/^(0|[1-9][0-9]{0,77})$/.test(value) || BigInt(value) >= 1n << BigInt(bits)) throw new Error("Invalid OFT quote quantity");
  return BigInt(value);
}
function quoteBlock(block: Awaited<ReturnType<EvmReader["getBlock"]>>) {
  if (!block?.hash || !bytes32(block.hash.toLowerCase()) || !Number.isSafeInteger(block.number) || block.number < 0 || !Number.isSafeInteger(block.timestamp) || block.timestamp < 0) throw new Error("Missing OFT quote snapshot");
  return Object.freeze({ number: block.number, hash: block.hash.toLowerCase(), timestamp: block.timestamp });
}
function quoteDeployment(side: OftDeployment, block: ReturnType<typeof quoteBlock>) {
  // Do not serialize unexpected caller-owned metadata alongside public pins.
  return Object.freeze({ chainId: side.chainId, genesisHash: side.genesisHash, eid: side.eid,
    endpoint: side.endpoint, endpointCodeHash: side.endpointCodeHash, oft: side.oft, oftCodeHash: side.oftCodeHash,
    token: side.token, tokenCodeHash: side.tokenCodeHash, tokenDecimals: side.tokenDecimals, sharedDecimals: side.sharedDecimals,
    messageLibrary: side.messageLibrary, messageLibraryCodeHash: side.messageLibraryCodeHash,
    blockNumber: block.number, blockHash: block.hash, blockTimestamp: block.timestamp });
}
async function quoteRead(provider: OftQuoteReader, target: string, abi: Interface, name: string, args: readonly unknown[], block: number, from: string) {
  const raw = await provider.call({ to: target, data: abi.encodeFunctionData(name, args), blockTag: block, from });
  if (typeof raw !== "string" || !/^0x([0-9a-fA-F]{2})*$/.test(raw) || raw.length > 32770) throw new Error("Malformed OFT quote response");
  const result = abi.decodeFunctionResult(name, raw);
  if (abi.encodeFunctionResult(name, result).toLowerCase() !== raw.toLowerCase()) throw new Error("Noncanonical OFT quote response");
  return result;
}
function receiveGas(options: string, cap: bigint): bigint {
  const data = getBytes(options);
  if (![22, 38].includes(data.length) || data[0] !== 0 || data[1] !== 3 || data[2] !== 1 || data[3] !== 0 || data[4] !== data.length - 5 || data[5] !== 1) throw new Error("Unsupported merged OFT receive options");
  const gas = BigInt(hexlify(data.slice(6, 22)));
  if (gas === 0n || gas > cap || (data.length === 38 && BigInt(hexlify(data.slice(22))) !== 0n)) throw new Error("OFT receive gas or native value exceeds policy");
  return gas;
}
/** Read-only, advisory default-debit quote. Never spendability, delivery or receipt authority. */
export async function quoteOftSend(path: OftPathway, request: OftSendQuoteRequest, sourceProvider: OftQuoteReader, destinationProvider: EvmReader, clock: () => number) {
  // Capture all caller-owned configuration before asynchronous reads. Conformance
  // flags are trusted prerequisites, not conformance discovered by quoting.
  const approved = { ...path, sourcePin: { protocol: path.sourcePin.protocol, oft: path.sourcePin.oft }, source: { ...path.source }, destination: { ...path.destination } };
  const input = { ...request }; validatePathway(approved);
  const amount = quoteUint(input.amountLD), minimum = quoteUint(input.minAmountLD), feeCap = quoteUint(input.nativeFeeCapWei), gasCap = quoteUint(input.maxReceiveGas, 128);
  if (!address(input.sourceWallet) || !address(input.recipient) || amount === 0n || minimum === 0n || minimum > amount || gasCap === 0n ||
      typeof input.extraOptions !== "string" || !/^0x([0-9a-f]{2})*$/.test(input.extraOptions) || input.extraOptions.length > 8194 || (input.extraOptions !== "0x" && !input.extraOptions.startsWith("0x0003"))) throw new Error("Invalid OFT send quote request");
  const createdAt = clock(), expiresAt = createdAt + 60;
  if (!Number.isSafeInteger(createdAt) || createdAt < 0 || !Number.isSafeInteger(expiresAt)) throw new Error("Invalid OFT quote clock");
  const { source, destination } = approved;
  const rate = 10n ** BigInt(source.tokenDecimals - source.sharedDecimals), sent = amount / rate * rate, shared = sent / rate;
  const destinationAmount = shared * 10n ** BigInt(destination.tokenDecimals - destination.sharedDecimals);
  if (sent === 0n || sent < minimum || shared >= 1n << 64n || destinationAmount >= 1n << 256n) throw new Error("OFT quote amount cannot meet minimum or shared units");
  try {
    const sourceBlock = quoteBlock(await sourceProvider.getBlock("latest")), destinationBlock = quoteBlock(await destinationProvider.getBlock("latest"));
    await verifyDeployment(source, destination, sourceProvider, sourceBlock.number);
    await verifyDeployment(destination, source, destinationProvider, destinationBlock.number);
    const from = input.sourceWallet;
    const library = String((await quoteRead(sourceProvider, source.endpoint, endpointAbi, "getSendLibrary", [source.oft, destination.eid], sourceBlock.number, from))[0]).toLowerCase();
    const receiveLibrary = String((await read(destinationProvider, destination.endpoint, endpointAbi, "getReceiveLibrary", [destination.oft, source.eid], destinationBlock.number))[0]).toLowerCase();
    if (library !== source.messageLibrary || receiveLibrary !== destination.messageLibrary) throw new Error("OFT quote messaging library changed");
    const mergedOptions = String((await quoteRead(sourceProvider, source.oft, quoteAbi, "combineOptions", [destination.eid, 1, input.extraOptions], sourceBlock.number, from))[0]).toLowerCase();
    const gas = receiveGas(mergedOptions, gasCap);
    // Quote the ORIGINAL extras, never the merged options (which would apply
    // enforced options twice). Compose and command cannot be supplied here.
    const params = [destination.eid, padded(input.recipient), amount, minimum, input.extraOptions, "0x", "0x"];
    const [limits, fees, receipt] = await quoteRead(sourceProvider, source.oft, quoteAbi, "quoteOFT", [params], sourceBlock.number, from);
    const [messaging] = await quoteRead(sourceProvider, source.oft, quoteAbi, "quoteSend", [params, false], sourceBlock.number, from);
    if (fees.length !== 0 || BigInt(receipt[0]) !== sent || BigInt(receipt[1]) !== sent || BigInt(limits[0]) > BigInt(limits[1]) || sent < BigInt(limits[0]) || sent > BigInt(limits[1])) throw new Error("Unsupported OFT debit or nominal limits");
    if (BigInt(messaging[1]) !== 0n || BigInt(messaging[0]) > feeCap) throw new Error("OFT messaging fees exceed native-only budget");
    for (const [provider, block] of [[sourceProvider, sourceBlock], [destinationProvider, destinationBlock]] as const) {
      const after = quoteBlock(await provider.getBlock(block.number));
      if (after.number !== block.number || after.hash !== block.hash || after.timestamp !== block.timestamp) throw new Error("OFT quote snapshot changed");
    }
    const completedAt = clock();
    if (!Number.isSafeInteger(completedAt) || completedAt < createdAt || completedAt >= expiresAt) throw new Error("OFT quote construction expired");
    return Object.freeze({ version: "oft-send-quote/1" as const,
      sourcePin: Object.freeze({ protocol: approved.sourcePin.protocol, oft: approved.sourcePin.oft }),
      source: quoteDeployment(source, sourceBlock), destination: quoteDeployment(destination, destinationBlock),
      sourceWallet: input.sourceWallet, recipient: input.recipient, amountLD: input.amountLD, minAmountLD: input.minAmountLD,
      amountSentLD: sent.toString(), amountReceivedLD: sent.toString(), destinationAmountLD: destinationAmount.toString(), dustLD: (amount - sent).toString(),
      limits: Object.freeze({ minAmountLD: BigInt(limits[0]).toString(), maxAmountLD: BigInt(limits[1]).toString() }),
      nativeFeeWei: BigInt(messaging[0]).toString(), lzTokenFeeWei: "0" as const, nativeFeeCapWei: input.nativeFeeCapWei,
      extraOptions: input.extraOptions, mergedOptions, receiveGas: gas.toString(), maxReceiveGas: input.maxReceiveGas,
      sourceGasCostIncluded: false as const, createdAt, completedAt, expiresAt });
  } catch {
    // RPC exceptions may retain provider credentials or private upstream data.
    throw new Error("OFT send quote observation is unresolved");
  }
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
