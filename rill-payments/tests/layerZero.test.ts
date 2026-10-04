import { expect, test } from "bun:test";
import { Interface, concat, keccak256, solidityPacked, solidityPackedKeccak256 } from "ethers";
import { buildOftRetry, decodeOftPacket, LAYERZERO_SOURCE_PINS, observeOftReceive, readSourceOftPacket, type OftPathway, type OftRetryReader } from "../src/layerZero";
import type { EvmReceipt } from "../src/evmReceipt";

const endpoint = new Interface([
  "function eid() view returns(uint32)", "function inboundPayloadHash(address,uint32,bytes32,uint64) view returns(bytes32)", "function lazyInboundNonce(address,uint32,bytes32) view returns(uint64)",
  "function getReceiveLibrary(address,uint32) view returns(address,bool)", "function lzReceive((uint32 srcEid,bytes32 sender,uint64 nonce),address,bytes32,bytes,bytes) payable",
  "event PacketSent(bytes encodedPayload,bytes options,address sendLibrary)", "event PacketDelivered((uint32 srcEid,bytes32 sender,uint64 nonce) origin,address receiver)",
]);
const oft = new Interface(["function endpoint() view returns(address)", "function peers(uint32) view returns(bytes32)", "function token() view returns(address)", "function sharedDecimals() view returns(uint8)",
  "function decimalConversionRate() view returns(uint256)", "function oftVersion() pure returns(bytes4,uint64)", "event OFTReceived(bytes32 indexed guid,uint32 srcEid,address indexed toAddress,uint256 amountReceivedLD)"]);
const erc20 = new Interface(["function decimals() view returns(uint8)", "event Transfer(address indexed from,address indexed to,uint256 value)"]);
const addr = (n: number): string => "0x" + n.toString(16).padStart(40, "0"), hash = (n: number): string => "0x" + n.toString(16).padStart(64, "0"), padded = (a: string) => "0x" + "0".repeat(24) + a.slice(2);
function fixture(nonce = 2n) {
  const code = "0x60006000", codeHash = keccak256(code);
  const deployment = (n: number, eid: number) => ({ chainId: "11155111", genesisHash: "0x25a5cc106eea7138acab33231d7160d69cb777ee0c2c553fcddf5138993e6dd9", eid,
    endpoint: addr(n), endpointCodeHash: codeHash, oft: addr(n + 1), oftCodeHash: codeHash, token: addr(n + 2), tokenCodeHash: codeHash, tokenDecimals: 6, sharedDecimals: 6, messageLibrary: addr(n + 3), messageLibraryCodeHash: codeHash });
  const path: OftPathway = { version: "oft-pathway/1", sourcePin: LAYERZERO_SOURCE_PINS, source: deployment(10, 30101), destination: deployment(20, 30102),
    deploymentConformanceVerified: true, zeroValueDirectCreditVerified: true, nonUpgradeableVerified: true };
  const source = path.source, destination = path.destination, recipient = addr(30), sender = padded(source.oft), receiver = padded(destination.oft);
  const guid = solidityPackedKeccak256(["uint64", "uint32", "bytes32", "uint32", "bytes32"], [nonce, source.eid, sender, destination.eid, receiver]);
  const message = solidityPacked(["bytes32", "uint64"], [padded(recipient), 1000000n]);
  const encoded = solidityPacked(["uint8", "uint64", "uint32", "bytes32", "uint32", "bytes32", "bytes32", "bytes"], [1, nonce, source.eid, sender, destination.eid, receiver, guid, message]);
  let commitment = keccak256(concat([guid, message])), lazy = 1n, simulations = 0, gas = 50000n, finalized: number | null = 50;
  const eventLog = (abi: Interface, name: string, args: unknown[], account: string, index: number) => ({ address: account, index, ...abi.encodeEventLog(abi.getEvent(name)!, args) });
  const sourceReceipt: EvmReceipt = { hash: hash(100), status: 1, blockNumber: 42, blockHash: hash(42), logs: [eventLog(endpoint, "PacketSent", [encoded, "0x", source.messageLibrary], source.endpoint, 1)] };
  const destinationReceipt: EvmReceipt = { hash: hash(200), status: 1, blockNumber: 43, blockHash: hash(43), logs: [
    eventLog(endpoint, "PacketDelivered", [[source.eid, sender, nonce], destination.oft], destination.endpoint, 1),
    eventLog(oft, "OFTReceived", [guid, source.eid, recipient, 1000000n], destination.oft, 2),
    eventLog(erc20, "Transfer", [addr(0), recipient, 1000000n], destination.token, 3),
  ] };
  const reader = (side: typeof source, peer: typeof source): OftRetryReader => ({
    getNetwork: async () => ({ chainId: 11155111n }), getBlock: async (tag) => tag === "finalized" ? (finalized === null ? null : { number: finalized, hash: hash(finalized), timestamp: 1500 }) :
      tag === 0 ? { number: 0, hash: side.genesisHash, timestamp: 0 } : { number: tag === "latest" ? 44 : tag, hash: hash(tag === "latest" ? 44 : tag), timestamp: 1400 },
    getCode: async () => code, getStorage: async () => hash(0), getLogs: async () => [], getTransactionCount: async () => 0, getTransaction: async () => null,
    getTransactionReceipt: async (h) => h === sourceReceipt.hash ? sourceReceipt : h === destinationReceipt.hash ? destinationReceipt : null,
    estimateGas: async () => gas,
    call: async (tx) => {
      const abi = tx.to === side.endpoint ? endpoint : tx.to === side.oft ? oft : erc20;
      const parsed = abi.parseTransaction({ data: tx.data })!; let result: unknown[];
      switch (parsed.name) {
        case "eid": result = [side.eid]; break;
        case "endpoint": result = [side.endpoint]; break;
        case "token": result = [side.token]; break;
        case "peers": result = [padded(peer.oft)]; break;
        case "sharedDecimals": result = [6]; break;
        case "decimals": result = [6]; break;
        case "decimalConversionRate": result = [1n]; break;
        case "oftVersion": result = ["0x02e49c2c", 1]; break;
        case "getReceiveLibrary": result = [side.messageLibrary, false]; break;
        case "lazyInboundNonce": result = [lazy]; break;
        case "inboundPayloadHash": result = [BigInt(parsed.args[3]) === nonce ? commitment : hash(1)]; break;
        case "lzReceive": simulations++; expect(tx.value).toBe(0n); expect(parsed.args[1].toLowerCase()).toBe(destination.oft); return "0x";
        default: throw new Error("Unexpected read");
      }
      return abi.encodeFunctionResult(parsed.name, result);
    },
  });
  return { path, encoded, recipient, guid, sourceReceipt, destinationReceipt, sourceReader: reader(source, destination), destinationReader: reader(destination, source),
    commitment: (value: string) => { commitment = value; }, lazy: (value: bigint) => { lazy = value; }, gas: (value: bigint) => { gas = value; }, finalize: (value: number | null) => { finalized = value; }, simulations: () => simulations };
}
test("PacketV1 identity/hash/units decode and finalized source PacketSent authenticate routing evidence", async () => {
  const f = fixture(); const packet = decodeOftPacket(f.encoded); expect(packet.guid).toBe(f.guid); expect(packet.recipient).toBe(f.recipient); expect(packet.amountShared).toBe("1000000");
  expect(await readSourceOftPacket(f.path, f.sourceReceipt.hash, 1, f.sourceReader)).toEqual(packet);
  expect(() => decodeOftPacket(f.encoded + "00")).toThrow("noncompose");
  expect(() => decodeOftPacket(f.encoded.replace(f.guid.slice(2), "0".repeat(64)))).toThrow("identity");
});
test("committed, cleared and nilified states never mean merchant receipt", async () => {
  const f = fixture(); expect((await observeOftReceive(f.path, f.encoded, f.destinationReader)).state).toBe("payload_committed");
  f.commitment(hash(0)); expect((await observeOftReceive(f.path, f.encoded, f.destinationReader)).state).toBe("unresolved");
  f.commitment("0x" + "f".repeat(64)); expect((await observeOftReceive(f.path, f.encoded, f.destinationReader)).state).toBe("nilified");
});
test("finalized destination credit requires endpoint origin, OFT event and actual token Transfer", async () => {
  const f = fixture(); f.commitment(hash(0)); expect((await observeOftReceive(f.path, f.encoded, f.destinationReader, f.destinationReceipt.hash)).state).toBe("destination_credit_finalized");
  (f.destinationReceipt.logs as unknown[]).pop(); await expect(observeOftReceive(f.path, f.encoded, f.destinationReader, f.destinationReceipt.hash)).rejects.toThrow("does not prove");
});
test("direct retry artifact is packet-derived zero-value, bounded and unsigned", async () => {
  const f = fixture(); const artifact = await buildOftRetry(f.path, f.encoded, addr(40), f.destinationReader, () => 1000, 100000n, 10n);
  expect(artifact.to).toBe(f.path.destination.endpoint); expect(artifact.value).toBe("0"); expect(artifact.maxGasCostWei).toBe("1000000"); expect(artifact.expiresAt).toBe(1060); expect(f.simulations()).toBe(1);
  expect(endpoint.parseTransaction({ data: artifact.data })?.name).toBe("lzReceive"); expect(JSON.stringify(artifact)).not.toContain("refund");
});
test("nilified/missing payload, nonce gap, unverified deployment and excess gas cannot retry", async () => {
  const f = fixture(); f.commitment(hash(0)); await expect(buildOftRetry(f.path, f.encoded, addr(40), f.destinationReader, () => 1000, 100000n, 10n)).rejects.toThrow("commitment");
  const gap = fixture(100n); await expect(buildOftRetry(gap.path, gap.encoded, addr(40), gap.destinationReader, () => 1000, 100000n, 10n)).rejects.toThrow("nonce gap");
  const expensive = fixture(); expensive.gas(100001n); await expect(buildOftRetry(expensive.path, expensive.encoded, addr(40), expensive.destinationReader, () => 1000, 100000n, 10n)).rejects.toThrow("gas budget");
  const invalid = fixture(); await expect(observeOftReceive({ ...invalid.path, deploymentConformanceVerified: false as true }, invalid.encoded, invalid.destinationReader)).rejects.toThrow("conformance");
});
test("unfinalized destination success remains nonreceipt evidence", async () => {
  const f = fixture(); f.finalize(null); const state = await observeOftReceive(f.path, f.encoded, f.destinationReader, f.destinationReceipt.hash); expect(state.state).toBe("payload_committed");
});
test("malformed gas, simulation, snapshot and timestamp values cannot produce artifacts", async () => {
  const f = fixture();
  await expect(buildOftRetry(f.path, f.encoded, addr(40), { ...f.destinationReader, estimateGas: async () => NaN as unknown as bigint }, () => 1000, 100000n, 10n)).rejects.toThrow("gas budget");
  await expect(buildOftRetry(f.path, f.encoded, addr(40), { ...f.destinationReader, call: async (tx) =>
    tx.to === f.path.destination.endpoint && endpoint.parseTransaction({ data: tx.data })?.name === "lzReceive" ? "0x1234" : f.destinationReader.call(tx) }, () => 1000, 100000n, 10n)).rejects.toThrow("simulation");
  await expect(buildOftRetry(f.path, f.encoded, addr(40), f.destinationReader, () => Number.MAX_SAFE_INTEGER, 100000n, 10n)).rejects.toThrow("clock");
  await expect(observeOftReceive(f.path, f.encoded, { ...f.destinationReader, getBlock: async (tag) => tag === "latest" ? { number: -1, hash: hash(44), timestamp: 1000 } : f.destinationReader.getBlock(tag) })).rejects.toThrow("unavailable");
});
test("inconsistent predecessor snapshot after simulation invalidates the retry", async () => {
  const f = fixture(3n); let burned = false;
  const provider: OftRetryReader = { ...f.destinationReader, estimateGas: async () => { burned = true; return 50000n; }, call: async (tx) => {
    if (tx.to === f.path.destination.endpoint) {
      const parsed = endpoint.parseTransaction({ data: tx.data });
      if (parsed?.name === "inboundPayloadHash" && BigInt(parsed.args[3]) === 2n && burned) return endpoint.encodeFunctionResult("inboundPayloadHash", [hash(0)]);
    }
    return f.destinationReader.call(tx);
  } };
  await expect(buildOftRetry(f.path, f.encoded, addr(40), provider, () => 1000, 100000n, 10n)).rejects.toThrow("preceding nonce");
});
test("snapshot reorg and endpoint-only or OFT-only logs do not prove destination credit", async () => {
  const f = fixture(); await expect(observeOftReceive(f.path, f.encoded, { ...f.destinationReader, getBlock: async (tag) =>
    tag === 44 ? { number: 44, hash: hash(99), timestamp: 1400 } : f.destinationReader.getBlock(tag) })).rejects.toThrow("snapshot reorged");
  for (const index of [1, 2, 3]) {
    const partial = fixture();
    await expect(observeOftReceive(partial.path, partial.encoded, { ...partial.destinationReader, getTransactionReceipt: async () => ({ ...partial.destinationReceipt,
      logs: partial.destinationReceipt.logs.filter((log) => log.index !== index) }) }, partial.destinationReceipt.hash)).rejects.toThrow("does not prove");
  }
});
