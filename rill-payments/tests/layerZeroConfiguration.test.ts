import { expect, test } from "bun:test";
import { AbiCoder, Interface, keccak256 } from "ethers";
import { LAYERZERO_SOURCE_PINS, observeUln302Configuration, type Uln302ConfigurationReader, type Uln302ConfigurationRequest } from "../src/layerZero";

const addr = (n: number) => "0x" + n.toString(16).padStart(40, "0"), hash = (n: number) => "0x" + n.toString(16).padStart(64, "0");
const abi = new Interface([
  "function eid() view returns(uint32)", "function getSendLibrary(address,uint32) view returns(address)",
  "function getReceiveLibrary(address,uint32) view returns(address,bool)", "function version() pure returns(uint64,uint8,uint8)",
  "function getConfig(address,address,uint32,uint32) view returns(bytes)",
  "function receiveLibraryTimeout(address,uint32) view returns(address,uint256)", "function defaultReceiveLibraryTimeout(uint32) view returns(address,uint256)",
]);
const coder = AbiCoder.defaultAbiCoder(), ulnType = "tuple(uint64,uint8,uint8,uint8,address[],address[])", executorType = "tuple(uint32,address)";
function fixture(kind: "send" | "receive" = "send") {
  const pin = (n: number) => ({ address: addr(n), codeHash: keccak256("0x6000") });
  const request: Uln302ConfigurationRequest = { version: "layerzero-uln302-observation/1", chainId: "10", genesisHash: hash(1), eid: 30111, remoteEid: 30110,
    endpoint: pin(1), oapp: pin(2), library: { ...pin(3), kind }, block: { number: 100, hash: hash(2) } };
  const calls: { target: string; name: string; block: number | undefined; args: readonly unknown[] }[] = [];
  const reads: { name: string; args: readonly unknown[] }[] = [];
  const state = { chainId: 10n, genesisHash: hash(1), blockHash: hash(2), timestamp: 10000, code: "0x6000", eid: 30111, selected: addr(3), isDefault: false,
    version: [3n, 0, 2] as readonly unknown[], uln: [15n, 2, 1, 1, [addr(10), addr(11)], [addr(12)]] as readonly unknown[],
    executor: [1024, addr(20)] as readonly unknown[], timeout: [addr(4), 101n] as readonly unknown[], corrupt: "", corruptName: "", inner: "" };
  const reader: Uln302ConfigurationReader = {
    async getNetwork() { reads.push({ name: "network", args: [] }); return { chainId: state.chainId }; },
    async getBlock(tag) { reads.push({ name: "block", args: [tag] }); return tag === 0 ? { number: 0, timestamp: 0, hash: state.genesisHash } : { number: 100, timestamp: state.timestamp, hash: state.blockHash }; },
    async getCode(target, block) { reads.push({ name: "code", args: [target, block] }); return state.code; },
    async call(input) {
      const parsed = abi.parseTransaction({ data: input.data })!; calls.push({ target: input.to, name: parsed.name, block: input.blockTag, args: Array.from(parsed.args) });
      const results: Record<string, readonly unknown[]> = { eid: [state.eid], getSendLibrary: [state.selected], getReceiveLibrary: [state.selected, state.isDefault], version: state.version,
        receiveLibraryTimeout: state.timeout, defaultReceiveLibraryTimeout: state.timeout };
      const values = parsed.name === "getConfig" ? [state.inner || coder.encode([Number(parsed.args[3]) === 2 ? ulnType : executorType], [Number(parsed.args[3]) === 2 ? state.uln : state.executor])] : results[parsed.name]!;
      const encoded = abi.encodeFunctionResult(parsed.name, values); return parsed.name === state.corruptName ? state.corrupt || encoded + "00" : encoded;
    },
  };
  return { request, reader, state, calls, reads };
}

test("explicit send observation reads effective ULN and executor at the original block without authority", async () => {
  const f = fixture(), result = await observeUln302Configuration(f.request, f.reader);
  expect(result.authority).toBe("none"); expect(result.abiSourcePin).toBe(LAYERZERO_SOURCE_PINS.protocol); expect(result.request).toEqual(f.request);
  expect(result.uln).toEqual({ confirmations: "15", requiredDVNs: [addr(10), addr(11)], optionalDVNs: [addr(12)], optionalDVNThreshold: 1 });
  expect(result.executor).toEqual({ maxMessageSize: 1024, address: addr(20), configured: true }); expect(result.receive).toBeNull();
  expect(f.calls.map((call) => call.name)).toEqual(["eid", "getSendLibrary", "version", "getConfig", "getConfig"]);
  expect(f.calls.every((call) => call.block === 100)).toBe(true); expect(f.calls.filter((call) => call.name === "getConfig").map((call) => call.args)).toEqual([[addr(2), addr(3), 30110n, 2n], [addr(2), addr(3), 30110n, 1n]]);
  expect(f.reads.filter((read) => read.name === "code").every((read) => read.args[1] === 100)).toBe(true);
  expect(Object.hasOwn(result, "deploymentConformanceVerified")).toBe(false); expect(Object.hasOwn(result, "quote")).toBe(false);
  for (const value of [result, result.request, result.request.endpoint, result.request.oapp, result.request.library, result.request.block, result.uln, result.uln.requiredDVNs, result.uln.optionalDVNs, result.executor]) expect(Object.isFrozen(value)).toBe(true);
});

test("receive observations choose the effective timeout branch and never query executor config", async () => {
  for (const isDefault of [false, true]) for (const expiry of [99n, 100n, 101n]) {
    const f = fixture("receive"); f.state.isDefault = isDefault; f.state.timeout = [addr(4), expiry];
    const result = await observeUln302Configuration(f.request, f.reader);
    expect(result.receive).toEqual({ isDefault, timeoutLibrary: addr(4), expiryBlock: expiry.toString(), withinWindow: expiry > 100n,
      nonzeroLibraryWithinWindow: expiry > 100n, timeoutLibraryConfiguration: "not_observed" }); expect(result.executor).toBeNull(); expect(Object.isFrozen(result.receive)).toBe(true);
    expect(f.calls.filter((call) => call.name === "getConfig").map((call) => call.args[3])).toEqual([2n]);
    expect(f.calls.at(-1)?.name).toBe(isDefault ? "defaultReceiveLibraryTimeout" : "receiveLibraryTimeout");
    expect(f.calls.at(-1)?.args).toEqual(isDefault ? [30110n] : [addr(2), 30110n]);
  }
});

test("unset executor and zero-library timeout values remain observations, not invented operational proof", async () => {
  for (const executor of [[0, addr(20)], [100, addr(0)], [0, addr(0)]]) {
    const f = fixture(); f.state.executor = executor; expect((await observeUln302Configuration(f.request, f.reader)).executor?.configured).toBe(false);
  }
  for (const expiry of [0n, 101n]) {
    const f = fixture("receive"); f.state.timeout = [addr(0), expiry]; const result = await observeUln302Configuration(f.request, f.reader);
    expect(result.receive?.timeoutLibrary).toBe(addr(0)); expect(result.receive?.withinWindow).toBe(expiry > 100n); expect(result.receive?.nonzeroLibraryWithinWindow).toBe(false);
  }
});

test("effective literal zero confirmations, optional-only sets and cross-array overlap follow pinned source", async () => {
  for (const uln of [[0n, 1, 0, 0, [addr(10)], []], [0n, 0, 1, 1, [], [addr(10)]], [1n, 1, 1, 1, [addr(10)], [addr(10)]]]) {
    const f = fixture(); f.state.uln = uln; const result = await observeUln302Configuration(f.request, f.reader);
    expect(result.uln.confirmations).toBe(String(uln[0])); expect(result.authority).toBe("none");
  }
});

test("the maximum pinned protocol DVN lists fit the bounded canonical response profile", async () => {
  const f = fixture(), list = Array.from({ length: 127 }, (_, i) => addr(i + 100)); f.state.uln = [15n, 127, 127, 127, list, list];
  const encoded = coder.encode([ulnType], [f.state.uln]); expect((encoded.length - 2) / 2).toBeGreaterThan(8192);
  const result = await observeUln302Configuration(f.request, f.reader); expect(result.uln.requiredDVNs).toHaveLength(127); expect(result.uln.optionalDVNs).toHaveLength(127);
});

test("invalid or unrecognized declarations refuse before any reader call", async () => {
  const f = fixture();
  const invalid = [ { ...f.request, version: "other" }, { ...f.request, chainId: "010" }, { ...f.request, chainId: "0" }, { ...f.request, chainId: (1n << 256n).toString() },
    { ...f.request, genesisHash: hash(0) }, { ...f.request, remoteEid: f.request.eid }, { ...f.request, eid: 2 ** 32 }, { ...f.request, library: { ...f.request.library, kind: "unknown" } },
    { ...f.request, endpoint: { ...f.request.endpoint, address: addr(0) } }, { ...f.request, oapp: { ...f.request.oapp, codeHash: hash(0) } }, { ...f.request, block: { number: -1, hash: hash(2) } } ];
  for (const request of invalid) await expect(observeUln302Configuration(request as Uln302ConfigurationRequest, f.reader)).rejects.toThrow("LayerZero configuration observation refused");
  expect(f.calls).toEqual([]); expect(f.reads).toEqual([]);
});

test("declared string fields reject coercible nonprimitives before any RPC or retained object reference", async () => {
  for (const field of ["chainId", "genesisHash", "endpointAddress", "oappAddress", "libraryAddress", "endpointHash", "oappHash", "libraryHash", "blockHash"]) {
    const original = fixture().request;
    const value = field === "chainId" ? "10" : field.endsWith("Address") ? addr(1) : hash(1);
    for (const malformed of [10, 10n, new String(value), { toString: () => value }, { [Symbol.toPrimitive]: () => value }]) {
      const f = fixture(), request = structuredClone(original) as unknown as Record<string, unknown>;
      if (field === "chainId" || field === "genesisHash") request[field] = malformed;
      else if (field === "blockHash") (request.block as Record<string, unknown>).hash = malformed;
      else {
        const target = field.startsWith("endpoint") ? "endpoint" : field.startsWith("oapp") ? "oapp" : "library";
        (request[target] as Record<string, unknown>)[field.endsWith("Address") ? "address" : "codeHash"] = malformed;
      }
      await expect(observeUln302Configuration(request as unknown as Uln302ConfigurationRequest, f.reader)).rejects.toThrow("LayerZero configuration observation refused");
      expect(f.reads).toEqual([]); expect(f.calls).toEqual([]);
    }
  }
});

test("wrong network, code, endpoint, selected library and version never yield configuration evidence", async () => {
  for (const mismatch of ["chain", "genesis", "block", "code", "eid", "selected", "version"]) {
    const f = fixture();
    if (mismatch === "chain") f.state.chainId = 42161n; if (mismatch === "genesis") f.state.genesisHash = hash(3); if (mismatch === "block") f.state.blockHash = hash(3);
    if (mismatch === "code") f.state.code = "0x6001"; if (mismatch === "eid") f.state.eid++; if (mismatch === "selected") f.state.selected = addr(4); if (mismatch === "version") f.state.version = [3, 0, 1];
    await expect(observeUln302Configuration(f.request, f.reader)).rejects.toThrow("LayerZero configuration observation refused");
  }
});

test("malformed effective configs are refused without sorting, merging or repairing sentinels", async () => {
  const list = Array.from({ length: 128 }, (_, i) => addr(i + 100));
  for (const uln of [[1n, 2, 0, 0, [addr(11), addr(10)], []], [1n, 2, 0, 0, [addr(10), addr(10)], []], [1n, 1, 0, 0, [addr(0)], []],
    [1n, 1, 0, 0, [], []], [1n, 1, 1, 0, [addr(10)], [addr(12)]], [1n, 1, 1, 2, [addr(10)], [addr(12)]], [1n, 1, 0, 1, [addr(10)], []],
    [1n, 0, 0, 0, [], []], [1n, 255, 0, 0, [], []], [1n, 128, 0, 0, list, []], [(1n << 64n) - 1n, 1, 0, 0, [addr(10)], []]]) {
    const f = fixture(); f.state.uln = uln; await expect(observeUln302Configuration(f.request, f.reader)).rejects.toThrow("LayerZero configuration observation refused");
  }
});

test("outer and inner noncanonical ABI and oversized config responses are refused before evidence", async () => {
  for (const change of ["outer", "inner", "oversize", "badhex"]) {
    const f = fixture();
    if (change === "outer") f.state.corruptName = "getConfig";
    if (change === "inner") f.state.inner = coder.encode([ulnType], [f.state.uln]) + "00";
    if (change === "oversize") f.state.inner = "0x" + "00".repeat(40_000);
    if (change === "badhex") { f.state.corruptName = "getConfig"; f.state.corrupt = "0xz"; }
    await expect(observeUln302Configuration(f.request, f.reader)).rejects.toThrow("LayerZero configuration observation refused");
  }
});

test("captured request pins and reader methods survive mutation while snapshots are rechecked", async () => {
  const f = fixture(), expected = structuredClone(f.request), original = f.reader.getNetwork; let changed = false;
  f.reader.getNetwork = async function () {
    if (!changed) { changed = true;
      const mutable = f.request as unknown as { remoteEid: number; library: { address: string }; block: { hash: string } }; mutable.remoteEid = 1; mutable.library.address = addr(99); mutable.block.hash = hash(99);
      f.reader.call = async () => { throw new Error("replacement must never run"); };
    }
    return original.call(this);
  };
  const result = await observeUln302Configuration(f.request, f.reader); expect(result.request).toEqual(expected); expect(result.uln.requiredDVNs).toEqual([addr(10), addr(11)]);
  const reorg = fixture(), call = reorg.reader.call;
  reorg.reader.call = async (input) => { const value = await call(input); if (abi.parseTransaction({ data: input.data })?.name === "getConfig") reorg.state.blockHash = hash(99); return value; };
  await expect(observeUln302Configuration(reorg.request, reorg.reader)).rejects.toThrow("LayerZero configuration observation refused");
});

test("private adapter errors are sanitized and caller declarations remain untouched", async () => {
  const f = fixture(), before = structuredClone(f.request); f.reader.call = async () => { throw new Error("PRIVATE_RPC_CREDENTIALS"); };
  let error: unknown; try { await observeUln302Configuration(f.request, f.reader); } catch (caught) { error = caught; }
  expect(error instanceof Error).toBe(true); expect((error as Error).message).toBe("LayerZero configuration observation refused"); expect((error as Error).cause).toBeUndefined();
  expect(f.request).toEqual(before);
});
