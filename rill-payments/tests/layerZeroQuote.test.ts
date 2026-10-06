import { expect, test } from "bun:test";
import { Interface, keccak256, solidityPacked } from "ethers";
import { LAYERZERO_SOURCE_PINS, quoteOftSend, type OftPathway, type OftQuoteReader, type OftSendQuoteRequest } from "../src/layerZero";

// Independently specified pinned IOFT tuple ordering, including signed fee details.
const param = "(uint32,bytes32,uint256,uint256,bytes,bytes,bytes)";
const oft = new Interface([
  "function endpoint() view returns(address)", "function peers(uint32) view returns(bytes32)", "function token() view returns(address)",
  "function sharedDecimals() view returns(uint8)", "function decimalConversionRate() view returns(uint256)", "function oftVersion() pure returns(bytes4,uint64)",
  "function combineOptions(uint32,uint16,bytes) view returns(bytes)",
  `function quoteOFT(${param}) view returns((uint256,uint256),(int256,string)[],(uint256,uint256))`,
  `function quoteSend(${param},bool) view returns((uint256,uint256))`,
]);
const endpoint = new Interface(["function eid() view returns(uint32)", "function getSendLibrary(address,uint32) view returns(address)", "function getReceiveLibrary(address,uint32) view returns(address,bool)"]);
const token = new Interface(["function decimals() view returns(uint8)"]);
const addr = (n: number) => "0x" + n.toString(16).padStart(40, "0");
const hash = (n: number) => "0x" + n.toString(16).padStart(64, "0");
const padded = (a: string) => "0x" + "0".repeat(24) + a.slice(2);
const options = (gas = 100000n, value?: bigint) => solidityPacked(
  value === undefined ? ["uint16", "uint8", "uint16", "uint8", "uint128"] : ["uint16", "uint8", "uint16", "uint8", "uint128", "uint128"],
  value === undefined ? [3, 1, 17, 1, gas] : [3, 1, 33, 1, gas, value],
);
function fixture() {
  const code = "0x60006000", codeHash = keccak256(code), genesis = "0x25a5cc106eea7138acab33231d7160d69cb777ee0c2c553fcddf5138993e6dd9";
  const deployment = (n: number, decimals: number, eid: number) => ({ chainId: "11155111", genesisHash: genesis, eid,
    endpoint: addr(n), endpointCodeHash: codeHash, oft: addr(n + 1), oftCodeHash: codeHash, token: addr(n + 2), tokenCodeHash: codeHash,
    tokenDecimals: decimals, sharedDecimals: 6, messageLibrary: addr(n + 3), messageLibraryCodeHash: codeHash });
  const path: OftPathway = { version: "oft-pathway/1", sourcePin: LAYERZERO_SOURCE_PINS, source: deployment(10, 18, 30101), destination: deployment(20, 6, 30102),
    deploymentConformanceVerified: true, zeroValueDirectCreditVerified: true, nonUpgradeableVerified: true };
  const amount = 10n ** 18n;
  const request: OftSendQuoteRequest = { sourceWallet: addr(30), recipient: addr(31), amountLD: (amount + 5n).toString(), minAmountLD: amount.toString(),
    extraOptions: "0x", nativeFeeCapWei: "100", maxReceiveGas: "200000" };
  const state = { min: 0n, max: amount, sent: amount, received: amount, nativeFee: 100n, lzFee: 0n,
    fees: [] as [bigint, string][], merged: options(), sourceLibrary: path.source.messageLibrary, destinationLibrary: path.destination.messageLibrary,
    sourceReorg: false, destinationReorg: false, now: 1000, after: 1000, badCode: false, proxy: false,
    wrongNetwork: false, raw: null as string | null, onRead: () => {} };
  const calls: { side: string; name: string; args: readonly unknown[]; block?: number; from?: string }[] = [];
  const reader = (side: typeof path.source, peer: typeof path.source, label: string, height: number): OftQuoteReader => ({
    getNetwork: async () => ({ chainId: state.wrongNetwork ? 1n : 11155111n }),
    getBlock: async (tag) => {
      if (tag === "latest") { state.onRead(); return { number: height, hash: hash(height), timestamp: 5000 }; }
      if (tag === 0) return { number: 0, hash: genesis, timestamp: 0 };
      const reorg = label === "source" ? state.sourceReorg : state.destinationReorg;
      return { number: height, hash: hash(reorg ? 999 : height), timestamp: 5000 };
    },
    getCode: async () => state.badCode ? "0x6001" : code, getStorage: async () => hash(state.proxy ? 1 : 0),
    getLogs: async () => [], getTransactionCount: async () => 0, getTransaction: async () => null, getTransactionReceipt: async () => null,
    call: async (tx) => {
      const abi = tx.to === side.oft ? oft : tx.to === side.endpoint ? endpoint : token;
      const parsed = abi.parseTransaction({ data: tx.data })!;
      calls.push({ side: label, name: parsed.name, args: parsed.args, block: tx.blockTag, from: tx.from });
      let result: unknown[];
      switch (parsed.name) {
        case "eid": result = [side.eid]; break;
        case "endpoint": result = [side.endpoint]; break;
        case "token": result = [side.token]; break;
        case "peers": result = [padded(peer.oft)]; break;
        case "decimals": result = [side.tokenDecimals]; break;
        case "sharedDecimals": result = [side.sharedDecimals]; break;
        case "decimalConversionRate": result = [10n ** BigInt(side.tokenDecimals - side.sharedDecimals)]; break;
        case "oftVersion": result = ["0x02e49c2c", 1]; break;
        case "getSendLibrary": result = [state.sourceLibrary]; break;
        case "getReceiveLibrary": result = [state.destinationLibrary, false]; break;
        case "combineOptions": result = [state.merged]; break;
        case "quoteOFT": result = [[state.min, state.max], state.fees, [state.sent, state.received]]; break;
        case "quoteSend": result = [[state.nativeFee, state.lzFee]]; break;
        default: throw new Error("Unexpected quote call");
      }
      if (state.raw !== null && parsed.name === "quoteOFT") return state.raw;
      return abi.encodeFunctionResult(parsed.name, result);
    },
  });
  const source = reader({ ...path.source }, { ...path.destination }, "source", 44), destination = reader({ ...path.destination }, { ...path.source }, "destination", 45);
  let clockCalls = 0;
  return { path, request, state, calls, source, destination, quote: () => quoteOftSend(path, request, source, destination, () => clockCalls++ === 0 ? state.now : state.after) };
}

test("read-only quote binds original extras/caller/blocks and rounded limits, not dust or custody", async () => {
  const f = fixture(), quote = await f.quote();
  expect(quote.amountSentLD).toBe("1000000000000000000"); expect(quote.dustLD).toBe("5"); expect(quote.destinationAmountLD).toBe("1000000");
  expect(quote.limits.maxAmountLD).toBe(quote.amountSentLD); // Raw amount exceeds nominal maximum by dust, actual debit fits.
  expect(quote.sourceGasCostIncluded).toBe(false); expect(quote.nativeFeeWei).toBe("100"); expect(quote.expiresAt).toBe(1060);
  const reads = f.calls.filter((call) => ["quoteOFT", "quoteSend", "combineOptions", "getSendLibrary"].includes(call.name));
  expect(reads.length).toBe(4); expect(reads.every((call) => call.from === f.request.sourceWallet && call.block === 44 && call.side === "source")).toBe(true);
  const quotes = reads.filter((call) => call.name.startsWith("quote"));
  expect([...quotes[0]!.args[0] as readonly unknown[]]).toEqual([...quotes[1]!.args[0] as readonly unknown[]]);
  const params = quotes[0]!.args[0] as readonly unknown[];
  expect(params).toEqual([30102n, padded(f.request.recipient), BigInt(f.request.amountLD), BigInt(f.request.minAmountLD), "0x", "0x", "0x"]);
  expect(quotes[1]!.args[1]).toBe(false);
  expect(Object.isFrozen(quote) && Object.isFrozen(quote.source) && Object.isFrozen(quote.destination) && Object.isFrozen(quote.sourcePin) && Object.isFrozen(quote.limits)).toBe(true);
  expect(JSON.stringify(quote)).not.toMatch(/private|signature|calldata|sendTransaction|acceptance|spendable/);
});

test("shared quantity fits uint64 while destination local quantity may exceed uint64", async () => {
  const f = fixture(); const destination = { ...f.path.destination, tokenDecimals: 36 };
  // Reader checks are independent of this fixture's six-decimal destination.
  const provider: OftQuoteReader = { ...f.destination, call: async (tx) => {
    if (tx.to === destination.token && token.parseTransaction({ data: tx.data })?.name === "decimals") return token.encodeFunctionResult("decimals", [36]);
    if (tx.to === destination.oft && oft.parseTransaction({ data: tx.data })?.name === "decimalConversionRate") return oft.encodeFunctionResult("decimalConversionRate", [10n ** 30n]);
    return f.destination.call(tx);
  } };
  const quote = await quoteOftSend({ ...f.path, destination }, f.request, f.source, provider, () => 1000);
  expect(quote.destinationAmountLD).toBe((10n ** 36n).toString());
});

test("uint64 shared ceiling and zero native fee are valid bounded quotes", async () => {
  const f = fixture(), amount = ((1n << 64n) - 1n) * 10n ** 12n;
  Object.assign(f.request, { amountLD: amount.toString(), minAmountLD: amount.toString(), nativeFeeCapWei: "0", extraOptions: "0x0003" });
  Object.assign(f.state, { sent: amount, received: amount, max: amount, nativeFee: 0n });
  const quote = await f.quote(); expect(quote.destinationAmountLD).toBe(((1n << 64n) - 1n).toString()); expect(quote.nativeFeeWei).toBe("0");
  expect((f.calls.find((call) => call.name === "quoteSend")!.args[0] as readonly unknown[])[4]).toBe("0x0003");
});

test("dust/slippage and shared overflow refuse before quoting", async () => {
  for (const request of [
    { amountLD: "5", minAmountLD: "1" }, { minAmountLD: "1000000000000000001" },
    { amountLD: ((1n << 64n) * 10n ** 12n).toString() },
  ]) {
    const f = fixture(); await expect(quoteOftSend(f.path, { ...f.request, ...request }, f.source, f.destination, () => 1000)).rejects.toThrow();
    expect(f.calls.length).toBe(0);
  }
});

test("nominal limits, altered debit/credit and any signed fee detail are unsupported", async () => {
  for (const changed of [
    { min: 10n ** 18n + 1n }, { max: 10n ** 18n - 1n }, { min: 10n, max: 1n },
    { sent: 10n ** 18n - 1n }, { received: 10n ** 18n + 1n },
    ...[-1n, 0n, 1n].map((amount) => ({ fees: [[amount, "PRIVATE_FEE_DESCRIPTION"]] as [bigint, string][] })),
  ]) {
    const f = fixture(); Object.assign(f.state, changed); await expect(f.quote()).rejects.toThrow("unresolved");
  }
});

test("merged options must be one bounded positive-gas zero-value receive", async () => {
  for (const merged of ["0x", "0x0002", options(0n), options(200001n), options(100000n, 1n), options() + options().slice(6), options() + "00", options().replace("000301", "000302")]) {
    const f = fixture(); f.state.merged = merged; await expect(f.quote()).rejects.toThrow("unresolved");
    expect(f.calls.some((call) => call.name.startsWith("quote"))).toBe(false);
  }
  const f = fixture(); f.state.merged = options(100000n, 0n); expect((await f.quote()).receiveGas).toBe("100000");
});

test("native-only transport cap, both libraries/deployments/networks and both anchors are required", async () => {
  for (const changed of [{ nativeFee: 101n }, { lzFee: 1n }, { sourceLibrary: addr(99) }, { destinationLibrary: addr(99) },
    { badCode: true }, { proxy: true }, { wrongNetwork: true }, { sourceReorg: true }, { destinationReorg: true }]) {
    const f = fixture(); Object.assign(f.state, changed); await expect(f.quote()).rejects.toThrow("unresolved");
  }
});

test("invalid quantities, wallets, extras and approval flags never reach RPC quoting", async () => {
  for (const changed of [{ amountLD: "01" }, { amountLD: "0" }, { amountLD: (1n << 256n).toString() }, { minAmountLD: "0" },
    { minAmountLD: "999999999999999999999" }, { nativeFeeCapWei: "-1" }, { maxReceiveGas: "0" }, { maxReceiveGas: (1n << 128n).toString() },
    { sourceWallet: addr(0) }, { recipient: "not-address" }, { extraOptions: "0x0002" }, { extraOptions: "0x00030A" }]) {
    const f = fixture(); await expect(quoteOftSend(f.path, { ...f.request, ...changed }, f.source, f.destination, () => 1000)).rejects.toThrow(); expect(f.calls.length).toBe(0);
  }
  const f = fixture(); await expect(quoteOftSend({ ...f.path, deploymentConformanceVerified: false as true }, f.request, f.source, f.destination, () => 1000)).rejects.toThrow("conformance");
});

test("destination-only network, genesis, code, proxy and peer changes independently refuse", async () => {
  const f = fixture();
  const providers: OftQuoteReader[] = [
    { ...f.destination, getNetwork: async () => ({ chainId: 1n }) },
    { ...f.destination, getBlock: async (tag) => tag === 0 ? { number: 0, hash: hash(999), timestamp: 0 } : f.destination.getBlock(tag) },
    { ...f.destination, getCode: async () => "0x6001" },
    { ...f.destination, getStorage: async () => hash(1) },
    { ...f.destination, call: async (tx) => tx.to === f.path.destination.oft && oft.parseTransaction({ data: tx.data })?.name === "peers"
      ? oft.encodeFunctionResult("peers", [hash(999)]) : f.destination.call(tx) },
  ];
  for (const destination of providers) {
    await expect(quoteOftSend(f.path, f.request, f.source, destination, () => 1000)).rejects.toThrow("unresolved");
    expect(f.calls.some((call) => call.name.startsWith("quote"))).toBe(false);
  }
});

test("malformed ABI and private backend exceptions never become returned quote data", async () => {
  for (const raw of ["0x", "0x1234", "not-hex", "0x" + "00".repeat(16385)]) {
    const f = fixture(); f.state.raw = raw; await expect(f.quote()).rejects.toThrow("unresolved");
  }
  const f = fixture(); f.state.raw = oft.encodeFunctionResult("quoteOFT", [[0, f.state.max], [], [f.state.sent, f.state.received]]) + "00";
  await expect(f.quote()).rejects.toThrow("unresolved");
  const provider = { ...f.source, call: async () => { throw new Error("PRIVATE_RPC_CREDENTIAL_CANARY"); } };
  try { await quoteOftSend(f.path, f.request, provider, f.destination, () => 1000); throw new Error("must refuse"); }
  catch (error) { expect((error as Error).message).toBe("OFT send quote observation is unresolved"); expect((error as Error).cause).toBeUndefined(); }
});

test("construction clock rollback, expiry and malformed snapshots refuse", async () => {
  for (const after of [999, 1060, NaN, Number.MAX_SAFE_INTEGER]) {
    const f = fixture(); f.state.after = after; await expect(f.quote()).rejects.toThrow("unresolved");
  }
  const f = fixture(); const source = { ...f.source, getBlock: async () => ({ number: -1, hash: hash(1), timestamp: 5000 }) };
  await expect(quoteOftSend(f.path, f.request, source, f.destination, () => 1000)).rejects.toThrow("unresolved");
  for (const now of [-1, NaN, Number.MAX_SAFE_INTEGER]) {
    const invalid = fixture(); invalid.state.now = now; await expect(invalid.quote()).rejects.toThrow("clock"); expect(invalid.calls.length).toBe(0);
  }
});

test("asynchronous caller mutation cannot replace the captured pathway or request", async () => {
  const f = fixture(); f.state.onRead = () => {
    Object.assign(f.path.source, { oft: addr(99), tokenDecimals: 36 }); Object.assign(f.request, { sourceWallet: addr(99), amountLD: "1" });
  };
  const quote = await f.quote(); expect(quote.source.oft).toBe(addr(11)); expect(quote.source.tokenDecimals).toBe(18);
  expect(quote.sourceWallet).toBe(addr(30)); expect(quote.amountLD).toBe("1000000000000000005");
});
