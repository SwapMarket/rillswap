import { describe, expect, test } from "bun:test";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { ABI, EvmRpc, type SponsoredClaimProof } from "../src/swap/evmHtlc";

const address = (byte: string) => `0x${byte.repeat(20)}`;
const word = (value: bigint) => value.toString(16).padStart(64, "0");
const topicAddress = (value: string) => `0x${value.slice(2).padStart(64, "0")}`;
const TX = "ab".repeat(32), BLOCK = `0x${"cd".repeat(32)}`, OP = `0x${"ef".repeat(32)}`;
const preimage = "42".repeat(32), hash = bytesToHex(sha256(hexToBytes(preimage)));
const proof: SponsoredClaimProof = {
  userOpHash: OP, entryPoint: address("11"), sender: address("22"), htlc: address("33"), preimage, destination: address("44"),
  lock: { preimageHash: hash, amount: 20_000_000n, token: address("55"), claimAddress: address("22"), refundAddress: address("66"), timelock: 500 },
};
type Log = { address: string; topics: string[]; data: string };
const before: Log = { address: proof.entryPoint, topics: [ABI.beforeExecutionTopic], data: "0x" };
const claim: Log = { address: proof.htlc, topics: [ABI.claimTopic, `0x${hash}`], data: `0x${preimage}` };
const transfer: Log = { address: proof.lock.token, topics: [ABI.transferTopic, topicAddress(proof.sender), topicAddress(proof.destination)], data: `0x${word(proof.lock.amount)}` };
const operation = (op = OP, sender = proof.sender, success = true): Log => ({
  address: proof.entryPoint, topics: [ABI.userOperationTopic, op, topicAddress(sender), topicAddress(address("00"))],
  data: `0x${word(0n)}${word(success ? 1n : 0n)}${word(1n)}${word(1n)}`,
});
function rpc(logs: Log[], options: { active?: boolean; tip?: number; canonical?: string; status?: string } = {}): EvmRpc {
  const receipt = { transactionHash: `0x${TX}`, blockHash: BLOCK, blockNumber: "0x64", status: options.status ?? "0x1",
    logs: logs.map((log, index) => ({ ...log, transactionHash: `0x${TX}`, blockNumber: "0x64", logIndex: `0x${(index + 8).toString(16)}` })) };
  return new EvmRpc("http://127.0.0.1:8545", async (_url, init) => {
    const { method } = JSON.parse(init.body as string) as { method: string };
    const result = method === "eth_getTransactionReceipt" ? receipt : method === "eth_blockNumber" ? `0x${(options.tip ?? 101).toString(16)}` :
      method === "eth_getBlockByNumber" ? { hash: options.canonical ?? BLOCK } : method === "eth_call" ? `0x${word(options.active ? 1n : 0n)}` : undefined;
    if (result === undefined) throw new Error(`Unexpected RPC ${method}`);
    return Response.json({ jsonrpc: "2.0", id: 1, result });
  });
}

describe("operation-bound sponsored completion", () => {
  test("a successful exact claim and forwarding operation is proven at settlement depth", async () => {
    await rpc([before, claim, transfer, operation()]).verifySponsoredClaim(TX, proof, 2);
  });
  test("mixed bundles retain failed-op boundaries and permit the correct operation", async () => {
    await rpc([before, operation(`0x${"01".repeat(32)}`, proof.sender, false), claim, transfer, operation(),
      operation(`0x${"02".repeat(32)}`)]).verifySponsoredClaim(TX, proof, 2);
  });
  const invalid: [string, Log[]][] = [
    ["unrelated historical transfer", [transfer]],
    ["validation decoys", [claim, transfer, before, operation()]],
    ["previous operation effects", [before, claim, transfer, operation(`0x${"01".repeat(32)}`), operation()]],
    ["following operation effects", [before, operation(), claim, transfer, operation(`0x${"01".repeat(32)}`)]],
    ["failed expected operation", [before, claim, transfer, operation(OP, proof.sender, false)]],
    ["different staging account", [before, claim, transfer, operation(OP, address("99"))]],
    ["foreign EntryPoint emitter", [before, claim, transfer, { ...operation(), address: address("99") }]],
    ["duplicate operation event", [before, claim, transfer, operation(), operation()]],
    ["different claim hash", [before, { ...claim, topics: [ABI.claimTopic, `0x${"99".repeat(32)}`] }, transfer, operation()]],
    ["different preimage", [before, { ...claim, data: `0x${"99".repeat(32)}` }, transfer, operation()]],
    ["different HTLC emitter", [before, { ...claim, address: address("99") }, transfer, operation()]],
    ["different transfer source", [before, claim, { ...transfer, topics: [ABI.transferTopic, topicAddress(address("99")), topicAddress(proof.destination)] }, operation()]],
    ["insufficient forwarding", [before, claim, { ...transfer, data: `0x${word(proof.lock.amount - 1n)}` }, operation()]],
  ];
  for (const [name, logs] of invalid) test(`${name} cannot prove completion`, async () => {
    await expect(rpc(logs).verifySponsoredClaim(TX, proof, 2)).rejects.toThrow();
  });
  for (const [name, options] of [
    ["active lock", { active: true }], ["insufficient depth", { tip: 100 }],
    ["reorganized receipt", { canonical: `0x${"99".repeat(32)}` }], ["failed receipt", { status: "0x0" }],
  ] as const) test(`${name} remains unresolved`, async () => {
    await expect(rpc([before, claim, transfer, operation()], options).verifySponsoredClaim(TX, proof, 2)).rejects.toThrow();
  });
});
