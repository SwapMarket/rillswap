import { expect, test } from "bun:test";
import { awaitReceipt, EvmError, EvmRpc } from "../src/swap/evmHtlc";

// Like a real fetch, a stalled request settles only when its signal aborts.
const stalled = (signal: AbortSignal | null | undefined): Promise<never> =>
  new Promise((_resolve, reject) => signal?.addEventListener("abort", () => reject(signal.reason)));

// Fails fast instead of hanging the suite if a request is left unbounded again.
const within = <T>(promise: Promise<T>, ms: number): Promise<T> => {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const guard = new Promise<never>((_resolve, reject) => { timer = setTimeout(() => reject(new Error("still waiting")), ms); });
  return Promise.race([promise, guard]).finally(() => clearTimeout(timer));
};

test("a stalled EVM endpoint cannot hold awaitReceipt past its deadline", async () => {
  const rpc = new EvmRpc("http://rpc.test/", async (_url, init) => stalled(init.signal), 20);
  const waiting = within(awaitReceipt(rpc, "11".repeat(32), 1, { intervalMs: 1, timeoutMs: 50 }), 1_000);
  await expect(waiting).rejects.toThrow(EvmError);
  await expect(waiting).rejects.toThrow("eth_getTransactionReceipt timed out");
});

test("a response body that never finishes is also bounded", async () => {
  const rpc = new EvmRpc("http://rpc.test/", async (_url, init) =>
    ({ ok: true, status: 200, json: () => stalled(init.signal) }) as unknown as Response, 20);
  await expect(within(rpc.blockNumber(), 1_000)).rejects.toThrow("eth_blockNumber timed out");
});

test("a prompt answer is unaffected by the request timeout", async () => {
  const rpc = new EvmRpc("http://rpc.test/", async () => Response.json({ jsonrpc: "2.0", id: 1, result: "0x2a" }), 20);
  expect(await rpc.blockNumber()).toBe(42);
  const failing = new EvmRpc("http://rpc.test/", async () => new Response("", { status: 502 }), 20);
  await expect(failing.blockNumber()).rejects.toThrow("HTTP 502");
});
