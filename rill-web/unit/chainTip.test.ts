import { expect, test } from "bun:test";
import regtest from "../src/networks/regtest-rillswap-e2e-v1.json";
import { readChainTip, type ChainFetch } from "../src/swap/chainTip";
import { mempoolApiForNetwork, resolveSwapDefaults, validateMempoolApi } from "../src/swap/config";

const network = { name: "regtest" as const, genesis_hash: regtest.genesis_hash };
const hash = "a".repeat(64);
const responses = (height = "100", tip = hash) => [network.genesis_hash, height, tip, height, tip];

test("mempool defaults are network-specific and explicit deployment endpoints survive round trips", () => {
  expect(mempoolApiForNetwork("mainnet")).toBe("https://mempool.space/api");
  expect(mempoolApiForNetwork("signet")).toBe("https://mempool.space/signet/api");
  const defaults = resolveSwapDefaults({ VITE_RILLSWAP_NETWORK: "regtest", VITE_RILLSWAP_MEMPOOL_API: "http://localhost:9091/api/" });
  expect(mempoolApiForNetwork("regtest", defaults)).toBe("http://localhost:9091/api");
  for (const api of ["http://mempool.space/api", "https://user:password@mempool.space/api", "https://mempool.space/api?token=x", "https://mempool.space/api#x"]) {
    expect(() => validateMempoolApi(api, "regtest")).toThrow();
  }
  expect(() => validateMempoolApi("http://localhost:8091/api", "mainnet")).toThrow();
});

test("tip observations are bounded, stable, credential-free, and contain no private payload", async () => {
  const values = responses();
  const requests: string[] = [];
  const result = await readChainTip("http://127.0.0.1:8091/api", network, { fetch: (async (url, options) => {
    requests.push(String(url));
    expect(options?.credentials).toBe("omit"); expect(options?.redirect).toBe("error");
    expect(options?.body).toBeUndefined(); expect(options?.referrerPolicy).toBe("no-referrer");
    return new Response(values.shift());
  }) as ChainFetch });
  expect(result).toEqual({ height: 100, hash });
  expect(requests).toHaveLength(5);
});

test("wrong genesis, unstable tips, missing data, invalid numbers and oversized bodies fail closed", async () => {
  for (const values of [["f".repeat(64)], [network.genesis_hash, "100", hash, "101", hash],
    responses("1e3"), responses("500000000"), responses("100", "unknown"), ["x".repeat(129)]]) {
    await expect(readChainTip("http://127.0.0.1:8091/api", network, {
      fetch: (async () => new Response(values.shift() ?? "")) as ChainFetch,
    })).rejects.toThrow();
  }
});

test("canceled reads make no request and never fall back to another operator", async () => {
  const cancellation = new AbortController(); cancellation.abort();
  let requests = 0;
  await expect(readChainTip("http://127.0.0.1:8091/api", network, { signal: cancellation.signal,
    fetch: (async () => { requests++; return new Response(); }) as ChainFetch })).rejects.toThrow();
  expect(requests).toBe(0);
});
