/** Explicitly trusted chain observations. No keys, addresses, or invoices are transmitted. */
import { validateMempoolApi, type NetworkName } from "./config";
import { parseStrictEventJson } from "../strictEventJson";

export interface ObservedTip {
  readonly height: number;
  readonly hash: string;
}

export type ChainFetch = (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>;

const HEX32 = /^[0-9a-f]{64}$/;

/** Bounded, abortable UTF-8 response reading shared by trusted chain observations. */
export async function readBoundedChainText(response: Response, signal: AbortSignal, limit = 128): Promise<string> {
  if (!response.ok || !response.body || Number(response.headers.get("content-length")) > limit) {
    await response.body?.cancel();
    throw new Error("Chain API returned an unavailable or oversized response");
  }
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  const abort = (): void => { void reader.cancel().catch(() => {}); };
  signal.addEventListener("abort", abort, { once: true });
  if (signal.aborted) abort();
  try {
    for (;;) {
      signal.throwIfAborted();
      const { value, done } = await reader.read();
      signal.throwIfAborted();
      if (done) break;
      size += value.length;
      if (size > limit) { await reader.cancel(); throw new Error("Chain API response exceeded its limit"); }
      chunks.push(value);
    }
  } finally { signal.removeEventListener("abort", abort); reader.releaseLock(); }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
  return new TextDecoder("utf-8", { fatal: true }).decode(bytes).trim();
}

/** Highest next-block rate accepted from a chain API, in sat/vB; anything above is treated as broken. */
const MAX_NEXT_BLOCK_SAT_VB = 10_000;

/**
 * The chain API's next-block fee rate (mempool `fastestFee`), in whole sat/kvB rounded up.
 * Advice from an explicitly trusted API, used only as a floor for what this browser asks for.
 */
export async function readNextBlockFeeRate(
  base: string,
  name: NetworkName,
  options: { readonly signal?: AbortSignal; readonly fetch?: ChainFetch } = {},
): Promise<number> {
  const api = validateMempoolApi(base, name);
  const signal = options.signal
    ? AbortSignal.any([options.signal, AbortSignal.timeout(10_000)]) : AbortSignal.timeout(10_000);
  signal.throwIfAborted();
  const response = await (options.fetch ?? fetch)(`${api}/v1/fees/recommended`, {
    signal, credentials: "omit", redirect: "error", cache: "no-store", referrerPolicy: "no-referrer",
  });
  const data = parseStrictEventJson(await readBoundedChainText(response, signal, 1024), 1024);
  const rate = data !== null && typeof data === "object" && !Array.isArray(data) ? (data as Record<string, unknown>).fastestFee : undefined;
  if (typeof rate !== "number" || !Number.isFinite(rate) || rate <= 0 || rate > MAX_NEXT_BLOCK_SAT_VB) {
    throw new Error("Chain API returned no usable next-block fee rate");
  }
  return Math.ceil(Number((rate * 1000).toFixed(3))); // 1.1 sat/vB is 1100, not 1101
}

/** Matching genesis is a sanity check, not independent chain or signet challenge validation. */
export async function readChainTip(
  base: string,
  network: { readonly name: NetworkName; readonly genesis_hash: string },
  options: { readonly signal?: AbortSignal; readonly fetch?: ChainFetch } = {},
): Promise<ObservedTip> {
  const api = validateMempoolApi(base, network.name);
  const signal = options.signal
    ? AbortSignal.any([options.signal, AbortSignal.timeout(10_000)]) : AbortSignal.timeout(10_000);
  signal.throwIfAborted();
  const transport = options.fetch ?? fetch;
  const get = async (path: string): Promise<string> => readBoundedChainText(await transport(`${api}/${path}`, {
    signal, credentials: "omit", redirect: "error", cache: "no-store", referrerPolicy: "no-referrer",
  }), signal);
  const genesis = await get("block-height/0");
  if (!HEX32.test(genesis) || genesis !== network.genesis_hash) throw new Error("Chain API genesis does not match the selected network");
  const heightText = await get("blocks/tip/height");
  const hash = await get("blocks/tip/hash");
  const heightAgain = await get("blocks/tip/height");
  const hashAgain = await get("blocks/tip/hash");
  if (!/^(0|[1-9][0-9]{0,8})$/.test(heightText) || Number(heightText) >= 500_000_000 || !HEX32.test(hash)) {
    throw new Error("Chain API returned an invalid block height or hash");
  }
  if (heightAgain !== heightText || hashAgain !== hash) throw new Error("Chain tip changed during observation. Request a fresh quote.");
  return Object.freeze({ height: Number(heightText), hash });
}
