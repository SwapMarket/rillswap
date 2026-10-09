/** Explicitly trusted chain observations. No keys, addresses, or invoices are transmitted. */
import { validateMempoolApi, type NetworkName } from "./config";

export interface ObservedTip {
  readonly height: number;
  readonly hash: string;
}

export type ChainFetch = (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>;

const HEX32 = /^[0-9a-f]{64}$/;

async function boundedText(response: Response): Promise<string> {
  if (!response.ok || !response.body || Number(response.headers.get("content-length")) > 128) {
    await response.body?.cancel();
    throw new Error("Chain API returned an unavailable or oversized response");
  }
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      size += value.length;
      if (size > 128) { await reader.cancel(); throw new Error("Chain API response exceeded its limit"); }
      chunks.push(value);
    }
  } finally { reader.releaseLock(); }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
  return new TextDecoder("utf-8", { fatal: true }).decode(bytes).trim();
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
  const get = async (path: string): Promise<string> => boundedText(await transport(`${api}/${path}`, {
    signal, credentials: "omit", redirect: "error", cache: "no-store", referrerPolicy: "no-referrer",
  }));
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
