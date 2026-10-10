/** Deployment defaults are public configuration, never wallet credentials. */
export const NETWORK_NAMES = ["mainnet", "signet", "testnet4", "regtest"] as const;
export type NetworkName = typeof NETWORK_NAMES[number];

export interface SwapDefaults {
  readonly network: NetworkName;
  readonly relays: readonly string[];
  readonly mempoolApi: string;
  readonly broadcastApi: string;
  /** Public endpoint only. Credentials are never deployment defaults. */
  readonly nodeApi?: string;
}

export const MAX_RELAYS = 4;

export function validateRelay(value: string, network: NetworkName): string {
  const url = new URL(value);
  const loopback = url.hostname === "127.0.0.1" || url.hostname === "localhost";
  if (url.username || url.password || url.hash ||
      (url.protocol !== "wss:" && !(network === "regtest" && loopback && url.protocol === "ws:"))) {
    throw new Error("Use a wss:// relay, or an explicit local ws:// relay for regtest");
  }
  return url.href;
}

export function validateRelays(input: string, network: NetworkName): readonly string[] {
  const urls = [...new Set(input.split(/[\s,]+/).filter(Boolean).map((url) => validateRelay(url, network)))];
  if (urls.length === 0 || urls.length > MAX_RELAYS) throw new Error(`Choose between 1 and ${MAX_RELAYS} relays`);
  return Object.freeze(urls);
}

export function validateMempoolApi(value: string, network: NetworkName): string {
  const url = new URL(value);
  const local = url.hostname === "127.0.0.1" || url.hostname === "localhost";
  if (url.username || url.password || url.search || url.hash || url.hostname.includes("*") ||
      (url.protocol !== "https:" && !(network === "regtest" && local && url.protocol === "http:"))) {
    throw new Error("Use an HTTPS mempool API, or an explicit loopback HTTP API for regtest");
  }
  return url.href.replace(/\/$/, "");
}

const MEMPOOL_APIS: Record<NetworkName, string> = {
  mainnet: "https://mempool.space/api",
  signet: "https://mempool.space/signet/api",
  testnet4: "https://mempool.space/testnet4/api",
  regtest: "http://127.0.0.1:8091/api",
};

export function resolveSwapDefaults(env: Record<string, string | undefined>): SwapDefaults {
  const network = env.VITE_RILLSWAP_NETWORK ?? "mainnet";
  if (!(NETWORK_NAMES as readonly string[]).includes(network)) {
    throw new Error("VITE_RILLSWAP_NETWORK must be mainnet, signet, testnet4, or regtest");
  }
  const name = network as NetworkName;
  if (env.VITE_RILLSWAP_RELAY !== undefined && env.VITE_RILLSWAP_RELAYS !== undefined) {
    throw new Error("Set VITE_RILLSWAP_RELAYS or VITE_RILLSWAP_RELAY, not both");
  }
  return {
    network: name,
    relays: validateRelays(env.VITE_RILLSWAP_RELAYS ?? env.VITE_RILLSWAP_RELAY ??
      (name === "regtest" ? "ws://127.0.0.1:7777" : "wss://relay.damus.io wss://nos.lol wss://relay.primal.net"), name),
    mempoolApi: validateMempoolApi(env.VITE_RILLSWAP_MEMPOOL_API ?? MEMPOOL_APIS[name], name),
    broadcastApi: validateMempoolApi(env.VITE_RILLSWAP_BROADCAST_API ?? (name === "regtest" ? "http://127.0.0.1:8092/api" : env.VITE_RILLSWAP_MEMPOOL_API ?? MEMPOOL_APIS[name]), name),
    ...(env.VITE_RILLSWAP_NODE_API !== undefined || name === "regtest" ? {
      nodeApi: validateMempoolApi(env.VITE_RILLSWAP_NODE_API ?? "http://127.0.0.1:8093", name),
    } : {}),
  };
}

export const relaysForNetwork = (network: NetworkName, deployment?: SwapDefaults): readonly string[] =>
  deployment?.network === network ? deployment.relays :
    resolveSwapDefaults({ VITE_RILLSWAP_NETWORK: network }).relays;

export const mempoolApiForNetwork = (network: NetworkName, deployment?: SwapDefaults): string =>
  deployment?.network === network ? deployment.mempoolApi : MEMPOOL_APIS[network];
