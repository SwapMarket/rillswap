/** Deployment defaults are public configuration, never wallet credentials. */
export const NETWORK_NAMES = ["mainnet", "signet", "testnet4", "regtest"] as const;
export type NetworkName = typeof NETWORK_NAMES[number];

export interface SwapDefaults {
  readonly network: NetworkName;
  readonly relay: string;
}

export function validateRelay(value: string, network: NetworkName): string {
  const url = new URL(value);
  const loopback = url.hostname === "127.0.0.1" || url.hostname === "localhost";
  if (url.username || url.password || url.hash ||
      (url.protocol !== "wss:" && !(network === "regtest" && loopback && url.protocol === "ws:"))) {
    throw new Error("Use a wss:// relay, or an explicit local ws:// relay for regtest");
  }
  return url.href;
}

export function resolveSwapDefaults(env: Record<string, string | undefined>): SwapDefaults {
  const network = env.VITE_RILLSWAP_NETWORK ?? "mainnet";
  if (!(NETWORK_NAMES as readonly string[]).includes(network)) {
    throw new Error("VITE_RILLSWAP_NETWORK must be mainnet, signet, testnet4, or regtest");
  }
  const name = network as NetworkName;
  return {
    network: name,
    relay: validateRelay(env.VITE_RILLSWAP_RELAY ??
      (name === "regtest" ? "ws://127.0.0.1:7777" : "wss://relay.damus.io"), name),
  };
}

export const relayForNetwork = (network: NetworkName, deployment?: SwapDefaults): string =>
  deployment?.network === network ? deployment.relay :
    resolveSwapDefaults({ VITE_RILLSWAP_NETWORK: network }).relay;
