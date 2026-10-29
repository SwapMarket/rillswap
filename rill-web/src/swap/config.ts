/** Deployment defaults are public configuration, never wallet credentials. */
import { validateEvmAssetIdentity } from "../generated/manualAdvertisementValidators.js";
import type { EvmAssetIdentity } from "../manualProviderAdvertisement.ts";
import { isOnionRelay, PUBLIC_RELAYS } from "./publicRelays.ts";

export const NETWORK_NAMES = ["mainnet", "signet", "testnet4", "regtest"] as const;
export type NetworkName = typeof NETWORK_NAMES[number];

export interface SwapDefaults {
  readonly network: NetworkName;
  readonly relays: readonly string[];
  readonly mempoolApi: string;
  readonly broadcastApi: string;
  /** Public endpoint only. Credentials are never deployment defaults. */
  readonly nodeApi?: string;
  /** RS-010: JSON-RPC endpoint for reading the EVM chain; the user's wallet signs. */
  readonly evmRpc?: string;
  /** Trusted token deployments, independent of provider discovery. Missing pins disable new EVM swaps. */
  readonly evmAssets?: Readonly<Partial<Record<"USDC" | "USDT", EvmAssetIdentity>>>;
  /** Alchemy-compatible gas sponsor for receiving stablecoins without a wallet extension (all three or none). */
  readonly evmSponsor?: EvmSponsorDefaults;
  /** Published sibling builds, as relative links: picking one of these networks opens its own page. */
  readonly deployments?: Readonly<Partial<Record<NetworkName, string>>>;
}
export interface EvmSponsorDefaults {
  readonly url: string;
  /** ERC-4337 EntryPoint v0.7 the sponsor's user operations are bound to. */
  readonly entryPoint: string;
  /** The only EIP-7702 delegate the browser-held claim key may authorize. */
  readonly delegate: string;
  /** Alchemy gas policy id sent as `paymasterService.policyId`; absent for a proxy that applies its own. */
  readonly policyId?: string;
}

const EVM_ADDRESS = /^0x[0-9a-f]{40}$/;
const POLICY_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
export function validateEvmSponsor(url: string, entryPoint: string, delegate: string, network: NetworkName, policyId = ""): EvmSponsorDefaults {
  if (!EVM_ADDRESS.test(entryPoint) || !EVM_ADDRESS.test(delegate)) throw new Error("EntryPoint and delegate must be lowercase 0x addresses");
  if (policyId !== "" && !POLICY_ID.test(policyId)) throw new Error("Gas sponsor policy id must be a UUID");
  return { url: validateMempoolApi(url, network), entryPoint, delegate, ...(policyId !== "" ? { policyId: policyId.toLowerCase() } : {}) };
}

export const MAX_RELAYS = 8;

export function validateRelay(value: string, network: NetworkName): string {
  const url = new URL(value);
  const loopback = url.hostname === "127.0.0.1" || url.hostname === "localhost";
  if (url.username || url.password || url.hash ||
      (url.protocol !== "wss:" && !(url.protocol === "ws:" && isOnionRelay(url.href)) &&
        !(network === "regtest" && loopback && url.protocol === "ws:"))) {
    throw new Error("Use a wss:// relay, a ws:// onion relay, or an explicit local ws:// relay for regtest");
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

/**
 * Explorer page for `txid` on the same instance as a mempool/Esplora API:
 * `https://host[/net]/api` maps to `https://host[/net]/tx/<txid>`.
 */
export function explorerTxUrl(api: string, txid: string): string {
  if (!/^[0-9a-f]{64}$/.test(txid)) throw new Error("Invalid transaction ID");
  const url = new URL(api);
  url.pathname = `${url.pathname.replace(/\/+$/, "").replace(/\/api$/, "")}/tx/${txid}`;
  return url.href;
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
      (name === "regtest" ? "ws://127.0.0.1:7777" : PUBLIC_RELAYS.join(" ")), name),
    mempoolApi: validateMempoolApi(env.VITE_RILLSWAP_MEMPOOL_API ?? MEMPOOL_APIS[name], name),
    broadcastApi: validateMempoolApi(env.VITE_RILLSWAP_BROADCAST_API ?? (name === "regtest" ? "http://127.0.0.1:8092/api" : env.VITE_RILLSWAP_MEMPOOL_API ?? MEMPOOL_APIS[name]), name),
    ...(env.VITE_RILLSWAP_NODE_API !== undefined || name === "regtest" ? {
      nodeApi: validateMempoolApi(env.VITE_RILLSWAP_NODE_API ?? "http://127.0.0.1:8093", name),
    } : {}),
    ...(env.VITE_RILLSWAP_EVM_RPC !== undefined || name === "regtest" ? {
      evmRpc: validateMempoolApi(env.VITE_RILLSWAP_EVM_RPC ?? "http://127.0.0.1:8545", name),
    } : {}),
    ...(sponsorDefaults(env, name)),
    ...(env.VITE_RILLSWAP_EVM_ASSETS === undefined ? {} : { evmAssets: parseEvmAssets(env.VITE_RILLSWAP_EVM_ASSETS) }),
    ...(env.VITE_RILLSWAP_DEPLOYMENTS === undefined ? {} : { deployments: parseDeployments(env.VITE_RILLSWAP_DEPLOYMENTS) }),
  };
}

// Same-site relative directories only ("./", "../", "./signet/"), so a build
// works under any Pages prefix and can never send users to another origin.
const DEPLOYMENT_LINK = /^\.\.?\/(?:[a-z0-9-]+\/)*$/;

function parseDeployments(document: string): NonNullable<SwapDefaults["deployments"]> {
  const value: unknown = JSON.parse(document);
  if (value === null || typeof value !== "object" || Array.isArray(value) ||
      Object.entries(value).some(([name, link]) =>
        !(NETWORK_NAMES as readonly string[]).includes(name) || typeof link !== "string" || !DEPLOYMENT_LINK.test(link))) {
    throw new Error("VITE_RILLSWAP_DEPLOYMENTS must map network names to relative directory links such as \"../\" or \"./signet/\"");
  }
  return Object.freeze({ ...value as Partial<Record<NetworkName, string>> });
}

function parseEvmAssets(document: string): NonNullable<SwapDefaults["evmAssets"]> {
  const value: unknown = JSON.parse(document);
  if (value === null || typeof value !== "object" || Array.isArray(value) ||
      Object.entries(value).some(([symbol, asset]) => !["USDC", "USDT"].includes(symbol) || !validateEvmAssetIdentity(asset))) {
    throw new Error("VITE_RILLSWAP_EVM_ASSETS must map USDC/USDT to complete EVM asset identities");
  }
  return Object.freeze(Object.fromEntries(Object.entries(value).map(([symbol, asset]) => [symbol, Object.freeze({ ...asset })])));
}

export function trustedEvmAsset(symbol: "USDC" | "USDT", network: NetworkName, namespace: string | null, defaults: SwapDefaults): EvmAssetIdentity {
  const asset = defaults.network === network ? defaults.evmAssets?.[symbol] : undefined;
  if (!asset || (asset.chain_id === 31337 && (network !== "regtest" || asset.deployment_namespace !== namespace))) {
    throw new Error(`No trusted ${symbol} deployment is configured for this network. Provider announcements cannot select the token.`);
  }
  return asset;
}

function sponsorDefaults(env: Record<string, string | undefined>, name: NetworkName): { evmSponsor?: EvmSponsorDefaults } {
  const values = [env.VITE_RILLSWAP_EVM_SPONSOR, env.VITE_RILLSWAP_EVM_ENTRY_POINT, env.VITE_RILLSWAP_EVM_7702_DELEGATE];
  const policy = env.VITE_RILLSWAP_EVM_SPONSOR_POLICY;
  if (values.every((value) => value === undefined)) {
    if (policy !== undefined) throw new Error("VITE_RILLSWAP_EVM_SPONSOR_POLICY needs VITE_RILLSWAP_EVM_SPONSOR");
    return {};
  }
  if (values.some((value) => value === undefined)) throw new Error("Set VITE_RILLSWAP_EVM_SPONSOR, VITE_RILLSWAP_EVM_ENTRY_POINT, and VITE_RILLSWAP_EVM_7702_DELEGATE together");
  return { evmSponsor: validateEvmSponsor(values[0]!, values[1]!.toLowerCase(), values[2]!.toLowerCase(), name, policy ?? "") };
}

export const relaysForNetwork = (network: NetworkName, deployment?: SwapDefaults): readonly string[] =>
  deployment?.network === network ? deployment.relays :
    resolveSwapDefaults({ VITE_RILLSWAP_NETWORK: network }).relays;

export const mempoolApiForNetwork = (network: NetworkName, deployment?: SwapDefaults): string =>
  deployment?.network === network ? deployment.mempoolApi : MEMPOOL_APIS[network];
