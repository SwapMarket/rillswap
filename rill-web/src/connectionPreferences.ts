/** Browser-only connection overrides. Never stores defaults, credentials, or recovery state. */
import canonicalize from "canonicalize";
import { mempoolApiForNetwork, NETWORK_NAMES, relaysForNetwork, validateMempoolApi, validateRelays, type NetworkName, type SwapDefaults } from "./swap/config";

export interface ConnectionSettings {
  readonly relays: readonly string[];
  readonly mempoolApi: string;
  readonly broadcastApi: string;
  readonly evmRpc: string;
}

export interface ConnectionPreferenceState {
  readonly values: ConnectionSettings;
  /** Unreadable settings must not silently select fallback network recipients. */
  readonly needsReset: boolean;
  readonly message: string;
}

type Network = Readonly<Record<string, unknown>> & { readonly name: string };
type PreferenceStorage = Pick<Storage, "getItem" | "setItem" | "removeItem">;
type Overrides = Partial<ConnectionSettings>;
interface Profile {
  overrides: Overrides;
  needsReset: boolean;
  message: string;
}

const FIELDS = ["relays", "mempoolApi", "broadcastApi", "evmRpc"] as const;
const MAX_RECORD_LENGTH = 65_536;
const UNREADABLE = "Saved connections could not be read. Reset connection settings to choose current defaults before connecting.";
const SESSION_ONLY = "Connections changed for this session only: browser storage is unavailable. Saved settings may return after reload.";

/** Exactly the existing deployment/network fallback rules, shared by initial load, switching, and reset. */
export function connectionDefaults(network: NetworkName, deployment: SwapDefaults): ConnectionSettings {
  const mempoolApi = mempoolApiForNetwork(network, deployment);
  return {
    relays: relaysForNetwork(network, deployment), mempoolApi,
    broadcastApi: network === deployment.network ? deployment.broadcastApi : network === "regtest" ? "http://127.0.0.1:8092/api" : mempoolApi,
    evmRpc: network === deployment.network ? deployment.evmRpc ?? "" : network === "regtest" ? "http://127.0.0.1:8545" : "",
  };
}

function validated(field: keyof ConnectionSettings, value: unknown, network: NetworkName): ConnectionSettings[keyof ConnectionSettings] {
  if (field === "relays") {
    if (!Array.isArray(value) || value.some((url) => typeof url !== "string")) throw new Error("Invalid saved relays");
    return validateRelays(value.join("\n"), network);
  }
  if (typeof value !== "string") throw new Error("Invalid saved endpoint");
  return field === "evmRpc" && value.trim() === "" ? "" : validateMempoolApi(value.trim(), network);
}

function parse(raw: string, network: NetworkName): Overrides {
  if (raw.length > MAX_RECORD_LENGTH) throw new Error("Saved connections are too large");
  const record = JSON.parse(raw);
  if (!record || typeof record !== "object" || Array.isArray(record) || record.version !== 1 ||
      Object.keys(record).some((key) => key !== "version" && key !== "overrides") ||
      !record.overrides || typeof record.overrides !== "object" || Array.isArray(record.overrides)) throw new Error("Unsupported saved connections");
  const overrides: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(record.overrides)) {
    if (!(FIELDS as readonly string[]).includes(key)) throw new Error("Unsupported saved connection field");
    overrides[key] = validated(key as keyof ConnectionSettings, value, network);
  }
  return overrides as Overrides;
}

/** One owner for keying, validation, default evolution, and session-only fallback. No live cross-tab mutation. */
export class ConnectionPreferences {
  private readonly directory: string;
  private readonly profiles = new Map<string, Profile>();

  constructor(pageUrl: string, private readonly storage: () => PreferenceStorage = () => window.localStorage) {
    this.directory = new URL(".", pageUrl).href;
  }

  private key(network: Network): string {
    if (!(NETWORK_NAMES as readonly string[]).includes(network.name)) throw new Error("Unsupported connection network");
    // Full identity includes genesis, consensus profile, and the regtest deployment namespace.
    return `rillswap:connections:v1:${canonicalize([this.directory, network])}`;
  }

  private profile(network: Network): Profile {
    const key = this.key(network);
    let profile = this.profiles.get(key);
    if (!profile) {
      profile = { overrides: {}, needsReset: false, message: "" };
      try {
        const raw = this.storage().getItem(key);
        if (raw !== null) profile.overrides = parse(raw, network.name as NetworkName);
      } catch {
        // A denied read does not prove that previously saved overrides were absent.
        profile.needsReset = true;
        profile.message = UNREADABLE;
      }
      this.profiles.set(key, profile);
    }
    return profile;
  }

  read(network: Network, deployment: SwapDefaults): ConnectionPreferenceState {
    const profile = this.profile(network);
    return { values: { ...connectionDefaults(network.name as NetworkName, deployment), ...profile.overrides },
      needsReset: profile.needsReset, message: profile.message };
  }

  /** Only re-diff the field deliberately edited, never prune other overrides after a defaults update. */
  save(network: Network, deployment: SwapDefaults, field: keyof ConnectionSettings, input: string): ConnectionPreferenceState {
    const profile = this.profile(network);
    if (profile.needsReset) throw new Error(UNREADABLE);
    const value = validated(field, field === "relays" ? input.trim().split(/[\s,]+/).filter(Boolean) : input, network.name as NetworkName);
    const overrides = { ...profile.overrides };
    if (JSON.stringify(value) === JSON.stringify(connectionDefaults(network.name as NetworkName, deployment)[field])) delete overrides[field];
    else Object.assign(overrides, { [field]: value });
    const raw = JSON.stringify({ version: 1, overrides });
    if (raw.length > MAX_RECORD_LENGTH) throw new Error("Connection settings are too large to save");
    profile.overrides = overrides;
    try {
      if (Object.keys(overrides).length) this.storage().setItem(this.key(network), raw);
      else this.storage().removeItem(this.key(network));
      profile.message = "Connection overrides saved. Unchanged fields follow updated deployment defaults.";
    } catch { profile.message = SESSION_ONLY; }
    return this.read(network, deployment);
  }

  reset(network: Network, deployment: SwapDefaults): ConnectionPreferenceState {
    const profile = this.profile(network);
    profile.overrides = {};
    profile.needsReset = false; // Explicit permission to use current defaults, even if deletion fails.
    try {
      this.storage().removeItem(this.key(network));
      profile.message = "Connection settings reset to current defaults. Future default updates will apply.";
    } catch { profile.message = `Defaults restored for this session only. ${SESSION_ONLY}`; }
    return this.read(network, deployment);
  }
}
