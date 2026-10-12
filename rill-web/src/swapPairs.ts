/**
 * Display assets and the swap route for each send/receive pair. Asset labels
 * are UI concepts; only a route's `profile` names a protocol profile. Adding a
 * future asset (for example a stablecoin) changes this table, not the form.
 */
export type AssetId = "btc" | "ln" | "usdt" | "usdc";
export type ProfileId = "btc-to-ln/v1" | "ln-to-btc/v1" | "erc20-to-ln/v1" | "ln-to-erc20/v1";

export interface Asset {
  readonly id: AssetId;
  readonly symbol: string;
  readonly name: string;
  /** Present when no route involving this asset is offered yet. */
  readonly unavailable?: string;
}

export const ASSETS: readonly Asset[] = [
  { id: "btc", symbol: "BTC", name: "Bitcoin" },
  { id: "ln", symbol: "LN", name: "Lightning" },
  { id: "usdt", symbol: "USDT", name: "Tether" },
  { id: "usdc", symbol: "USDC", name: "USD Coin" },
];

export interface Route {
  readonly from: Asset;
  readonly to: Asset;
  /** Null when no protocol profile serves this pair. */
  readonly profile: ProfileId | null;
  /** Why this pair cannot be quoted in this build, or null when it can. */
  readonly unavailable: string | null;
  readonly title: string;
  readonly tagline: string;
}

const PROFILES: Partial<Record<`${AssetId}>${AssetId}`, ProfileId>> = {
  "btc>ln": "btc-to-ln/v1",
  "ln>btc": "ln-to-btc/v1",
  "usdc>ln": "erc20-to-ln/v1",
  "usdt>ln": "erc20-to-ln/v1",
  "ln>usdc": "ln-to-erc20/v1",
  "ln>usdt": "ln-to-erc20/v1",
};

/** Profiles whose browser quote flow exists in this build. */
const QUOTABLE: ReadonlySet<ProfileId> = new Set(["btc-to-ln/v1", "ln-to-btc/v1", "erc20-to-ln/v1"]);

/** Stablecoin display assets match an announced ERC20 by symbol suffix (dev chains serve fUSDC for USDC). */
export const STABLECOIN_SYMBOL: Partial<Record<AssetId, "USDC" | "USDT">> = { usdc: "USDC", usdt: "USDT" };

export function asset(id: string): Asset {
  const found = ASSETS.find((item) => item.id === id);
  if (!found) throw new Error("Unknown asset");
  return found;
}

export function routeFor(fromId: string, toId: string): Route {
  const from = asset(fromId), to = asset(toId);
  const profile = PROFILES[`${from.id}>${to.id}`] ?? null;
  const unavailable = from.id === to.id ? "Choose two different assets."
    : from.unavailable ?? to.unavailable
    ?? (profile === null ? `${from.name} to ${to.name} swaps are not offered.`
      : QUOTABLE.has(profile) ? null : `${from.name} to ${to.name} quotes are coming soon.`);
  return { from, to, profile, unavailable,
    title: `${from.name} in. ${to.name} out.`,
    tagline: profile === "ln-to-btc/v1"
      ? "Pay a Lightning invoice, receive Bitcoin on-chain. No account. Your keys stay with you."
      : profile === "btc-to-ln/v1"
        ? "Pay a Lightning invoice from your Bitcoin wallet. No account. Your keys stay with you."
        : profile === "erc20-to-ln/v1"
          ? `Pay a Lightning invoice with ${from.symbol} from your EVM wallet. No account. Your keys stay with you.`
          : "This pair is shown for planning. It cannot be quoted yet." };
}
