/**
 * Provider and offer ranking, shared by the marketplace and the review UI.
 *
 * "time": fewest funding confirmations first, then price (the default);
 * "price": cheapest first, then confirmations. A provider that did not
 * announce its depth (null) sorts after every known one, never as 0 or 1.
 * Dependency-free at runtime so UI test fixtures can use it unchanged.
 */
import type { Erc20Quote } from "./erc20Swap";
import type { PreparedLnErc20Quote } from "./lnErc20Swap";
import type { ReverseQuote } from "./reverseSwap";
import type { PreparedQuote } from "./swap";

/** Ranking reads only the authenticated quote of a located offer. */
type Offer<Q> = { readonly prepared: { readonly quote: Q } };

export type SortMode = "time" | "price";

/** What ranking compares: a funding depth, a price in the flow's own unit, and a stable tie-break. */
export interface Ranked { readonly depth: number | null; readonly price: bigint; readonly tie: string }

const byDepth = (a: number | null, b: number | null): number => a === b ? 0 : a === null ? 1 : b === null ? -1 : a - b;
const byPrice = (a: bigint, b: bigint): number => a < b ? -1 : a > b ? 1 : 0;

export function compareRanked(mode: SortMode, a: Ranked, b: Ranked): number {
  const order = mode === "time"
    ? byDepth(a.depth, b.depth) || byPrice(a.price, b.price)
    : byPrice(a.price, b.price) || byDepth(a.depth, b.depth);
  return order || a.tie.localeCompare(b.tie);
}

export const rank = <T>(items: readonly T[], key: (item: T) => Ranked, mode: SortMode): T[] =>
  [...items].sort((a, b) => compareRanked(mode, key(a), key(b)));

/** The fastest and the cheapest of several offers (possibly the same one), for manual-selection labels. */
export function fastestAndCheapest<T>(items: readonly T[], key: (item: T) => Ranked): { fastest: T | null; cheapest: T | null } {
  if (items.length < 2) return { fastest: null, cheapest: null };
  return { fastest: rank(items, key, "time")[0]!, cheapest: rank(items, key, "price")[0]! };
}

/** BTC to LN: signed depth, then the on-chain amount to fund for the same invoice. */
export const forwardRank = ({ prepared: { quote } }: Offer<PreparedQuote>): Ranked =>
  ({ depth: quote.fundingConfirmations, price: quote.contractAmountSat, tie: `${quote.providerIdentity}:${quote.providerSlot}` });

/** LN to BTC: the estimate's depth before the payout can be claimed, then the hold invoice. */
export const reverseRank = ({ prepared: { quote } }: Offer<ReverseQuote>): Ranked =>
  ({ depth: quote.fundingConfirmations, price: quote.holdInvoiceSat, tie: `${quote.providerIdentity}:${quote.providerSlot}` });

/** ERC20 to LN: signed EVM depth, then the token amount to lock for the same invoice. */
export const erc20Rank = ({ prepared: { quote } }: Offer<Erc20Quote>): Ranked =>
  ({ depth: quote.fundingConfirmations, price: quote.lockAmountTokenBase, tie: `${quote.providerIdentity}:${quote.providerSlot}` });

/** LN to ERC20: the estimate's EVM depth, then the hold invoice for the same token payout. */
export const lnErc20Rank = ({ prepared: { quote } }: Offer<PreparedLnErc20Quote["quote"]>): Ranked =>
  ({ depth: quote.offer.funding_confirmations, price: BigInt(quote.offer.economics.hold_invoice_sat), tie: quote.providerIdentity });
