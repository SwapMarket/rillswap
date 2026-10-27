/** Bounded multi-relay discovery and noncommitting, independently verified firm quotes. */
import { type AnnouncementCandidate, verifyNostrProviderAnnouncement } from "../nostrProviderAnnouncement";
import { parseStrictEventJson } from "../strictEventJson";
import { ANNOUNCEMENT_KIND, MAX_DISCOVERY_EVENTS } from "./discovery";
import { MAX_RELAYS } from "./config";
import { RelayConnection, type RelayQueryResult } from "./relay";
import { SwapError } from "./session";
import { ProtocolError, same } from "./wire";
import { type PreparedReverseQuote, prepareReverseQuote, type ReverseSwapRequest } from "./reverseSwap";
import { prepareSwap, type PreparedSwap, type SwapRequest } from "./swap";
import { type Erc20SwapRequest, type PreparedErc20Swap, prepareErc20Swap } from "./erc20Swap";
import type { EvmAssetIdentity } from "../manualProviderAdvertisement";
import { prepareLnErc20Quote, type LnErc20Request, type PreparedLnErc20Quote } from "./lnErc20Swap";

type AnnouncementProfile = Parameters<typeof verifyNostrProviderAnnouncement>[3];

export const MAX_QUOTE_PROVIDERS = 8;

export interface LocatedProvider {
  readonly announcement: AnnouncementCandidate;
  readonly rawAnnouncement: string;
  readonly relayUrls: readonly string[];
}

export interface RelayObservation {
  readonly url: string;
  readonly result: RelayQueryResult;
}

export interface ProviderDirectory {
  readonly providers: readonly LocatedProvider[];
  readonly warnings: readonly string[];
}

/** Unique events one identity may spend verification on per relay (RS-005 per-identity receive bound). */
export const MAX_IDENTITY_EVENTS = 32;

function authorOf(raw: string): string | null {
  try {
    const event = parseStrictEventJson(raw) as { pubkey?: unknown } | null;
    const author = event?.pubkey;
    return typeof author === "string" && /^[0-9a-f]{64}$/.test(author) ? author : null;
  } catch { return null; }
}

/**
 * Verified provider slots across relays. Receive work is bounded globally by
 * the relay count times the per-relay event limit, and per identity and relay
 * by MAX_IDENTITY_EVENTS. Anyone can publish announcements, so floods and
 * misbehaving providers degrade discovery with warnings rather than abort it:
 * invalid events cost nothing beyond their own verification, a truncated relay
 * is reported as incomplete, and an identity that signs conflicting data at
 * one revision (even an older one) is excluded. A pinned identity that
 * equivocates still stops discovery, because the user chose it.
 */
export function scanAnnouncements(
  observations: readonly RelayObservation[],
  network: SwapRequest["network"],
  identity?: string,
  profile: AnnouncementProfile = "btc-to-ln/v1",
): ProviderDirectory {
  const warnings: string[] = [];
  const verified = new Map<string, AnnouncementCandidate | null>();
  const overBudget = new Set<string>();
  const equivocating = new Set<string>();
  const revisions = new Map<string, string>();
  const slots = new Map<string, { announcement: AnnouncementCandidate; rawAnnouncement: string; relays: Set<string> }>();
  for (const { url, result } of observations) {
    if (result.truncated) warnings.push(`${url}: more than ${MAX_DISCOVERY_EVENTS} events, discovery incomplete`);
    else if (result.completion !== "eose") warnings.push(`${url}: incomplete discovery (${result.completion})`);
    // Budgets are per relay: the author is read before any signature check,
    // so one relay's forged events must not exhaust an identity elsewhere.
    const spent = new Map<string, number>();
    for (const raw of result.events) {
      let candidate = verified.get(raw);
      if (candidate === undefined) {
        const author = authorOf(raw);
        if (author === null || (identity !== undefined && author !== identity)) continue;
        const count = (spent.get(author) ?? 0) + 1;
        spent.set(author, count);
        if (count > MAX_IDENTITY_EVENTS) { overBudget.add(author); continue; }
        candidate = null;
        try { candidate = verifyNostrProviderAnnouncement(raw, author, network, profile); } catch { /* ignored */ }
        verified.set(raw, candidate);
      }
      if (candidate === null) continue;
      const slot = `${candidate.identityXOnlyKey}:${candidate.slot}`;
      const revision = `${slot}:${candidate.revision}`;
      if (revisions.has(revision) && revisions.get(revision) !== candidate.advertisementJcs) {
        if (identity !== undefined) {
          throw new SwapError("Provider announced conflicting data at the same revision; no quote was selected");
        }
        equivocating.add(candidate.identityXOnlyKey);
      }
      revisions.set(revision, candidate.advertisementJcs);
      const previous = slots.get(slot);
      if (!previous || candidate.revision > previous.announcement.revision) {
        slots.set(slot, { announcement: candidate, rawAnnouncement: raw, relays: new Set([url]) });
      } else if (candidate.revision === previous.announcement.revision) {
        previous.relays.add(url);
      }
    }
  }
  for (const author of overBudget) warnings.push(`${author.slice(0, 12)}…: more than ${MAX_IDENTITY_EVENTS} announcements, some ignored`);
  for (const author of equivocating) warnings.push(`${author.slice(0, 12)}…: conflicting announcements, provider excluded`);
  return {
    providers: [...slots.values()]
      .filter(({ announcement }) => !equivocating.has(announcement.identityXOnlyKey))
      .map(({ announcement, rawAnnouncement, relays }) => ({
        announcement, rawAnnouncement, relayUrls: Object.freeze([...relays]),
      })),
    warnings,
  };
}

async function observeRelays(
  urls: readonly string[], network: SwapRequest["network"], identity?: string, signal?: AbortSignal,
): Promise<readonly RelayObservation[]> {
  if (urls.length === 0 || urls.length > MAX_RELAYS) throw new SwapError("Relay count invalid");
  return Promise.all(urls.map(async (url): Promise<RelayObservation> => {
    let relay: RelayConnection | undefined;
    try {
      signal?.throwIfAborted();
      relay = await RelayConnection.open(url, 10_000, undefined, signal);
      signal?.throwIfAborted();
      // RS-005: the multi-letter `network` tag is not a portable relay index
      // (relay.primal.net refuses it); fetch by kind and verify the network locally.
      const filter: Record<string, unknown> = { kinds: [ANNOUNCEMENT_KIND] };
      if (identity) filter.authors = [identity];
      return { url, result: await relay.queryDetailed(filter, MAX_DISCOVERY_EVENTS) };
    } catch {
      return { url, result: { events: [], truncated: false, completion: "error" } };
    } finally { relay?.close(); }
  }));
}

export async function discoverMarketplace(
  urls: readonly string[], network: SwapRequest["network"], identity?: string, signal?: AbortSignal,
  profile: AnnouncementProfile = "btc-to-ln/v1",
): Promise<ProviderDirectory> {
  return scanAnnouncements(await observeRelays(urls, network, identity, signal), network, identity, profile);
}

/** One announced provider slot across every profile it serves, for browsing before any amount is entered. */
export interface DirectoryEntry {
  readonly identity: string;
  readonly slot: string;
  readonly profiles: readonly AnnouncementProfile[];
  readonly amountBands: AnnouncementCandidate["amountBands"];
  readonly indicativeFeePolicy: AnnouncementCandidate["indicativeFeePolicy"];
  readonly evmAssets: AnnouncementCandidate["evmAssets"];
  readonly relayUrls: readonly string[];
  readonly expiresAt: number;
}

export const DIRECTORY_PROFILES: readonly AnnouncementProfile[] = ["btc-to-ln/v1", "ln-to-btc/v1", "erc20-to-ln/v1", "ln-to-erc20/v1"];

/** Fee a provider announces for `amount`, before any firm quote. */
export function indicativeFee(policy: AnnouncementCandidate["indicativeFeePolicy"], amount: bigint): bigint {
  return BigInt(policy.base_sat) + (amount * BigInt(policy.proportional_millionths) + 999_999n) / 1_000_000n;
}

export interface Directory { readonly entries: readonly DirectoryEntry[]; readonly warnings: readonly string[] }

export async function discoverDirectory(urls: readonly string[], network: SwapRequest["network"], signal?: AbortSignal): Promise<Directory> {
  return directoryFromObservations(await observeRelays(urls, network, undefined, signal), network);
}

export function directoryFromObservations(observations: readonly RelayObservation[], network: SwapRequest["network"]): Directory {
  const entries = new Map<string, DirectoryEntry>();
  const warnings = new Set<string>();
  for (const profile of DIRECTORY_PROFILES) {
    const directory = scanAnnouncements(observations, network, undefined, profile);
    for (const warning of directory.warnings) warnings.add(warning);
    for (const { announcement, relayUrls } of directory.providers) {
      const key = `${announcement.identityXOnlyKey}:${announcement.slot}`;
      const previous = entries.get(key);
      entries.set(key, previous
        ? { ...previous, profiles: [...previous.profiles, profile], relayUrls: [...new Set([...previous.relayUrls, ...relayUrls])] }
        : { identity: announcement.identityXOnlyKey, slot: announcement.slot, profiles: [profile], amountBands: announcement.amountBands,
          indicativeFeePolicy: announcement.indicativeFeePolicy, evmAssets: announcement.evmAssets, relayUrls, expiresAt: announcement.expiresAt });
    }
  }
  return { entries: [...entries.values()].sort((a, b) => `${a.identity}:${a.slot}`.localeCompare(`${b.identity}:${b.slot}`)), warnings: [...warnings] };
}

export interface LocatedQuote<P extends { dispose(): void } = PreparedSwap> {
  readonly prepared: P;
  readonly relayUrl: string;
  /** Close the owned transport and discard unused private quote state. */
  dispose(): void;
}

const estimatedFee = (provider: LocatedProvider, amount: bigint): bigint => indicativeFee(provider.announcement.indicativeFeePolicy, amount);

export function eligibleProviders(providers: readonly LocatedProvider[], amount: bigint): readonly LocatedProvider[] {
  return providers.filter(({ announcement }) => withinBands(announcement.amountBands, amount))
    .sort((a, b) => {
      const difference = estimatedFee(a, amount) - estimatedFee(b, amount);
      return difference < 0n ? -1 : difference > 0n ? 1 :
        `${a.announcement.identityXOnlyKey}:${a.announcement.slot}`.localeCompare(`${b.announcement.identityXOnlyKey}:${b.announcement.slot}`);
    });
}

const shortIdentity = (provider: LocatedProvider): string => `${provider.announcement.identityXOnlyKey.slice(0, 12)}…`;

type AmountBands = AnnouncementCandidate["amountBands"];
const withinBands = (bands: AmountBands, amount: bigint): boolean =>
  bands.some((band) => amount >= BigInt(band.minimum_sat) && amount <= BigInt(band.maximum_sat));

/** Why no announced provider serves `amount`, phrased for the user. */
export function ineligibilityReason(providers: readonly { identity: string; amountBands: AmountBands }[], amount: bigint): string {
  if (providers.length === 0) return "No provider announced this swap direction on your relays. Try another relay or pin a provider in Settings.";
  const limits = providers.map(({ identity, amountBands }) => {
    const minimum = amountBands.reduce((low, band) => BigInt(band.minimum_sat) < low ? BigInt(band.minimum_sat) : low, BigInt(amountBands[0]!.minimum_sat));
    const maximum = amountBands.reduce((high, band) => BigInt(band.maximum_sat) > high ? BigInt(band.maximum_sat) : high, 0n);
    return `${minimum.toLocaleString()} to ${maximum.toLocaleString()} sat (${identity.slice(0, 12)}…)`;
  });
  return `No provider accepts ${amount.toLocaleString()} sat. Announced limits: ${limits.join("; ")}.`;
}

export const providerLimits = (providers: readonly LocatedProvider[]): { identity: string; amountBands: AmountBands }[] =>
  providers.map(({ announcement }) => ({ identity: announcement.identityXOnlyKey, amountBands: announcement.amountBands }));

/** The lowest announced fee for `amount` among directory entries serving `profile` (and `pinned`, if set). */
export type DirectoryEstimate = { readonly identity: string; readonly feeSat: bigint } | { readonly reason: string };

export function estimateFromDirectory(entries: readonly DirectoryEntry[], profile: AnnouncementProfile, amount: bigint, pinned = ""): DirectoryEstimate {
  const serving = entries.filter((entry) => entry.profiles.includes(profile) && (!pinned || entry.identity === pinned));
  const eligible = serving.filter((entry) => withinBands(entry.amountBands, amount))
    .map((entry) => ({ identity: entry.identity, feeSat: indicativeFee(entry.indicativeFeePolicy, amount) }))
    .sort((a, b) => a.feeSat < b.feeSat ? -1 : a.feeSat > b.feeSat ? 1 : a.identity.localeCompare(b.identity));
  if (eligible.length > 0) return eligible[0]!;
  return { reason: pinned && serving.length === 0 ? "The chosen provider does not announce this swap direction." : ineligibilityReason(serving, amount) };
}

export function rankQuotes(quotes: readonly LocatedQuote[]): readonly LocatedQuote[] {
  return [...quotes].sort((a, b) => {
    const left = a.prepared.quote, right = b.prepared.quote;
    const difference = left.contractAmountSat - right.contractAmountSat;
    return difference < 0n ? -1 : difference > 0n ? 1 :
      `${left.providerIdentity}:${left.providerSlot}`.localeCompare(`${right.providerIdentity}:${right.providerSlot}`);
  });
}

/** Each preparation owns its own inbox subscription and retains its exact offer. */
export async function quoteProviders(
  providers: readonly LocatedProvider[], request: Omit<SwapRequest, "identity">, signal?: AbortSignal,
): Promise<QuoteFanOut<PreparedSwap>> {
  const result = await fanOutQuotes(providers, (relay, provider) =>
    prepareSwap(relay, { ...request, identity: provider.announcement.identityXOnlyKey }, () => {}, {
      announcement: provider.rawAnnouncement, timeouts: { replyMs: 15_000, settleMs: 600_000 },
    }), signal);
  return { ...result, quotes: rankQuotes(result.quotes) };
}

/** LN to BTC: the lowest hold invoice for the same payout wins. Quotes are not payable yet. */
export async function quoteReverseProviders(
  providers: readonly LocatedProvider[], request: Omit<ReverseSwapRequest, "identity">, signal?: AbortSignal,
): Promise<QuoteFanOut<PreparedReverseQuote>> {
  const result = await fanOutQuotes(providers, (relay, provider) =>
    prepareReverseQuote(relay, { ...request, identity: provider.announcement.identityXOnlyKey },
      { announcement: provider.rawAnnouncement }), signal);
  return { ...result, quotes: rankReverseQuotes(result.quotes) };
}

/** Discovery selects counterparties, never the trusted asset or its units. */
export function selectEvmAsset(
  providers: readonly LocatedProvider[], asset: EvmAssetIdentity,
): { readonly asset: EvmAssetIdentity; readonly providers: readonly LocatedProvider[] } | null {
  const eligible = providers.filter((item) => item.announcement.evmAssets.some((served) => same(served, asset)));
  return eligible.length === 0 ? null : { asset, providers: eligible };
}

/** ERC20 to LN: the smallest lock for the same invoice wins. */
export async function quoteErc20Providers(
  providers: readonly LocatedProvider[], request: Omit<Erc20SwapRequest, "identity">, signal?: AbortSignal,
): Promise<QuoteFanOut<PreparedErc20Swap>> {
  const result = await fanOutQuotes(providers, (relay, provider) =>
    prepareErc20Swap(relay, { ...request, identity: provider.announcement.identityXOnlyKey }, () => {}, {
      announcement: provider.rawAnnouncement, timeouts: { replyMs: 15_000, settleMs: 900_000 },
    }), signal);
  const quotes = [...result.quotes].sort((a, b) => {
    const left = a.prepared.quote, right = b.prepared.quote;
    const difference = left.lockAmountTokenBase - right.lockAmountTokenBase;
    return difference < 0n ? -1 : difference > 0n ? 1 :
      `${left.providerIdentity}:${left.providerSlot}`.localeCompare(`${right.providerIdentity}:${right.providerSlot}`);
  });
  return { ...result, quotes };
}

/** Compare Lightning costs for the same exact ERC20 payout without creating hold invoices. */
export async function quoteLnErc20Providers(
  providers: readonly LocatedProvider[], request: Omit<LnErc20Request, "identity">, signal?: AbortSignal,
): Promise<QuoteFanOut<PreparedLnErc20Quote>> {
  const result = await fanOutQuotes(providers, (relay, provider) => prepareLnErc20Quote(relay,
    { ...request, identity: provider.announcement.identityXOnlyKey }, { announcement: provider.rawAnnouncement, replyMs: 15_000 }), signal);
  return { ...result, quotes: [...result.quotes].sort((a, b) => {
    const left = BigInt(a.prepared.quote.offer.economics.hold_invoice_sat), right = BigInt(b.prepared.quote.offer.economics.hold_invoice_sat);
    return left < right ? -1 : left > right ? 1 : a.prepared.quote.providerIdentity.localeCompare(b.prepared.quote.providerIdentity);
  }) };
}

export function rankReverseQuotes(quotes: readonly LocatedQuote<PreparedReverseQuote>[]): readonly LocatedQuote<PreparedReverseQuote>[] {
  return [...quotes].sort((a, b) => {
    const left = a.prepared.quote, right = b.prepared.quote;
    const difference = left.holdInvoiceSat - right.holdInvoiceSat;
    return difference < 0n ? -1 : difference > 0n ? 1 :
      `${left.providerIdentity}:${left.providerSlot}`.localeCompare(`${right.providerIdentity}:${right.providerSlot}`);
  });
}

export interface QuoteFanOut<P extends { dispose(): void }> {
  readonly quotes: readonly LocatedQuote<P>[];
  readonly failures: number;
  /** One line per provider that returned no acceptable offer, phrased for the user. */
  readonly reasons: readonly string[];
}

/** Why a provider's offer was not usable; only our own typed refusals carry detail. */
function failureReason(error: unknown): string {
  return error instanceof SwapError || error instanceof ProtocolError ? error.message : "no usable reply";
}

async function fanOutQuotes<P extends { dispose(): void }>(
  providers: readonly LocatedProvider[],
  prepare: (relay: RelayConnection, provider: LocatedProvider) => Promise<P>,
  signal?: AbortSignal,
): Promise<QuoteFanOut<P>> {
  const completed = new Set<LocatedQuote<P>>();
  const reasons: string[] = [];
  const cancel = (): void => { for (const quote of completed) quote.dispose(); };
  signal?.addEventListener("abort", cancel, { once: true });
  try {
  const results = await Promise.all(providers.slice(0, MAX_QUOTE_PROVIDERS).map(async (provider) => {
    let reason = "no relay reachable";
    for (const url of provider.relayUrls) {
      if (signal?.aborted) return null;
      let relay: RelayConnection | undefined;
      try {
        relay = await RelayConnection.open(url, 10_000, undefined, signal);
        signal?.throwIfAborted();
        const prepared = await prepare(relay, provider);
        const connection = relay;
        const quote = { prepared, relayUrl: url, dispose: () => { prepared.dispose(); connection.close(); } };
        if (signal?.aborted) { quote.dispose(); return null; }
        completed.add(quote);
        return quote;
      } catch (error) { relay?.close(); reason = failureReason(error); }
    }
    reasons.push(`${shortIdentity(provider)}: ${reason}`);
    return null;
  }));
  const quotes = results.filter((quote): quote is LocatedQuote<P> => quote !== null);
  if (signal?.aborted) { cancel(); return { quotes: [], failures: results.length, reasons: [] }; }
  return { quotes, failures: results.length - quotes.length, reasons };
  } finally { signal?.removeEventListener("abort", cancel); }
}
