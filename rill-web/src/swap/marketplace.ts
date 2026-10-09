/** Bounded multi-relay discovery and noncommitting, independently verified firm quotes. */
import { type AnnouncementCandidate, verifyNostrProviderAnnouncement } from "../nostrProviderAnnouncement";
import { parseStrictEventJson } from "../strictEventJson";
import { ANNOUNCEMENT_KIND, MAX_DISCOVERY_EVENTS } from "./discovery";
import { MAX_RELAYS } from "./config";
import { RelayConnection, type RelayQueryResult } from "./relay";
import { SwapError } from "./session";
import { prepareSwap, type PreparedSwap, type SwapRequest } from "./swap";

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

export function scanAnnouncements(
  observations: readonly RelayObservation[],
  network: SwapRequest["network"],
  identity?: string,
): ProviderDirectory {
  const warnings: string[] = [];
  const uniqueRaw = new Set<string>();
  const revisions = new Map<string, string>();
  const slots = new Map<string, { announcement: AnnouncementCandidate; rawAnnouncement: string; relays: Set<string> }>();
  for (const { url, result } of observations) {
    if (result.truncated) throw new SwapError("Relay discovery exceeded its event limit; narrow your relay set or pin a provider");
    if (result.completion !== "eose") warnings.push(`${url}: incomplete discovery (${result.completion})`);
    for (const raw of result.events) {
      uniqueRaw.add(raw);
      if (uniqueRaw.size > MAX_DISCOVERY_EVENTS) {
        throw new SwapError("Combined relay discovery exceeded its event limit; no quote was selected");
      }
      let candidate: AnnouncementCandidate;
      try {
        const event = parseStrictEventJson(raw) as { pubkey?: unknown } | null;
        const author = identity ?? event?.pubkey;
        if (typeof author !== "string" || !/^[0-9a-f]{64}$/.test(author)) continue;
        candidate = verifyNostrProviderAnnouncement(raw, author, network, "btc-to-ln/v1");
      } catch { continue; }
      const slot = `${candidate.identityXOnlyKey}:${candidate.slot}`;
      const revision = `${slot}:${candidate.revision}`;
      if (revisions.has(revision) && revisions.get(revision) !== candidate.advertisementJcs) {
        throw new SwapError("Provider announced conflicting data at the same revision; no quote was selected");
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
  return {
    providers: [...slots.values()].map(({ announcement, rawAnnouncement, relays }) => ({
      announcement, rawAnnouncement, relayUrls: Object.freeze([...relays]),
    })),
    warnings,
  };
}

export async function discoverMarketplace(
  urls: readonly string[], network: SwapRequest["network"], identity?: string, signal?: AbortSignal,
): Promise<ProviderDirectory> {
  if (urls.length === 0 || urls.length > MAX_RELAYS) throw new SwapError("Relay count invalid");
  const observations = await Promise.all(urls.map(async (url): Promise<RelayObservation> => {
    let relay: RelayConnection | undefined;
    try {
      signal?.throwIfAborted();
      relay = await RelayConnection.open(url, 10_000, undefined, signal);
      signal?.throwIfAborted();
      const filter: Record<string, unknown> = { kinds: [ANNOUNCEMENT_KIND], "#network": [network.name] };
      if (identity) filter.authors = [identity];
      return { url, result: await relay.queryDetailed(filter, MAX_DISCOVERY_EVENTS) };
    } catch {
      return { url, result: { events: [], truncated: false, completion: "error" } };
    } finally { relay?.close(); }
  }));
  return scanAnnouncements(observations, network, identity);
}

export interface LocatedQuote {
  readonly prepared: PreparedSwap;
  readonly relayUrl: string;
  /** Close the owned transport and discard unused private quote state. */
  dispose(): void;
}

const estimatedFee = (provider: LocatedProvider, amount: bigint): bigint => {
  const fee = provider.announcement.indicativeFeePolicy;
  return BigInt(fee.base_sat) + (amount * BigInt(fee.proportional_millionths) + 999_999n) / 1_000_000n;
};

export function eligibleProviders(providers: readonly LocatedProvider[], amount: bigint): readonly LocatedProvider[] {
  return providers.filter(({ announcement }) => announcement.amountBands.some((band) =>
    amount >= BigInt(band.minimum_sat) && amount <= BigInt(band.maximum_sat)))
    .sort((a, b) => {
      const difference = estimatedFee(a, amount) - estimatedFee(b, amount);
      return difference < 0n ? -1 : difference > 0n ? 1 :
        `${a.announcement.identityXOnlyKey}:${a.announcement.slot}`.localeCompare(`${b.announcement.identityXOnlyKey}:${b.announcement.slot}`);
    });
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
): Promise<{ quotes: readonly LocatedQuote[]; failures: number }> {
  const completed = new Set<LocatedQuote>();
  const cancel = (): void => { for (const quote of completed) quote.dispose(); };
  signal?.addEventListener("abort", cancel, { once: true });
  try {
  const results = await Promise.all(providers.slice(0, MAX_QUOTE_PROVIDERS).map(async (provider) => {
    for (const url of provider.relayUrls) {
      if (signal?.aborted) return null;
      let relay: RelayConnection | undefined;
      try {
        relay = await RelayConnection.open(url, 10_000, undefined, signal);
        signal?.throwIfAborted();
        const prepared = await prepareSwap(relay, { ...request, identity: provider.announcement.identityXOnlyKey }, () => {}, {
          announcement: provider.rawAnnouncement, timeouts: { replyMs: 15_000, settleMs: 600_000 },
        });
        const connection = relay;
        const quote = { prepared, relayUrl: url, dispose: () => { prepared.dispose(); connection.close(); } };
        if (signal?.aborted) { quote.dispose(); return null; }
        completed.add(quote);
        return quote;
      } catch { relay?.close(); }
    }
    return null;
  }));
  const quotes = results.filter((quote): quote is LocatedQuote => quote !== null);
  if (signal?.aborted) { cancel(); return { quotes: [], failures: results.length }; }
  return { quotes: rankQuotes(quotes), failures: results.length - quotes.length };
  } finally { signal?.removeEventListener("abort", cancel); }
}
