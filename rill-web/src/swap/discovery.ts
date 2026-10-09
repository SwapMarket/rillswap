/** Provider discovery over one relay (port of rill-cli live_swap.discover). */
import { type AnnouncementCandidate, verifyNostrProviderAnnouncement } from "../nostrProviderAnnouncement";
import { SwapError } from "./session";

export const ANNOUNCEMENT_KIND = 39417;
export const MAX_DISCOVERY_EVENTS = 256;

export interface AnnouncementSource {
  query(filter: Record<string, unknown>, limit: number, timeoutMs?: number):
    Promise<{ events: string[]; truncated: boolean }>;
}


/**
 * Select the highest valid revision the relay returned. A relay can withhold
 * announcements, so this is not proof of freshness; equivocation at one
 * revision or a truncated flood is refused rather than guessed around.
 */
export async function discoverProvider(
  source: AnnouncementSource,
  identity: string,
  network: unknown,
  profile: "btc-to-ln/v1",
  timeoutMs = 10_000,
): Promise<AnnouncementCandidate> {
  const { events, truncated } = await source.query(
    { kinds: [ANNOUNCEMENT_KIND], authors: [identity] },
    MAX_DISCOVERY_EVENTS,
    timeoutMs,
  );
  if (truncated) throw new SwapError("provider discovery event limit exceeded; nothing was committed");
  let best: AnnouncementCandidate | null = null;
  const revisions = new Map<string, string>();
  for (const raw of events) {
    let found: AnnouncementCandidate;
    try {
      found = verifyNostrProviderAnnouncement(raw, identity, network, profile);
    } catch {
      continue;
    }
    const key = `${found.slot}:${found.revision}`;
    if (revisions.has(key) && revisions.get(key) !== found.advertisementJcs) {
      throw new SwapError("provider announced conflicting data at the same revision");
    }
    revisions.set(key, found.advertisementJcs);
    if (best === null || found.revision > best.revision) best = found;
  }
  if (best === null) throw new SwapError("no valid provider announcement found; nothing was committed");
  if (best.advertisedEpochInboxKeys.length === 0) throw new SwapError("provider announcement names no inbox");
  return best;
}
