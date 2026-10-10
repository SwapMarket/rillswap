/** Explicit read-only archive lookup, never handshake, acknowledgment, payment, or funding publication. */
import type { RelayConnection } from "./relay";
import { GIFT_WRAP_KIND, type Envelope, type ReverseFundingMailboxReader, SwapError } from "./session";

export interface ReverseFundingArchiveResult {
  /** Session-authenticated candidates. Binding signatures/transaction bytes still need independent validation. */
  readonly envelopes: readonly Envelope[];
  readonly incomplete: boolean;
}

export async function recoverReverseFundingEnvelopes(relays: readonly Pick<RelayConnection, "queryDetailed">[],
  receiver: ReverseFundingMailboxReader): Promise<ReverseFundingArchiveResult> {
  if (relays.length < 1 || relays.length > 4) throw new SwapError("Choose one to four recovery relays");
  const selected = [...relays]; // Caller mutations across queries do not change selection.
  const responses = await Promise.allSettled(selected.map((relay) => relay.queryDetailed({ kinds: [GIFT_WRAP_KIND], "#p": [receiver.clientKey] }, 64, 10000)));
  const envelopes: Envelope[] = []; let incomplete = false;
  for (const response of responses) {
    if (response.status !== "fulfilled") { incomplete = true; continue; }
    const result = response.value;
    if (result.truncated || result.events.length > 64) { incomplete = true; continue; }
    if (result.completion !== "eose") incomplete = true;
    for (const raw of result.events) {
      const envelope = receiver.admit(raw); if (envelope) envelopes.push(envelope);
    }
  }
  // EOSE or an empty archive proves neither no payment nor absence of funding.
  return Object.freeze({ envelopes: Object.freeze(envelopes), incomplete });
}
