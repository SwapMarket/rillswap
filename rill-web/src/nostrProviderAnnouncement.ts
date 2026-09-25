/** Disconnected RS-005 private-regtest NIP-01 advertisement event verifier. */
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import canonicalize from "canonicalize";
import { verifyEvent, type NostrEvent } from "nostr-tools";

import { verifyManualProviderAdvertisement, type ManualProviderCandidate } from "./manualProviderAdvertisement";
import { parseStrictEventJson } from "./strictEventJson";

const HEX32 = /^[0-9a-f]{64}$/;
const HEX64 = /^[0-9a-f]{128}$/;
const encoder = new TextEncoder();

export interface AnnouncementCandidate extends Omit<ManualProviderCandidate, "source"> {
  readonly source: "signed-nip01-announcement";
  readonly outerEventId: string;
  readonly addressD: string;
}

export class AnnouncementRefusedError extends Error {
  constructor() {
    super("Private-regtest provider announcement refused");
    this.name = "AnnouncementRefusedError";
  }
}

/**
 * Authenticate ONE raw signed kind-39417 event object, not a relay EVENT
 * frame. A future relay caller must independently cap the complete frame at
 * 128 KiB before extracting this object. No subscription, cache, trust pin,
 * endpoint connection, or admission is installed here.
 */
export function verifyPrivateRegtestAnnouncement(
  rawEventJson: string,
  approvedIdentityXOnlyKey: string,
  independentlySelectedNetwork: unknown,
  independentlySelectedProfile: "btc-to-ln/v1" | "ln-to-btc/v1",
): AnnouncementCandidate {
  try {
    const raw = parseStrictEventJson(rawEventJson);
    if (raw === null || typeof raw !== "object" || Array.isArray(raw)) {
      throw new AnnouncementRefusedError();
    }
    const event = raw as Record<string, unknown>;
    const fields = ["id", "pubkey", "created_at", "kind", "tags", "content", "sig"];
    if (Object.keys(event).length !== fields.length ||
        !fields.every((field) => Object.hasOwn(event, field)) ||
        typeof event.id !== "string" || !HEX32.test(event.id) ||
        typeof event.pubkey !== "string" || !HEX32.test(event.pubkey) ||
        typeof event.sig !== "string" || !HEX64.test(event.sig) ||
        !Number.isSafeInteger(event.created_at) || (event.created_at as number) < 0 ||
        event.kind !== 39417 ||
        typeof event.content !== "string" ||
        encoder.encode(event.content).length > 64 * 1024 ||
        !Array.isArray(event.tags) || event.tags.length !== 3) {
      throw new AnnouncementRefusedError();
    }
    const tags = event.tags as unknown[];
    const expected = [["rillswap", "nostr-experimental-1"], ["network", "regtest"]];
    for (let i = 0; i < expected.length; i++) {
      const tag = tags[i];
      if (!Array.isArray(tag) || tag.length !== 2 ||
          tag[0] !== expected[i]?.[0] || tag[1] !== expected[i]?.[1]) {
        throw new AnnouncementRefusedError();
      }
    }
    const addressTag = tags[2];
    if (!Array.isArray(addressTag) || addressTag.length !== 2 ||
        addressTag[0] !== "d" || typeof addressTag[1] !== "string" ||
        !HEX32.test(addressTag[1])) {
      throw new AnnouncementRefusedError();
    }
    // JSON.parse gives a fresh object without nostr-tools' verification cache.
    // The reconstructed NIP-01 event ID and BIP340 signature must both match.
    if (!verifyEvent(event as unknown as NostrEvent)) throw new AnnouncementRefusedError();

    const content: unknown = parseStrictEventJson(event.content, 64 * 1024);
    if (content === null || typeof content !== "object" || Array.isArray(content)) {
      throw new AnnouncementRefusedError();
    }
    const wrapper = content as Record<string, unknown>;
    const ad = wrapper.advertisement;
    if (ad === null || typeof ad !== "object" || Array.isArray(ad)) {
      throw new AnnouncementRefusedError();
    }
    const advertisement = ad as Record<string, unknown>;
    if (advertisement.provider_identity_xonly_key !== event.pubkey ||
        advertisement.created_at !== event.created_at ||
        !Array.isArray(advertisement.network_identities) ||
        advertisement.network_identities.length !== 1 ||
        (advertisement.network_identities[0] as Record<string, unknown>)?.name !== "regtest" ||
        advertisement.extensions === null ||
        typeof advertisement.extensions !== "object" ||
        Array.isArray(advertisement.extensions) ||
        Object.keys(advertisement.extensions).length !== 0) {
      throw new AnnouncementRefusedError();
    }
    const selected = verifyManualProviderAdvertisement(
      event.content, approvedIdentityXOnlyKey,
      independentlySelectedNetwork, independentlySelectedProfile,
    );
    const tuple = canonicalize([
      "rillswap", "nostr-experimental-1",
      advertisement.network_identities[0], advertisement.slot,
    ]);
    if (tuple === undefined || bytesToHex(sha256(encoder.encode(tuple))) !== addressTag[1]) {
      throw new AnnouncementRefusedError();
    }
    return Object.freeze({
      ...selected,
      source: "signed-nip01-announcement" as const,
      outerEventId: event.id,
      addressD: addressTag[1],
    });
  } catch {
    throw new AnnouncementRefusedError();
  }
}
