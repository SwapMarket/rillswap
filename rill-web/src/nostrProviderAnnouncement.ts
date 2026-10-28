/** Disconnected RS-005 NIP-01 advertisement event verifier for one supported network. */
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import canonicalize from "canonicalize";
import { verifyEvent, type NostrEvent } from "nostr-tools";

import { verifyManualProviderAdvertisement, type ManualProviderCandidate } from "./manualProviderAdvertisement";
import { parseStrictEventJson } from "./strictEventJson";
import { transportWorkRequirement } from "./transportPow";
import type { ProfileId } from "./swapPairs";

const HEX32 = /^[0-9a-f]{64}$/;
const HEX64 = /^[0-9a-f]{128}$/;
const encoder = new TextEncoder();
const HANDSHAKE_REQUIREMENTS = "rillswap/handshake-required-features";

/**
 * RS-005: unknown extension keys are ignored and the rest of the announcement
 * is used. Known keys must be well formed: the handshake requirement may only
 * name the epoch-binding feature (an unknown requirement refuses), the RS-010
 * asset list and RS-005 funding depth are validated by the manual
 * advertisement verifier, the RS-006 work requirement by transportWorkRequirement.
 */
function supportedExtensions(value: unknown): boolean {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const extensions = value as Record<string, unknown>;
  if (!Object.hasOwn(extensions, HANDSHAKE_REQUIREMENTS)) return true;
  const required = extensions[HANDSHAKE_REQUIREMENTS];
  return Array.isArray(required) && required.length === 1 && required[0] === "epoch-bound-session/v1";
}

export interface AnnouncementCandidate extends Omit<ManualProviderCandidate, "source"> {
  readonly source: "signed-nip01-announcement";
  readonly outerEventId: string;
  readonly addressD: string;
  /** The signed advertisement requires an epoch-bound session handshake. */
  readonly requiresEpochBinding: boolean;
  /** RS-006 transport proof of work every message to this provider needs (0: none). */
  readonly transportWorkBits: number;
}

export class AnnouncementRefusedError extends Error {
  constructor() {
    super("Provider announcement refused");
    this.name = "AnnouncementRefusedError";
  }
}

/**
 * Authenticate ONE raw signed kind-39417 event object, not a relay EVENT
 * frame. A future relay caller must independently cap the complete frame at
 * 128 KiB before extracting this object. No subscription, cache, trust pin,
 * endpoint connection, or admission is installed here.
 */
const SUPPORTED_NETWORK_TAGS: ReadonlySet<unknown> = new Set([
  "mainnet", "signet", "testnet4", "regtest",
]);

export function verifyNostrProviderAnnouncement(
  rawEventJson: string,
  approvedIdentityXOnlyKey: string,
  independentlySelectedNetwork: unknown,
  independentlySelectedProfile: ProfileId,
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
    const namespaceTag = tags[0];
    const networkTag = tags[1];
    if (!Array.isArray(namespaceTag) || namespaceTag.length !== 2 ||
        namespaceTag[0] !== "rillswap" || namespaceTag[1] !== "nostr-experimental-1" ||
        !Array.isArray(networkTag) || networkTag.length !== 2 ||
        networkTag[0] !== "network" || !SUPPORTED_NETWORK_TAGS.has(networkTag[1])) {
      throw new AnnouncementRefusedError();
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
        // The coarse public tag must name the one signed identity; the complete
        // identity is still compared with the independently selected network.
        (advertisement.network_identities[0] as Record<string, unknown>)?.name !== networkTag[1] ||
        !supportedExtensions(advertisement.extensions)) {
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
      // supportedExtensions admits only the exact epoch-binding requirement.
      requiresEpochBinding: Object.hasOwn(advertisement.extensions as object, HANDSHAKE_REQUIREMENTS),
      // Malformed or excessive work refuses the announcement rather than downgrading.
      transportWorkBits: transportWorkRequirement(advertisement.extensions as Record<string, unknown>),
    });
  } catch {
    throw new AnnouncementRefusedError();
  }
}
