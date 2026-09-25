/** Disconnected private-regtest NIP-59 producer, not delivery or admission. */
import canonicalize from "canonicalize";
import { getPublicKey, nip59, verifyEvent, type NostrEvent } from "nostr-tools";

const MAX_ENVELOPE_BYTES = 16 * 1024;
const MAX_OUTER_BYTES = 128 * 1024;
const XONLY_HEX = /^[0-9a-f]{64}$/;
const encoder = new TextEncoder();

export class Nip59FrameConstructionError extends Error {
  constructor() {
    super("Private-regtest NIP-59 frame construction refused");
    this.name = "Nip59FrameConstructionError";
  }
}

/**
 * Wrap an already application-validated, canonical RS-001 envelope. The caller
 * owns both the session key and independent recipient selection. This function
 * does not sign the application envelope, verify its schema or transcript,
 * publish the event, persist a key, or grant swap/session authority.
 */
export function wrapPrivateRegtestEnvelope(
  canonicalEnvelope: string,
  senderSessionSecret: Uint8Array,
  recipientMailboxXOnlyKey: string,
): NostrEvent {
  try {
    if (typeof canonicalEnvelope !== "string" ||
        encoder.encode(canonicalEnvelope).length === 0 ||
        encoder.encode(canonicalEnvelope).length > MAX_ENVELOPE_BYTES ||
        !(senderSessionSecret instanceof Uint8Array) || senderSessionSecret.length !== 32 ||
        typeof recipientMailboxXOnlyKey !== "string" ||
        !XONLY_HEX.test(recipientMailboxXOnlyKey)) {
      throw new Nip59FrameConstructionError();
    }
    // Comparing the original bytes to JCS also rejects duplicate keys,
    // insignificant whitespace, and noncanonical JSON string escapes. It is
    // not a substitute for full RS-001 schema or signature validation.
    const value: unknown = JSON.parse(canonicalEnvelope);
    if (value === null || typeof value !== "object" || Array.isArray(value) ||
        canonicalize(value) !== canonicalEnvelope) {
      throw new Nip59FrameConstructionError();
    }
    const envelope = value as Record<string, unknown>;
    const sender = getPublicKey(senderSessionSecret);
    if (envelope.protocol !== "rillswap" || envelope.wire_version !== "1" ||
        envelope.sender_session_key !== sender) {
      throw new Nip59FrameConstructionError();
    }

    // nostr-tools creates an unsigned rumor, NIP-44 v2 signed kind-13 seal,
    // and signed kind-1059 wrap with a fresh one-time key and recipient p tag.
    const outer = nip59.wrapEvent(
      { kind: 21417, tags: [["rillswap", "nostr-experimental-1"]], content: canonicalEnvelope },
      senderSessionSecret,
      recipientMailboxXOnlyKey,
    );
    // finalizeEvent caches signature verification on the in-memory object.
    // Round-trip through wire JSON to verify the bytes actually returned.
    const serialized = JSON.stringify(outer);
    if (encoder.encode(serialized).length > MAX_OUTER_BYTES) {
      throw new Nip59FrameConstructionError();
    }
    const wireEvent = JSON.parse(serialized) as NostrEvent;
    if (wireEvent.kind !== 1059 || wireEvent.tags.length !== 1 ||
        wireEvent.tags[0]?.length !== 2 || wireEvent.tags[0]?.[0] !== "p" ||
        wireEvent.tags[0]?.[1] !== recipientMailboxXOnlyKey ||
        !verifyEvent(wireEvent)) {
      throw new Nip59FrameConstructionError();
    }
    return wireEvent;
  } catch {
    // Do not surface a library exception carrying a key, ciphertext, or frame.
    throw new Nip59FrameConstructionError();
  }
}
