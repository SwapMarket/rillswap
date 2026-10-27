/** Disconnected private-regtest NIP-59 producer, not delivery or admission. */
import canonicalize from "canonicalize";
import { finalizeEvent, generateSecretKey, getPublicKey, nip44, nip59, verifyEvent, type NostrEvent } from "nostr-tools";

import { committedWork, mineNonceTag } from "./transportPow";

const MAX_ENVELOPE_BYTES = 16 * 1024;
const MAX_OUTER_BYTES = 128 * 1024;
const TWO_DAYS = 2 * 24 * 60 * 60;
const XONLY_HEX = /^[0-9a-f]{64}$/;
const encoder = new TextEncoder();

export class Nip59FrameConstructionError extends Error {
  constructor() {
    super("Private-regtest NIP-59 frame construction refused");
    this.name = "Nip59FrameConstructionError";
  }
}

interface UnsignedWrap {
  readonly wrapperSecret: Uint8Array;
  readonly wrapper: string;
  readonly createdAt: number;
  readonly content: string;
  readonly recipient: string;
}

/** Validate the envelope, then build the rumor, seal and encrypted outer content. */
function unsignedWrap(canonicalEnvelope: string, senderSessionSecret: Uint8Array, recipient: string): UnsignedWrap {
  if (typeof canonicalEnvelope !== "string" ||
      encoder.encode(canonicalEnvelope).length === 0 ||
      encoder.encode(canonicalEnvelope).length > MAX_ENVELOPE_BYTES ||
      !(senderSessionSecret instanceof Uint8Array) || senderSessionSecret.length !== 32 ||
      typeof recipient !== "string" || !XONLY_HEX.test(recipient)) {
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
  if (envelope.protocol !== "rillswap" || envelope.wire_version !== "1" ||
      envelope.sender_session_key !== getPublicKey(senderSessionSecret)) {
    throw new Nip59FrameConstructionError();
  }
  // nostr-tools' unsigned rumor and NIP-44 v2 signed kind-13 seal; the outer
  // wrap is built here (as nostr-tools' createWrap does) so work can be mined
  // into its tags before the one-time key signs it.
  const rumor = nip59.createRumor(
    { kind: 21417, tags: [["rillswap", "nostr-experimental-1"]], content: canonicalEnvelope },
    senderSessionSecret,
  );
  const seal = nip59.createSeal(rumor, senderSessionSecret, recipient);
  const wrapperSecret = generateSecretKey();
  return {
    wrapperSecret,
    wrapper: getPublicKey(wrapperSecret),
    createdAt: Math.round(Math.round(Date.now() / 1000) - Math.random() * TWO_DAYS),
    content: nip44.encrypt(JSON.stringify(seal), nip44.getConversationKey(wrapperSecret, recipient)),
    recipient,
  };
}

/** Sign the outer event and verify the bytes that would actually be published. */
function signedWrap(unsigned: UnsignedWrap, tags: string[][], workBits: number): NostrEvent {
  const outer = finalizeEvent(
    { kind: 1059, created_at: unsigned.createdAt, tags, content: unsigned.content },
    unsigned.wrapperSecret,
  );
  // finalizeEvent caches signature verification on the in-memory object.
  // Round-trip through wire JSON to verify the bytes actually returned.
  const serialized = JSON.stringify(outer);
  if (encoder.encode(serialized).length > MAX_OUTER_BYTES) throw new Nip59FrameConstructionError();
  const wireEvent = JSON.parse(serialized) as NostrEvent;
  if (wireEvent.kind !== 1059 || wireEvent.tags.length !== (workBits ? 2 : 1) ||
      wireEvent.tags[0]?.length !== 2 || wireEvent.tags[0]?.[0] !== "p" ||
      wireEvent.tags[0]?.[1] !== unsigned.recipient ||
      wireEvent.pubkey !== unsigned.wrapper ||
      !verifyEvent(wireEvent) ||
      (workBits > 0 && committedWork(wireEvent.id, wireEvent.tags) < workBits)) {
    throw new Nip59FrameConstructionError();
  }
  return wireEvent;
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
    const unsigned = unsignedWrap(canonicalEnvelope, senderSessionSecret, recipientMailboxXOnlyKey);
    return signedWrap(unsigned, [["p", recipientMailboxXOnlyKey]], 0);
  } catch {
    // Do not surface a library exception carrying a key, ciphertext, or frame.
    throw new Nip59FrameConstructionError();
  }
}

/**
 * The same wrap, carrying RS-006 transport proof of work when `workBits` > 0,
 * as a provider advertising `rillswap/transport-pow` requires on every message.
 */
export async function wrapWithTransportWork(
  canonicalEnvelope: string,
  senderSessionSecret: Uint8Array,
  recipientMailboxXOnlyKey: string,
  workBits: number,
): Promise<NostrEvent> {
  if (workBits === 0) return wrapPrivateRegtestEnvelope(canonicalEnvelope, senderSessionSecret, recipientMailboxXOnlyKey);
  try {
    const unsigned = unsignedWrap(canonicalEnvelope, senderSessionSecret, recipientMailboxXOnlyKey);
    const tags = await mineNonceTag(
      unsigned.wrapper, unsigned.createdAt, 1059, [["p", recipientMailboxXOnlyKey]], unsigned.content, workBits,
    );
    return signedWrap(unsigned, tags, workBits);
  } catch {
    throw new Nip59FrameConstructionError();
  }
}
