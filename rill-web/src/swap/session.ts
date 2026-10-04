/**
 * One browser client session: keys, signed envelopes, NIP-59 gift wraps,
 * and an authenticated inbox (port of rill-cli live_swap._Session and
 * rill-provider's strict gift-wrap receive rules). Keys live in memory only.
 */
import { schnorr } from "@noble/curves/secp256k1.js";
import { bytesToHex, hexToBytes, randomBytes } from "@noble/hashes/utils.js";
import canonicalize from "canonicalize";
import { getEventHash, getPublicKey, nip44, type NostrEvent, verifyEvent } from "nostr-tools";

import { wrapPrivateRegtestEnvelope } from "../nip59Transport";
import { jcs, unsignedEnvelopeHash } from "./hashes";
import { requireShape } from "./wire";

export const GIFT_WRAP_KIND = 1059;
const SEAL_KIND = 13;
const RUMOR_KIND = 21417;
const RUMOR_MEMBERS = ["content", "created_at", "id", "kind", "pubkey", "tags"];
const MAX_EVENT_BYTES = 128 * 1024;
const MAX_ENVELOPE_BYTES = 16 * 1024;
const encoder = new TextEncoder();

export interface Envelope {
  readonly protocol: "rillswap";
  readonly wire_version: "1";
  readonly profile_id: string;
  readonly network_identity: unknown;
  readonly session_id: string;
  readonly message_id: string;
  readonly sender_session_key: string;
  readonly sequence: number;
  readonly in_reply_to: string | null;
  readonly contract_hash: string | null;
  readonly message_type: string;
  readonly payload: Record<string, unknown>;
  readonly required_features: readonly string[];
  readonly extensions: Record<string, unknown>;
  readonly signature: string | null;
}

export interface Frame {
  readonly sealAuthor: string;
  readonly envelope: Envelope;
}

const refused = (): never => {
  throw new Error("gift wrap refused");
};

function signedEvent(raw: string, kind: number): NostrEvent {
  if (encoder.encode(raw).length > MAX_EVENT_BYTES) refused();
  const event = JSON.parse(raw) as NostrEvent;
  if (event === null || typeof event !== "object" || event.kind !== kind || !verifyEvent(event)) refused();
  return event;
}

/**
 * Decode one received gift wrap for `recipientSecret`, or throw. Mirrors
 * rill-provider `_nip59_receive._decode`: authenticate before decrypting,
 * exactly one recipient tag, an empty-tag seal, an exact rumor whose ID
 * recomputes, canonical envelope content, and matching authors.
 */
export function unwrapGiftWrap(
  raw: string,
  recipientSecret: Uint8Array,
  network: unknown,
  profile: string,
): Frame {
  const recipient = getPublicKey(recipientSecret);
  const outer = signedEvent(raw, GIFT_WRAP_KIND);
  const recipients = outer.tags.filter((tag) => tag[0] === "p");
  if (recipients.length !== 1 || recipients[0]!.length !== 2 || recipients[0]![1] !== recipient) refused();
  const sealRaw = nip44.decrypt(outer.content, nip44.getConversationKey(recipientSecret, outer.pubkey));
  const seal = signedEvent(sealRaw, SEAL_KIND);
  if (seal.tags.length !== 0) refused();
  const rumorRaw = nip44.decrypt(seal.content, nip44.getConversationKey(recipientSecret, seal.pubkey));
  if (encoder.encode(rumorRaw).length > MAX_EVENT_BYTES) refused();
  const rumor = JSON.parse(rumorRaw) as Record<string, unknown>;
  if (
    rumor === null ||
    typeof rumor !== "object" ||
    Object.keys(rumor).sort().join() !== RUMOR_MEMBERS.join() ||
    rumor.kind !== RUMOR_KIND ||
    !Number.isSafeInteger(rumor.created_at) ||
    (rumor.created_at as number) < 0 ||
    JSON.stringify(rumor.tags) !== JSON.stringify([["rillswap", "nostr-experimental-1"]]) ||
    typeof rumor.content !== "string" ||
    typeof rumor.pubkey !== "string" ||
    rumor.pubkey !== seal.pubkey
  ) {
    refused();
  }
  const content = rumor.content as string;
  const size = encoder.encode(content).length;
  if (size === 0 || size > MAX_ENVELOPE_BYTES) refused();
  if (getEventHash(rumor as unknown as NostrEvent) !== rumor.id) refused();
  const parsed: unknown = JSON.parse(content);
  if (canonicalize(parsed) !== content) refused();
  const envelope = requireShape<Envelope>("validateEnvelope", parsed);
  if (
    envelope.sender_session_key !== rumor.pubkey ||
    canonicalize(envelope.network_identity) !== canonicalize(network) ||
    envelope.profile_id !== profile
  ) {
    refused();
  }
  return { sealAuthor: seal.pubkey, envelope };
}

/** The relay surface a session needs; see relay.ts for the WebSocket one. */
export interface RelayLink {
  publish(event: NostrEvent): Promise<boolean>;
  subscribe(filter: Record<string, unknown>): Promise<void>;
  /** The next raw event JSON for our subscription, or null at the deadline. */
  next(deadline: number): Promise<string | null>;
}

export class SwapError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SwapError";
  }
}

export const NIP59_BACKDATE_SECONDS = 2 * 24 * 3600;

export class Session {
  readonly secret = schnorr.utils.randomSecretKey();
  readonly key = getPublicKey(this.secret);
  sessionId = bytesToHex(randomBytes(32));
  providerKey: string | null = null;
  private sequence = 0;
  private readonly seen = new Set<string>();
  private readonly inbox: Envelope[] = [];

  constructor(
    readonly relay: RelayLink,
    readonly network: unknown,
    readonly profile: string,
    readonly timeoutMs = 60_000,
    readonly clock: () => number = Date.now,
  ) {}

  envelope(
    messageType: string,
    payload: Record<string, unknown>,
    options: { inReplyTo?: string; contract?: string; signed?: boolean; requiredFeatures?: readonly string[] } = {},
  ): Envelope {
    const unsigned: Envelope = {
      protocol: "rillswap",
      wire_version: "1",
      profile_id: this.profile,
      network_identity: this.network,
      session_id: this.sessionId,
      message_id: bytesToHex(randomBytes(32)),
      sender_session_key: this.key,
      sequence: this.sequence,
      in_reply_to: options.inReplyTo ?? null,
      contract_hash: options.contract ?? null,
      message_type: messageType,
      payload,
      required_features: [...(options.requiredFeatures ?? [])],
      extensions: {},
      signature: null,
    };
    requireShape("validateEnvelope", JSON.parse(canonicalize(unsigned)!));
    this.sequence += 1;
    if (options.signed === false) return unsigned;
    const digest = unsignedEnvelopeHash(unsigned as unknown as Record<string, unknown>);
    return { ...unsigned, signature: bytesToHex(schnorr.sign(digest, this.secret, randomBytes(32))) };
  }

  async send(envelope: Envelope, recipient: string, beforePublish?: () => void): Promise<void> {
    const event = wrapPrivateRegtestEnvelope(new TextDecoder().decode(jcs(envelope)), this.secret, recipient);
    for (let attempt = 0; attempt < 3; attempt += 1) {
      beforePublish?.();
      if (await this.relay.publish(event)) return;
    }
    throw new SwapError(`relay did not accept ${envelope.message_type}`);
  }

  async listen(): Promise<void> {
    const since = Math.floor(this.clock() / 1000) - NIP59_BACKDATE_SECONDS;
    await this.relay.subscribe({ kinds: [GIFT_WRAP_KIND], "#p": [this.key], since });
  }

  /** Admit one raw event as an authenticated envelope for this session, or null. */
  admit(raw: string): Envelope | null {
    let frame: Frame;
    try {
      frame = unwrapGiftWrap(raw, this.secret, this.network, this.profile);
    } catch {
      return null;
    }
    const envelope = frame.envelope;
    if (
      envelope.session_id !== this.sessionId ||
      this.seen.has(envelope.message_id) ||
      frame.sealAuthor !== envelope.sender_session_key ||
      (this.providerKey !== null && envelope.sender_session_key !== this.providerKey)
    ) {
      return null;
    }
    if (envelope.message_type !== "handshake_accept") {
      try {
        const digest = unsignedEnvelopeHash(envelope as unknown as Record<string, unknown>);
        if (!schnorr.verify(hexToBytes(envelope.signature ?? ""), digest, hexToBytes(envelope.sender_session_key))) {
          return null;
        }
      } catch {
        return null;
      }
    }
    this.seen.add(envelope.message_id);
    return envelope;
  }

  async receive(wanted: (envelope: Envelope) => boolean, timeoutMs = this.timeoutMs): Promise<Envelope> {
    const index = this.inbox.findIndex(wanted);
    if (index >= 0) return this.inbox.splice(index, 1)[0]!;
    const deadline = this.clock() + timeoutMs;
    for (;;) {
      const raw = await this.relay.next(deadline);
      if (raw === null) throw new SwapError("timed out waiting for the provider");
      const admitted = this.admit(raw);
      if (admitted === null) continue;
      if (wanted(admitted)) return admitted;
      this.inbox.push(admitted);
    }
  }

  async replyTo(request: Envelope, expected: string, timeoutMs = this.timeoutMs): Promise<Envelope> {
    const answer = await this.receive((item) => item.in_reply_to === request.message_id, timeoutMs);
    if (answer.message_type === "error") {
      throw new SwapError(`provider refused ${request.message_type}: ${String(answer.payload.code)}`);
    }
    if (answer.message_type !== expected) throw new SwapError(`unexpected answer ${answer.message_type}`);
    return answer;
  }
}
