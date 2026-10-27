import { describe, expect, test } from "bun:test";
import canonicalize from "canonicalize";
import { generateSecretKey, getEventHash, getPublicKey, nip44, verifyEvent, type NostrEvent } from "nostr-tools";

import vector from "../../rill-docs/vectors/wire/nostr-transport-pow-v1.json";
import regtest from "../src/networks/regtest-rillswap-e2e-v1.json";
import { Nip59FrameConstructionError, wrapWithTransportWork } from "../src/nip59Transport";
import type { AnnouncementCandidate } from "../src/nostrProviderAnnouncement";
import { handshake } from "../src/swap/handshake";
import { type RelayLink, Session } from "../src/swap/session";
import {
  committedWork, MAX_WORK_BITS, mineNonceTag, TRANSPORT_POW_EXTENSION, TransportWorkError, transportWorkRequirement,
} from "../src/transportPow";

// Disposable synthetic scalars only, never production or wallet keys.
const senderSecret = Uint8Array.from({ length: 32 }, (_, i) => i === 31 ? 2 : 0);
const recipientSecret = Uint8Array.from({ length: 32 }, (_, i) => i === 31 ? 3 : 0);
const sender = getPublicKey(senderSecret);
const recipient = getPublicKey(recipientSecret);
const TWO_DAYS = 2 * 24 * 60 * 60;

type Tags = string[][];

function proven(event: { id: string; pubkey: string; created_at: number; kind: number; tags: Tags; content: string }): number | null {
  return getEventHash(event) === event.id ? committedWork(event.id, event.tags) : null;
}

function open(outer: NostrEvent, secret: Uint8Array): Record<string, unknown> {
  const seal = JSON.parse(nip44.decrypt(outer.content, nip44.getConversationKey(secret, outer.pubkey))) as NostrEvent;
  const rumor = JSON.parse(nip44.decrypt(seal.content, nip44.getConversationKey(secret, seal.pubkey))) as NostrEvent;
  return JSON.parse(rumor.content) as Record<string, unknown>;
}

describe("RS-006 transport proof of work", () => {
  test("agrees with the shared cross-language vector", () => {
    const required = vector.required_bits;
    expect(transportWorkRequirement(vector.announcement_extensions)).toBe(required);
    expect(transportWorkRequirement(vector.init_extensions)).toBe(required);
    for (const { name, event, proven_work, accepted } of vector.cases) {
      const work = proven(event as Parameters<typeof proven>[0]);
      expect([name, work]).toEqual([name, proven_work]);
      expect([name, work !== null && work >= required]).toEqual([name, accepted]);
    }
  });

  test("reads only an exact, bounded requirement", () => {
    expect(transportWorkRequirement({})).toBe(0);
    expect(transportWorkRequirement({ other: 1 })).toBe(0);
    expect(transportWorkRequirement({ [TRANSPORT_POW_EXTENSION]: { bits: MAX_WORK_BITS } })).toBe(MAX_WORK_BITS);
    for (const value of [{ bits: 0 }, { bits: 21 }, { bits: 1.5 }, { bits: "8" }, { bits: 8, more: 1 }, 8, null, []]) {
      expect(() => transportWorkRequirement({ [TRANSPORT_POW_EXTENSION]: value })).toThrow(TransportWorkError);
    }
  });

  test("WebCrypto and the synchronous fallback mine the same first nonce", async () => {
    // Quotes, escapes and non-ASCII exercise the split around the counter.
    const content = `ciphertext "quoted" \\ 🍕 ${"A".repeat(3000)}`;
    const base = { pubkey: sender, created_at: 1_700_000_000, kind: 1059, content };
    const subtleTags = await mineNonceTag(sender, base.created_at, 1059, [["p", recipient]], content, 10);
    const nobleTags = await mineNonceTag(sender, base.created_at, 1059, [["p", recipient]], content, 10, null);
    expect(nobleTags).toEqual(subtleTags);
    expect(subtleTags[0]).toEqual(["p", recipient]);
    expect(subtleTags[1]![0]).toBe("nonce");
    expect(subtleTags[1]![2]).toBe("10");
    const id = getEventHash({ ...base, tags: subtleTags });
    expect(committedWork(id, subtleTags)).toBe(10);
  });

  test("refuses targets outside 1 to 20 bits", async () => {
    for (const bits of [0, 21, 1.5]) {
      await expect(mineNonceTag(sender, 1, 1059, [["p", recipient]], "c", bits)).rejects.toThrow(TransportWorkError);
    }
  });

  test("a mined wrap keeps its fuzzed time, verifies after mining and still decrypts", async () => {
    const envelope = canonicalize({ protocol: "rillswap", wire_version: "1", sender_session_key: sender, note: "pow" })!;
    const before = Math.floor(Date.now() / 1000);
    const outer = await wrapWithTransportWork(envelope, senderSecret, recipient, 12);
    expect(outer.kind).toBe(1059);
    expect(outer.tags.length).toBe(2);
    expect(outer.tags[0]).toEqual(["p", recipient]);
    expect(outer.tags[1]![2]).toBe("12");
    expect(verifyEvent(JSON.parse(JSON.stringify(outer)))).toBe(true);
    expect(proven(outer)).toBe(12);
    expect(outer.created_at).toBeLessThanOrEqual(before + 1);
    expect(outer.created_at).toBeGreaterThanOrEqual(before - TWO_DAYS - 1);
    expect(open(outer, recipientSecret).note).toBe("pow");
    const plain = await wrapWithTransportWork(envelope, senderSecret, recipient, 0);
    expect(plain.tags).toEqual([["p", recipient]]);
    await expect(wrapWithTransportWork("{}", senderSecret, recipient, 8)).rejects.toThrow(Nip59FrameConstructionError);
  });
});

class MemoryRelay implements RelayLink {
  readonly published: NostrEvent[] = [];
  async publish(event: NostrEvent): Promise<boolean> {
    this.published.push(event);
    return true;
  }
  async subscribe(): Promise<void> {}
  async next(): Promise<string | null> {
    return null;
  }
}

describe("handshake declares the provider's work and mines it", () => {
  test.each([[0, false], [8, false], [8, true]])("work %d, epoch-bound %p", async (bits, epochBound) => {
    const epochSecret = generateSecretKey();
    const epoch = getPublicKey(epochSecret);
    const relay = new MemoryRelay();
    const session = new Session(relay, regtest, "btc-to-ln/v1", 50);
    session.replyTo = async () => { throw new Error("stop after the init"); };
    const provider = {
      advertisedEpochInboxKeys: [epoch], requiresEpochBinding: epochBound, transportWorkBits: bits,
    } as unknown as AnnouncementCandidate;
    await expect(handshake(session, provider, recipient)).rejects.toThrow("stop after the init");
    expect(session.workBits).toBe(bits);
    const [outer] = relay.published;
    expect(outer!.tags.length).toBe(bits ? 2 : 1);
    expect(proven(outer!)).toBe(bits);
    const init = open(outer!, epochSecret).payload as { extensions: Record<string, unknown> };
    expect(init.extensions[TRANSPORT_POW_EXTENSION]).toEqual(bits ? { bits } : undefined);
    expect(Object.hasOwn(init.extensions, "rillswap/epoch-bound-session")).toBe(epochBound);
  });
});
