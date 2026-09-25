import { describe, expect, test } from "bun:test";
import canonicalize from "canonicalize";
import { getEventHash, getPublicKey, nip44, nip59, verifyEvent } from "nostr-tools";

import { Nip59FrameConstructionError, wrapPrivateRegtestEnvelope } from "../src/nip59Transport";

// Disposable synthetic scalars only, never production or wallet keys.
const senderSecret = Uint8Array.from({ length: 32 }, (_, i) => i === 31 ? 2 : 0);
const recipientSecret = Uint8Array.from({ length: 32 }, (_, i) => i === 31 ? 3 : 0);
const recipient = getPublicKey(recipientSecret);
const sender = getPublicKey(senderSecret);

function envelope(senderSessionKey = sender): string {
  // This tests the disconnected wrapper, not RS-001 schema admission.
  const text = canonicalize({
    protocol: "rillswap", wire_version: "1", sender_session_key: senderSessionKey,
    note: "private regtest 🍕",
  });
  if (text === undefined) throw new Error("synthetic test envelope failed");
  return text;
}

function inspect(content: string) {
  const outer = wrapPrivateRegtestEnvelope(content, senderSecret, recipient);
  const seal = JSON.parse(nip44.v2.decrypt(
    outer.content,
    nip44.v2.utils.getConversationKey(recipientSecret, outer.pubkey),
  )) as Record<string, unknown>;
  const rumor = JSON.parse(nip44.v2.decrypt(
    seal.content as string,
    nip44.v2.utils.getConversationKey(recipientSecret, seal.pubkey as string),
  )) as Record<string, unknown>;
  return { outer, seal, rumor };
}

describe("disconnected private-regtest NIP-59 producer", () => {
  test("uses two independent signed layers and an unsigned bound rumor", () => {
    const content = envelope();
    const { outer, seal, rumor } = inspect(content);
    expect(verifyEvent(JSON.parse(JSON.stringify(outer)))).toBe(true);
    expect(verifyEvent({ ...JSON.parse(JSON.stringify(outer)), content: `${outer.content}bad` }))
      .toBe(false);
    expect(outer.kind).toBe(1059);
    expect(outer.tags).toEqual([["p", recipient]]);
    expect(outer.pubkey).not.toBe(sender);
    expect(seal.kind).toBe(13);
    expect(seal.tags).toEqual([]);
    expect(verifyEvent(seal as Parameters<typeof verifyEvent>[0])).toBe(true);
    expect(seal.pubkey).toBe(sender);
    expect(Object.keys(rumor).sort()).toEqual(
      ["id", "pubkey", "created_at", "kind", "tags", "content"].sort(),
    );
    expect(rumor.kind).toBe(21417);
    expect(rumor.tags).toEqual([["rillswap", "nostr-experimental-1"]]);
    expect(rumor.pubkey).toBe(sender);
    expect(rumor.content).toBe(content);
    expect(rumor.id).toBe(getEventHash({
      kind: rumor.kind as number,
      tags: rumor.tags as string[][],
      content: rumor.content as string,
      created_at: rumor.created_at as number,
      pubkey: rumor.pubkey as string,
    }));
    const unwrapped = nip59.unwrapEvent(outer, recipientSecret);
    expect(unwrapped.id).toBe(rumor.id as string);
    expect(unwrapped.content).toBe(rumor.content as string);
  });

  test("retries preserve application bytes but not wrapper identity", () => {
    const content = envelope();
    const first = inspect(content);
    const second = inspect(content);
    expect(first.rumor.content).toBe(second.rumor.content);
    expect(first.outer.id).not.toBe(second.outer.id);
    expect(first.outer.pubkey).not.toBe(second.outer.pubkey);
    expect(first.outer.content).not.toBe(second.outer.content);
  });

  test("bounds UTF-8 envelope bytes at 16 KiB, not character count", () => {
    const prefix = canonicalize({
      protocol: "rillswap", wire_version: "1", sender_session_key: sender, note: "",
    });
    if (prefix === undefined) throw new Error("synthetic prefix failed");
    const exact = canonicalize({
      protocol: "rillswap", wire_version: "1", sender_session_key: sender,
      note: "🍕".repeat((16 * 1024 - prefix.length) / 4),
    });
    if (exact === undefined) throw new Error("synthetic boundary failed");
    // The fixed JSON prefix plus 4-byte UTF-8 pizza glyphs fits exactly.
    expect(new TextEncoder().encode(exact).length).toBe(16 * 1024);
    expect(wrapPrivateRegtestEnvelope(exact, senderSecret, recipient).kind).toBe(1059);
    expect(() => wrapPrivateRegtestEnvelope(exact.replace(/"}$/, "🍕\"}"),
      senderSecret, recipient)).toThrow(Nip59FrameConstructionError);
  });

  test.each([
    ["mismatched sender", envelope("aa".repeat(32))],
    ["duplicate member", `{"protocol":"rillswap","protocol":"rillswap","wire_version":"1","sender_session_key":"${sender}"}`],
    ["whitespace", JSON.stringify(JSON.parse(envelope()), null, 2)],
    ["noncanonical field order", `{"wire_version":"1","protocol":"rillswap","sender_session_key":"${sender}"}`],
    ["wrong version", canonicalize({ protocol: "rillswap", wire_version: "2", sender_session_key: sender })],
    ["oversize", canonicalize({ protocol: "rillswap", wire_version: "1", sender_session_key: sender, note: "a".repeat(16 * 1024) })],
    ["invalid JSON", "{"],
  ] as [string, string][])("rejects %s without exposing input", (_label, content) => {
    expect(() => wrapPrivateRegtestEnvelope(content, senderSecret, recipient))
      .toThrow(Nip59FrameConstructionError);
  });

  test.each(["AB".repeat(32), "00", "ff".repeat(32)])(
    "rejects a malformed or unusable recipient key", (key) => {
      expect(() => wrapPrivateRegtestEnvelope(envelope(), senderSecret, key))
        .toThrow(Nip59FrameConstructionError);
    },
  );

  test("rejects unusable sender secrets", () => {
    expect(() => wrapPrivateRegtestEnvelope(envelope(), new Uint8Array(32), recipient))
      .toThrow(Nip59FrameConstructionError);
  });
});
