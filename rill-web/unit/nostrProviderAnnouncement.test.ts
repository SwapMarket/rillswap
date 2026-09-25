import { afterEach, describe, expect, spyOn, test } from "bun:test";
import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";

import { schnorr } from "@noble/curves/secp256k1.js";
import { sha256 } from "@noble/hashes/sha2.js";
import canonicalize from "canonicalize";
import { finalizeEvent, getPublicKey } from "nostr-tools";

import {
  AnnouncementRefusedError,
  verifyPrivateRegtestAnnouncement,
} from "../src/nostrProviderAnnouncement";
import application from "./fixtures/manual-advertisement-regtest-v1.json";
import vector from "./fixtures/nostr-announcement-regtest-v1.json";

const SECRET = Uint8Array.from({ length: 32 }, (_, i) => i === 31 ? 2 : 0);
const PUBLIC = "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
const NETWORK = {
  family: "bitcoin", name: "regtest",
  genesis_hash: "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206",
  signet_challenge: null, consensus_profile: "bitcoin-core-v30.0-regtest-default",
  deployment_namespace: "rillswap-e2e-v1",
};
const originalNow = Date.now;
afterEach(() => { Date.now = originalNow; });

function jcs(value: unknown): string {
  const text = canonicalize(value);
  if (text === undefined) throw new Error("synthetic data invalid");
  return text;
}

function fixtureEvent(): {
  id: string; pubkey: string; created_at: number; kind: number;
  tags: string[][]; content: string; sig: string;
} {
  return {
    id: vector.id, pubkey: vector.pubkey, created_at: vector.created_at,
    kind: vector.kind, tags: structuredClone(vector.tags),
    content: jcs(application), sig: vector.sig,
  };
}

function accept(raw: string, identity = PUBLIC, network: unknown = NETWORK) {
  const clock = spyOn(Date, "now").mockReturnValue(1703021600 * 1000);
  try {
    return verifyPrivateRegtestAnnouncement(raw, identity, network, "btc-to-ln/v1");
  } finally {
    clock.mockRestore();
  }
}

function reSign(event: ReturnType<typeof fixtureEvent>) {
  return finalizeEvent({
    created_at: event.created_at, kind: event.kind,
    tags: event.tags, content: event.content,
  }, SECRET);
}

function reSignApplication(wrapper: typeof application): void {
  const tag = sha256(new TextEncoder().encode("RillSwap/advertisement/v1"));
  const canonicalBytes = new TextEncoder().encode(jcs(wrapper.advertisement));
  const input = new Uint8Array(64 + canonicalBytes.length);
  input.set(tag);
  input.set(tag, 32);
  input.set(canonicalBytes, 64);
  wrapper.signature = Buffer.from(schnorr.sign(sha256(input), SECRET, new Uint8Array(32)))
    .toString("hex");
}

test("vendored published test vector matches committed discovery fixture hash", () => {
  const data = readFileSync(resolve(import.meta.dir, "fixtures/nostr-announcement-regtest-v1.json"));
  expect(createHash("sha256").update(data).digest("hex"))
    .toBe("c820cd2058a9f0091515a8d6b2af018b57aab93c203613bd536f34a7956e8670");
  const sibling = resolve(import.meta.dir, "../../rill-docs/vectors/discovery/nostr-announcement-regtest-v1.json");
  if (existsSync(sibling)) expect(readFileSync(sibling).equals(data)).toBe(true);
});

describe("private-regtest NIP-01 signed announcement", () => {
  test("published reference signatures, JCS content and address verify independently", () => {
    const event = fixtureEvent();
    expect(getPublicKey(SECRET)).toBe(PUBLIC);
    expect(createHash("sha256").update(event.content).digest("hex"))
      .toBe(vector.content_sha256);
    expect(new TextEncoder().encode(event.content).length).toBe(vector.content_utf8_length);
    const candidate = accept(JSON.stringify(event, null, 1));
    expect(candidate.source).toBe("signed-nip01-announcement");
    expect(candidate.outerEventId).toBe(vector.id);
    expect(candidate.addressD).toBe(vector.tags[2]![1]!);
    expect(candidate.identityXOnlyKey).toBe(PUBLIC);
    expect(candidate.networkIdentityJcs).toBe(jcs(NETWORK));
    expect(candidate.profileId).toBe("btc-to-ln/v1");
  });

  test("noncanonical event member order and escaped outer strings remain interoperable", () => {
    const event = fixtureEvent();
    const reordered = {
      sig: event.sig, kind: event.kind, tags: event.tags, content: event.content,
      pubkey: event.pubkey, id: event.id, created_at: event.created_at,
    };
    const escaped = JSON.stringify(reordered).replace("regtest", "\\u0072egtest");
    expect(accept(`  ${escaped}\n`).outerEventId).toBe(event.id);
  });

  test.each([
    ["wrong binding", (item: ReturnType<typeof fixtureEvent>) => { item.tags[0] = ["rillswap", "old"]; }],
    ["wrong coarse network", (item: ReturnType<typeof fixtureEvent>) => { item.tags[1] = ["network", "mainnet"]; }],
    ["wrong address", (item: ReturnType<typeof fixtureEvent>) => { item.tags[2] = ["d", "ab".repeat(32)]; }],
    ["extra tag", (item: ReturnType<typeof fixtureEvent>) => { item.tags.push(["x", "extra"]); }],
    ["extra tag member", (item: ReturnType<typeof fixtureEvent>) => { item.tags[0]!.push("extra"); }],
    ["wrong kind", (item: ReturnType<typeof fixtureEvent>) => { item.kind = 39418; }],
    ["mismatched outer timestamp", (item: ReturnType<typeof fixtureEvent>) => { item.created_at += 1; }],
  ] as [string, (item: ReturnType<typeof fixtureEvent>) => void][])(
    "rejects fully re-signed %s", (_name, mutate) => {
      const event = fixtureEvent();
      mutate(event);
      expect(() => accept(JSON.stringify(reSign(event)))).toThrow(AnnouncementRefusedError);
    },
  );

  test("rejects substituted identity, full-network mismatch and bad outer/application signatures", () => {
    const original = fixtureEvent();
    expect(() => accept(JSON.stringify(original), "aa".repeat(32)))
      .toThrow(AnnouncementRefusedError);
    expect(() => accept(JSON.stringify(original), PUBLIC, {
      ...NETWORK, deployment_namespace: "other-regtest",
    })).toThrow(AnnouncementRefusedError);
    expect(() => accept(JSON.stringify({ ...original, sig: "00".repeat(64) })))
      .toThrow(AnnouncementRefusedError);
    const tampered = structuredClone(application);
    tampered.advertisement.epoch_inbox_xonly_keys = ["ff".repeat(32)];
    const event = reSign({ ...original, content: jcs(tampered) });
    expect(() => accept(JSON.stringify(event))).toThrow(AnnouncementRefusedError);
  });

  test("rejects escaped duplicate members, extra fields, multiscope ads and noncanonical content", () => {
    const original = fixtureEvent();
    const withDup = JSON.stringify(original).replace('"kind":39417', '"kind":39417,"\\u006bind":39417');
    expect(() => accept(withDup)).toThrow(AnnouncementRefusedError);
    expect(() => accept(JSON.stringify({ ...original, unexpected: "extra" })))
      .toThrow(AnnouncementRefusedError);
    expect(() => accept(JSON.stringify(reSign({ ...original, content: JSON.stringify(application) }))))
      .toThrow(AnnouncementRefusedError);
    const multiple = structuredClone(application);
    multiple.advertisement.network_identities.push(structuredClone(NETWORK));
    reSignApplication(multiple);
    expect(() => accept(JSON.stringify(reSign({ ...original, content: jcs(multiple) }))))
      .toThrow(AnnouncementRefusedError);
    const extensions = structuredClone(application);
    (extensions.advertisement.extensions as Record<string, unknown>)["test/data"] = "signed";
    reSignApplication(extensions);
    expect(() => accept(JSON.stringify(reSign({ ...original, content: jcs(extensions) }))))
      .toThrow(AnnouncementRefusedError);
  });

  test("expires at now and bounds encoded raw event and decoded content", () => {
    expect(() => verifyPrivateRegtestAnnouncement(
      JSON.stringify(fixtureEvent()), PUBLIC, NETWORK, "btc-to-ln/v1",
    )).toThrow(AnnouncementRefusedError);
    expect(() => accept(JSON.stringify(fixtureEvent()) + " ".repeat(128 * 1024)))
      .toThrow(AnnouncementRefusedError);
    const content = "x".repeat(64 * 1024 + 1);
    expect(() => accept(JSON.stringify(reSign({ ...fixtureEvent(), content }))))
      .toThrow(AnnouncementRefusedError);
  });
});
