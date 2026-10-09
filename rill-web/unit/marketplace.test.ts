import { afterEach, beforeEach, expect, spyOn, test } from "bun:test";
import { schnorr } from "@noble/curves/secp256k1.js";
import { sha256 } from "@noble/hashes/sha2.js";
import canonicalize from "canonicalize";
import { finalizeEvent, getPublicKey } from "nostr-tools";
import { eligibleProviders, rankQuotes, scanAnnouncements, type LocatedQuote, type RelayObservation } from "../src/swap/marketplace";
import application from "./fixtures/manual-advertisement-regtest-v1.json";
import vector from "./fixtures/nostr-announcement-regtest-v1.json";
import network from "../src/networks/regtest-rillswap-e2e-v1.json";

let clock: ReturnType<typeof spyOn>;
beforeEach(() => { clock = spyOn(Date, "now").mockReturnValue(1703021600 * 1000); });
afterEach(() => clock.mockRestore());

function announcement(revision = 1, fee = "10", secretNumber = 2): string {
  const secret = new Uint8Array(32); secret[31] = secretNumber;
  const wrapper = structuredClone(application);
  wrapper.advertisement.provider_identity_xonly_key = getPublicKey(secret);
  wrapper.advertisement.revision = revision;
  wrapper.advertisement.indicative_fee_policy.base_sat = fee;
  wrapper.advertisement.amount_bands = [{ minimum_sat: "100", maximum_sat: "10000" }];
  const tag = sha256(new TextEncoder().encode("RillSwap/advertisement/v1"));
  const content = new TextEncoder().encode(canonicalize(wrapper.advertisement)!);
  const digest = new Uint8Array(64 + content.length);
  digest.set(tag); digest.set(tag, 32); digest.set(content, 64);
  wrapper.signature = Buffer.from(schnorr.sign(sha256(digest), secret)).toString("hex");
  return JSON.stringify(finalizeEvent({ kind: vector.kind, created_at: vector.created_at,
    tags: structuredClone(vector.tags), content: canonicalize(wrapper)! }, secret));
}

const observed = (events: string[], url = "wss://a.test/"): RelayObservation => ({
  url, result: { events, truncated: false, completion: "eose" },
});

test("same announcement on multiple relays preserves provenance without duplicate providers", () => {
  const raw = announcement();
  const directory = scanAnnouncements([observed([raw]), observed([raw], "wss://b.test/")], network);
  expect(directory.providers).toHaveLength(1);
  expect(directory.providers[0]!.relayUrls).toEqual(["wss://a.test/", "wss://b.test/"]);
  expect(directory.warnings).toEqual([]);
});

test("a lower-revision conflict cannot be hidden behind a newer announcement", () => {
  expect(() => scanAnnouncements([observed([announcement(3), announcement(1, "10"), announcement(1, "11")])], network))
    .toThrow("conflicting data");
});

test("provider identities are discovered automatically but a manual pin is never broadened", () => {
  const events = [announcement(1, "10", 2), announcement(1, "20", 3)];
  expect(scanAnnouncements([observed(events)], network).providers).toHaveLength(2);
  const identity = JSON.parse(events[0]!).pubkey;
  expect(scanAnnouncements([observed(events)], network, identity).providers.map((p) => p.announcement.identityXOnlyKey)).toEqual([identity]);
});

test("full network mismatch is refused even when events have plausible tags", () => {
  expect(scanAnnouncements([observed([announcement()])], { ...network, deployment_namespace: "other" }).providers).toEqual([]);
});

test("partial responses are disclosed but overflow never selects a prefix", () => {
  const partial = observed([announcement()]);
  const directory = scanAnnouncements([{ ...partial, result: { ...partial.result, completion: "timeout" } }], network);
  expect(directory.providers).toHaveLength(1);
  expect(directory.warnings[0]).toContain("incomplete discovery (timeout)");
  expect(() => scanAnnouncements([{ ...partial, result: { ...partial.result, truncated: true } }], network)).toThrow("event limit");
  expect(() => scanAnnouncements([observed(Array.from({ length: 257 }, (_, i) => `invalid-${i}`))], network)).toThrow("event limit");
});

test("highest revision replaces older transport provenance and amount bands filter offers", () => {
  const directory = scanAnnouncements([observed([announcement(1)]), observed([announcement(2)], "wss://new.test/")], network);
  expect(directory.providers[0]!.announcement.revision).toBe(2);
  expect(directory.providers[0]!.relayUrls).toEqual(["wss://new.test/"]);
  expect(eligibleProviders(directory.providers, 99n)).toHaveLength(0);
  expect(eligibleProviders(directory.providers, 100n)).toHaveLength(1);
  expect(eligibleProviders(directory.providers, 10001n)).toHaveLength(0);
});

test("verified contract prices, not indicative prices, choose the winner with deterministic ties", () => {
  const quote = (amount: bigint, identity: string): LocatedQuote => ({
    relayUrl: "wss://a.test/", dispose: () => {}, prepared: {
      quote: { contractAmountSat: amount, successFeeSat: amount - 1000n, providerIdentity: identity,
        providerSlot: "primary", contractHash: "0".repeat(64), refundLockHeight: 100, expiresAt: 9999 },
      dispose: () => {}, execute: async () => { throw new Error("not used"); },
    },
  });
  const expensive = quote(1200n, "a"), cheap = quote(1010n, "b"), tied = quote(1010n, "a");
  expect(rankQuotes([expensive, cheap, tied])).toEqual([tied, cheap, expensive]);
});
