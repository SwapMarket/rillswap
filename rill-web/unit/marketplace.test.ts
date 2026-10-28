import { afterEach, beforeEach, expect, spyOn, test } from "bun:test";
import { schnorr } from "@noble/curves/secp256k1.js";
import { sha256 } from "@noble/hashes/sha2.js";
import canonicalize from "canonicalize";
import { finalizeEvent, getPublicKey } from "nostr-tools";
import { MAX_DISCOVERY_EVENTS } from "../src/swap/discovery";
import { directoryFromObservations, eligibleProviders, estimateFromDirectory, indicativeFee, ineligibilityReason, MAX_IDENTITY_EVENTS, providerLimits, rankQuotes, scanAnnouncements, type LocatedQuote, type RelayObservation } from "../src/swap/marketplace";
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

test("a lower-revision conflict cannot be hidden behind a newer announcement, and excludes only that provider", () => {
  const conflicting = [announcement(3), announcement(1, "10"), announcement(1, "11")];
  const identity = JSON.parse(conflicting[0]!).pubkey as string;
  const other = announcement(1, "20", 3);
  const directory = scanAnnouncements([observed([...conflicting, other])], network);
  expect(directory.providers.map((provider) => provider.rawAnnouncement)).toEqual([other]);
  expect(directory.warnings).toEqual([`${identity.slice(0, 12)}…: conflicting announcements, provider excluded`]);
  // A pinned provider was the user's choice, so its equivocation stops discovery.
  expect(() => scanAnnouncements([observed(conflicting)], network, identity)).toThrow("conflicting data");
});

test("provider identities are discovered automatically but a manual pin is never broadened", () => {
  const events = [announcement(1, "10", 2), announcement(1, "20", 3)];
  expect(scanAnnouncements([observed(events)], network).providers).toHaveLength(2);
  const identity = JSON.parse(events[0]!).pubkey;
  expect(scanAnnouncements([observed(events)], network, identity).providers.map((p) => p.announcement.identityXOnlyKey)).toEqual([identity]);
});

test("an unreachable onion relay is not reported, but one that answers still routes the provider", () => {
  const onion = "ws://gnostr2jnapk72mnagq3cuykfon73temzp77hcbncn4silgt77boruid.onion/";
  const failed = (url: string): RelayObservation => ({ url, result: { events: [], truncated: false, completion: "error" } });
  const quiet = scanAnnouncements([observed([announcement()]), failed(onion)], network);
  expect(quiet.providers).toHaveLength(1);
  expect(quiet.warnings).toEqual([]);
  expect(scanAnnouncements([failed("wss://b.test/")], network).warnings).toEqual(["wss://b.test/: incomplete discovery (error)"]);
  const raw = announcement();
  expect(scanAnnouncements([observed([raw]), observed([raw], onion)], network).providers[0]!.relayUrls).toEqual(["wss://a.test/", onion]);
});

test("full network mismatch is refused even when events have plausible tags", () => {
  expect(scanAnnouncements([observed([announcement()])], { ...network, deployment_namespace: "other" }).providers).toEqual([]);
});

test("partial and truncated responses are disclosed, and floods degrade discovery instead of aborting it", () => {
  const valid = announcement();
  const partial = observed([valid]);
  const directory = scanAnnouncements([{ ...partial, result: { ...partial.result, completion: "timeout" } }], network);
  expect(directory.providers).toHaveLength(1);
  expect(directory.warnings[0]).toContain("incomplete discovery (timeout)");
  const truncated = scanAnnouncements([{ ...partial, result: { ...partial.result, truncated: true, completion: "limit" } }], network);
  expect(truncated.providers).toHaveLength(1);
  expect(truncated.warnings).toEqual([`wss://a.test/: more than ${MAX_DISCOVERY_EVENTS} events, discovery incomplete`]);
  // Invalid events never count against valid ones, on one relay or across relays.
  const junk = (prefix: string) => Array.from({ length: MAX_DISCOVERY_EVENTS }, (_, i) => `${prefix}-${i}`);
  const flooded = scanAnnouncements([observed([...junk("a"), valid]), observed(junk("b"), "wss://b.test/")], network);
  expect(flooded.providers.map((provider) => provider.rawAnnouncement)).toEqual([valid]);
  expect(flooded.warnings).toEqual([]);
});

test("an identity's verification budget is per relay, so one relay's forgeries cannot hide it elsewhere", () => {
  const revisions = Array.from({ length: MAX_IDENTITY_EVENTS + 1 }, (_, i) => announcement(i + 1));
  const identity = JSON.parse(revisions[0]!).pubkey as string;
  const capped = scanAnnouncements([observed(revisions)], network);
  expect(capped.providers[0]!.announcement.revision).toBe(MAX_IDENTITY_EVENTS);
  expect(capped.warnings).toEqual([`${identity.slice(0, 12)}…: more than ${MAX_IDENTITY_EVENTS} announcements, some ignored`]);
  const genuine = announcement(1);
  const forged = Array.from({ length: MAX_IDENTITY_EVENTS }, (_, i) => JSON.stringify({ ...JSON.parse(genuine), created_at: i }));
  const directory = scanAnnouncements([observed([...forged, genuine], "wss://evil.test/"), observed([genuine], "wss://b.test/")], network);
  expect(directory.providers.map((provider) => provider.rawAnnouncement)).toEqual([genuine]);
  expect(directory.providers[0]!.relayUrls).toEqual(["wss://b.test/"]);
});

test("highest revision replaces older transport provenance and amount bands filter offers", () => {
  const directory = scanAnnouncements([observed([announcement(1)]), observed([announcement(2)], "wss://new.test/")], network);
  expect(directory.providers[0]!.announcement.revision).toBe(2);
  expect(directory.providers[0]!.relayUrls).toEqual(["wss://new.test/"]);
  expect(eligibleProviders(directory.providers, 99n)).toHaveLength(0);
  expect(eligibleProviders(directory.providers, 100n)).toHaveLength(1);
  expect(eligibleProviders(directory.providers, 10001n)).toHaveLength(0);
  const identity = directory.providers[0]!.announcement.identityXOnlyKey.slice(0, 12);
  expect(ineligibilityReason(providerLimits(directory.providers), 10001n)).toBe(`No provider accepts 10,001 sat. Announced limits: 100 to 10,000 sat (${identity}…).`);
  expect(ineligibilityReason([], 10001n)).toContain("No provider announced this swap direction");
});

test("the directory lists each announced slot once with every profile it serves and its announced terms", () => {
  const raw = announcement(3, "25");
  const directory = directoryFromObservations([observed([raw]), observed([raw], "wss://b.test/")], network);
  expect(directory.entries).toHaveLength(1);
  const entry = directory.entries[0]!;
  expect(entry.profiles).toEqual(["btc-to-ln/v1", "ln-to-btc/v1"]);
  expect(entry.relayUrls).toEqual(["wss://a.test/", "wss://b.test/"]);
  expect(entry.amountBands).toEqual([{ minimum_sat: "100", maximum_sat: "10000" }]);
  expect(entry.indicativeFeePolicy.base_sat).toBe("25");
  expect(indicativeFee(entry.indicativeFeePolicy, 10_000n)).toBe(25n + BigInt(Math.ceil(10_000 * application.advertisement.indicative_fee_policy.proportional_millionths / 1_000_000)));
  expect(directory.warnings).toEqual([]);
  expect(directoryFromObservations([observed(["not json"])], network).entries).toEqual([]);
});

test("the directory estimate picks the lowest announced fee for the direction, honors a pinned identity, and explains misses", () => {
  const cheap = directoryFromObservations([observed([announcement(1, "10", 2)])], network).entries[0]!;
  const dear = directoryFromObservations([observed([announcement(1, "40", 3)])], network).entries[0]!;
  const reverseOnly = { ...cheap, identity: "ab".repeat(32), profiles: ["ln-to-btc/v1" as const] };
  const entries = [dear, cheap, reverseOnly];
  expect(estimateFromDirectory(entries, "btc-to-ln/v1", 1000n)).toEqual({ identity: cheap.identity, feeSat: 10n + 1n });
  expect(estimateFromDirectory(entries, "btc-to-ln/v1", 1000n, dear.identity)).toEqual({ identity: dear.identity, feeSat: 40n + 1n });
  expect(estimateFromDirectory(entries, "ln-to-btc/v1", 1000n)).toEqual({ identity: reverseOnly.identity, feeSat: 11n }); // equal fees tie on identity
  expect(estimateFromDirectory(entries, "btc-to-ln/v1", 20_000n)).toEqual({ reason: expect.stringContaining("No provider accepts 20,000 sat") });
  expect(estimateFromDirectory(entries, "btc-to-ln/v1", 1000n, reverseOnly.identity)).toEqual({ reason: "The chosen provider does not announce this swap direction." });
  expect(estimateFromDirectory([], "btc-to-ln/v1", 1000n)).toEqual({ reason: expect.stringContaining("No provider announced") });
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
