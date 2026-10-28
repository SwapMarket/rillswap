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
  verifyNostrProviderAnnouncement,
} from "../src/nostrProviderAnnouncement";
import application from "./fixtures/manual-advertisement-regtest-v1.json";
import vector from "./fixtures/nostr-announcement-regtest-v1.json";
import type { ProfileId } from "../src/swapPairs";

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

function accept(raw: string, identity = PUBLIC, network: unknown = NETWORK, profile: ProfileId = "btc-to-ln/v1") {
  const clock = spyOn(Date, "now").mockReturnValue(1703021600 * 1000);
  try {
    return verifyNostrProviderAnnouncement(raw, identity, network, profile);
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
  test("accepts the signed epoch requirement without treating it as live admission", () => {
    const wrapper = structuredClone(application);
    (wrapper.advertisement.extensions as Record<string, unknown>)["rillswap/handshake-required-features"] = ["epoch-bound-session/v1"];
    const original = fixtureEvent();
    // Signing only the outer wrapper must not authenticate changed application content.
    expect(() => accept(JSON.stringify(reSign({ ...original, content: jcs(wrapper) }))))
      .toThrow(AnnouncementRefusedError);
    reSignApplication(wrapper);
    const event = reSign({ ...original, content: jcs(wrapper) });
    expect(accept(JSON.stringify(event)).identityXOnlyKey).toBe(PUBLIC);
  });

  test.each([null, true, [], "epoch-bound-session/v1", ["unknown/v1"],
    ["epoch-bound-session/v1", "unknown/v1"], ["epoch-bound-session/v1", "epoch-bound-session/v1"]].map(value => [value]))(
    "refuses a signed malformed or unsupported handshake requirement %j", (value) => {
      const wrapper = structuredClone(application);
      (wrapper.advertisement.extensions as Record<string, unknown>)["rillswap/handshake-required-features"] = value;
      reSignApplication(wrapper);
      expect(() => accept(JSON.stringify(reSign({ ...fixtureEvent(), content: jcs(wrapper) }))))
        .toThrow(AnnouncementRefusedError);
    },
  );

  const asset = {
    family: "evm" as const, chain_id: 31337, name: "anvil-dev", htlc_contract: `0x${"1a".repeat(20)}`, htlc_version: 6 as const,
    token_contract: `0x${"2b".repeat(20)}`, token_symbol: "fUSDC", token_decimals: 6, block_seconds: 2, deployment_namespace: "dev",
  };

  test("admits the signed RS-010 asset list and exposes it to EVM profiles only", () => {
    const wrapper = structuredClone(application);
    wrapper.advertisement.profiles = ["btc-to-ln/v1", "erc20-to-ln/v1"];
    (wrapper.advertisement.extensions as Record<string, unknown>)["rillswap/evm-assets-v1"] = [asset];
    reSignApplication(wrapper);
    const event = reSign({ ...fixtureEvent(), content: jcs(wrapper) });
    expect(accept(JSON.stringify(event)).evmAssets).toEqual([asset]);
    const evm = accept(JSON.stringify(event), PUBLIC, NETWORK, "erc20-to-ln/v1");
    expect(evm.profileId).toBe("erc20-to-ln/v1");
    expect(evm.evmAssets[0]!.token_symbol).toBe("fUSDC");
    expect(accept(JSON.stringify(fixtureEvent())).evmAssets).toEqual([]);
  });

  test.each([
    [[]], [null], [{ ...asset, htlc_version: 5 }], [[{ ...asset, htlc_contract: `0x${"1A".repeat(20)}` }]],
    [[asset, asset]], [[{ ...asset, extra: 1 }]], [Array.from({ length: 17 }, () => asset)],
  ])("refuses a malformed signed asset list %j", (listed) => {
    const wrapper = structuredClone(application);
    (wrapper.advertisement.extensions as Record<string, unknown>)["rillswap/evm-assets-v1"] = listed;
    reSignApplication(wrapper);
    expect(() => accept(JSON.stringify(reSign({ ...fixtureEvent(), content: jcs(wrapper) }))))
      .toThrow(AnnouncementRefusedError);
  });

  test("an EVM profile without any served asset is refused", () => {
    const wrapper = structuredClone(application);
    wrapper.advertisement.profiles = ["ln-to-erc20/v1"];
    reSignApplication(wrapper);
    const event = JSON.stringify(reSign({ ...fixtureEvent(), content: jcs(wrapper) }));
    expect(() => accept(event, PUBLIC, NETWORK, "ln-to-erc20/v1")).toThrow(AnnouncementRefusedError);
  });

  test("unknown signed extensions are ignored while known ones still apply", () => {
    // RS-005: a newer provider's extra keys must not hide its offers.
    const wrapper = structuredClone(application);
    Object.assign(wrapper.advertisement.extensions, {
      "rillswap/handshake-required-features": ["epoch-bound-session/v1"], "test/data": "signed",
    });
    reSignApplication(wrapper);
    const candidate = accept(JSON.stringify(reSign({ ...fixtureEvent(), content: jcs(wrapper) })));
    expect(candidate.requiresEpochBinding).toBe(true);
    expect(candidate.fundingConfirmations).toBeNull();
  });

  test("exposes the announced funding depth and refuses a malformed one", () => {
    const signed = (profiles: string[], value: unknown) => {
      const wrapper = structuredClone(application);
      wrapper.advertisement.profiles = profiles;
      (wrapper.advertisement.extensions as Record<string, unknown>)["rillswap/funding-confirmations"] = value;
      reSignApplication(wrapper);
      return JSON.stringify(reSign({ ...fixtureEvent(), content: jcs(wrapper) }));
    };
    expect(accept(JSON.stringify(fixtureEvent())).fundingConfirmations).toBeNull(); // unknown, not 0 or 1
    expect(accept(signed(["btc-to-ln/v1"], { confirmations: 0 })).fundingConfirmations).toBe(0);
    const both = ["btc-to-ln/v1", "ln-to-btc/v1"];
    expect(accept(signed(both, { confirmations: 3 }), PUBLIC, NETWORK, "ln-to-btc/v1").fundingConfirmations).toBe(3);
    // Zero is only for BTC to LN, where the paying provider alone takes the risk.
    const cases: [string[], unknown][] = [
      [both, { confirmations: 0 }], [["ln-to-btc/v1"], { confirmations: 0 }],
      [["btc-to-ln/v1"], { confirmations: -1 }], [["btc-to-ln/v1"], { confirmations: "1" }],
      [["btc-to-ln/v1"], { confirmations: true }], [["btc-to-ln/v1"], { confirmations: 1, extra: 1 }],
      [["btc-to-ln/v1"], {}], [["btc-to-ln/v1"], 1], [["btc-to-ln/v1"], null], [["btc-to-ln/v1"], [1]],
    ];
    for (const [profiles, value] of cases) {
      const profile: ProfileId = profiles.includes("btc-to-ln/v1") ? "btc-to-ln/v1" : "ln-to-btc/v1";
      expect(() => accept(signed(profiles, value), PUBLIC, NETWORK, profile))
        .toThrow(AnnouncementRefusedError);
    }
  });

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
    // Unknown keys are ignored (RS-005); the signature still covers them.
    expect(accept(JSON.stringify(reSign({ ...original, content: jcs(extensions) }))).source)
      .toBe("signed-nip01-announcement");
  });

  test("expires at now and bounds encoded raw event and decoded content", () => {
    expect(() => verifyNostrProviderAnnouncement(
      JSON.stringify(fixtureEvent()), PUBLIC, NETWORK, "btc-to-ln/v1",
    )).toThrow(AnnouncementRefusedError);
    expect(() => accept(JSON.stringify(fixtureEvent()) + " ".repeat(128 * 1024)))
      .toThrow(AnnouncementRefusedError);
    const content = "x".repeat(64 * 1024 + 1);
    expect(() => accept(JSON.stringify(reSign({ ...fixtureEvent(), content }))))
      .toThrow(AnnouncementRefusedError);
  });
});

describe("public-network announcements", () => {
  function forNetwork(network: Record<string, unknown>, tag: string): string {
    const wrapper = structuredClone(application);
    (wrapper.advertisement as Record<string, unknown>).network_identities = [network];
    reSignApplication(wrapper);
    const address = createHash("sha256").update(jcs([
      "rillswap", "nostr-experimental-1", network, wrapper.advertisement.slot,
    ])).digest("hex");
    const event = fixtureEvent();
    event.content = jcs(wrapper);
    event.tags = [["rillswap", "nostr-experimental-1"], ["network", tag], ["d", address]];
    return JSON.stringify(reSign(event));
  }

  for (const name of ["signet", "testnet4", "mainnet"]) {
    const network = JSON.parse(readFileSync(
      resolve(import.meta.dir, `../src/networks/${name}.json`), "utf8",
    )) as Record<string, unknown>;

    test(`${name} announcements verify with their own coarse tag`, () => {
      const candidate = accept(forNetwork(network, name), PUBLIC, network);
      expect(candidate.source).toBe("signed-nip01-announcement");
    });

    test(`${name} announcements refuse a mismatched tag or selected network`, () => {
      for (const other of ["regtest", "signet", "testnet4", "mainnet", "testnet3"]) {
        if (other === name) continue;
        expect(() => accept(forNetwork(network, other), PUBLIC, network))
          .toThrow(AnnouncementRefusedError);
      }
      expect(() => accept(forNetwork(network, name), PUBLIC, NETWORK))
        .toThrow(AnnouncementRefusedError);
    });
  }
});

describe("RS-006 transport work requirement", () => {
  function withWork(value: unknown, epochBound = false): string {
    const wrapper = structuredClone(application);
    const extensions = wrapper.advertisement.extensions as Record<string, unknown>;
    extensions["rillswap/transport-pow"] = value;
    if (epochBound) extensions["rillswap/handshake-required-features"] = ["epoch-bound-session/v1"];
    reSignApplication(wrapper);
    return JSON.stringify(reSign({ ...fixtureEvent(), content: jcs(wrapper) }));
  }

  test("is exposed when signed, and absent means none", () => {
    expect(accept(JSON.stringify(fixtureEvent())).transportWorkBits).toBe(0);
    expect(accept(withWork({ bits: 16 })).transportWorkBits).toBe(16);
    const both = accept(withWork({ bits: 20 }, true));
    expect([both.transportWorkBits, both.requiresEpochBinding]).toEqual([20, true]);
  });

  test.each([[{ bits: 0 }], [{ bits: 21 }], [{ bits: "16" }], [{ bits: 16, extra: 1 }], [16], [null]])(
    "refuses a malformed or excessive signed requirement %j", (value) => {
      expect(() => accept(withWork(value))).toThrow(AnnouncementRefusedError);
    },
  );
});
