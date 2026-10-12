import { afterEach, describe, expect, spyOn, test } from "bun:test";
import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { schnorr } from "@noble/curves/secp256k1.js";
import { sha256 } from "@noble/hashes/sha2.js";
import canonicalize from "canonicalize";

import {
  ManualAdvertisementRefusedError,
  verifyManualProviderAdvertisement,
} from "../src/manualProviderAdvertisement";
import fixture from "./fixtures/manual-advertisement-regtest-v1.json";

// Independent test trust anchors, not taken from the advertisement being checked.
const APPROVED_IDENTITY = "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
const REGTEST_NETWORK = {
  family: "bitcoin", name: "regtest",
  genesis_hash: "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206",
  signet_challenge: null, consensus_profile: "bitcoin-core-v30.0-regtest-default",
  deployment_namespace: "rillswap-e2e-v1",
};
const encoder = new TextEncoder();
const NOW = 1703021600;
const APPROVED_TEST_SCALAR = Uint8Array.from({ length: 32 }, (_, i) => i === 31 ? 2 : 0);
const OTHER_MAILBOX = Buffer.from(schnorr.getPublicKey(
  Uint8Array.from({ length: 32 }, (_, i) => i === 31 ? 5 : 0),
)).toString("hex");

test("vendored discovery schema and signed fixture match reviewed docs hashes", () => {
  const sources = [
    ["schemas/wire/common-v1.schema.json", "src/schemas/wire/common-v1.schema.json",
      "0780c9d5a615b3b547793e9a11972da1b1b27a8e88d7f2d5608a20f357d35599"],
    ["schemas/advertisements/advertisement-v1.schema.json",
      "src/schemas/advertisements/advertisement-v1.schema.json",
      "ce0a4724dccf5ac961eb7008f58e970bf750b0c49c3f7733edf205843beb785b"],
    ["vectors/discovery/manual-advertisement-regtest-v1.json",
      "unit/fixtures/manual-advertisement-regtest-v1.json",
      "9a76830053da440eeb86280f7f633d5697226e3f4f47c8e08255d6535e8a9e10"],
    ["networks/mainnet.json", "src/networks/mainnet.json",
      "189ab9e2e8019c52320e602711f55e818ac92d72690a0bb2b0fcf985c5ae794b"],
    ["networks/signet.json", "src/networks/signet.json",
      "c9b93e9504a834fe1815b728c8a01bab4001abe22602ce12db8b0b1c07dfd751"],
    ["networks/testnet3.json", "src/networks/testnet3.json",
      "6c131991f6d0d4b99ea83660dfeec9ab65a0ae2a3ce6ba482685d332cf03ed47"],
    ["networks/testnet4.json", "src/networks/testnet4.json",
      "9726708f8e7eef112c307a729d5c68c60f15a4f976fb522f4d880cae33bbaf16"],
    ["networks/regtest-rillswap-e2e-v1.json", "src/networks/regtest-rillswap-e2e-v1.json",
      "1459c6aba0e5388d1fe2237ed735b1011f4ecace9bcd022566cb2d2f9caa1c7d"],
  ];
  for (const [docsRelative, webRelative, hash] of sources) {
    if (!docsRelative || !webRelative || !hash) throw new Error("test source missing");
    const vendored = readFileSync(resolve(import.meta.dir, "..", webRelative));
    expect(createHash("sha256").update(vendored).digest("hex")).toBe(hash);
    const siblingDocs = resolve(import.meta.dir, "../../rill-docs", docsRelative);
    if (existsSync(siblingDocs)) expect(readFileSync(siblingDocs).equals(vendored)).toBe(true);
  }
});

afterEach(() => {
  // No browser persistence or global clock behavior leaks between tests.
  Date.now = originalNow;
});
const originalNow = Date.now;

function canonical(value: unknown): string {
  const result = canonicalize(value);
  if (result === undefined) throw new Error("invalid synthetic test input");
  return result;
}

function importAtFixtureTime(
  text: string, identity = APPROVED_IDENTITY,
  network: unknown = REGTEST_NETWORK,
  profile: "btc-to-ln/v1" | "ln-to-btc/v1" = "btc-to-ln/v1",
) {
  const clock = spyOn(Date, "now").mockReturnValue(NOW * 1000);
  try {
    return verifyManualProviderAdvertisement(text, identity, network, profile);
  } finally {
    clock.mockRestore();
  }
}

function copyFixture(): typeof fixture {
  return structuredClone(fixture);
}

function resignTestOnly(ad: typeof fixture.advertisement, secret: Uint8Array): string {
  const tag = sha256(encoder.encode("RillSwap/advertisement/v1"));
  const bytes = encoder.encode(canonical(ad));
  const input = new Uint8Array(64 + bytes.length);
  input.set(tag);
  input.set(tag, 32);
  input.set(bytes, 64);
  return Buffer.from(schnorr.sign(sha256(input), secret, new Uint8Array(32))).toString("hex");
}

describe("manual application-signed provider import", () => {
  test("validates historical fixture's independent signature and selected complete network", () => {
    const text = canonical(fixture);
    const selected = importAtFixtureTime(text);
    expect(selected.source).toBe("manual-app-signature-only");
    expect(selected.identityXOnlyKey).toBe(APPROVED_IDENTITY);
    expect(selected.networkIdentityJcs).toBe(canonical(REGTEST_NETWORK));
    expect(selected.profileId).toBe("btc-to-ln/v1");
    expect(selected.revision).toBe(1);
    expect(selected.advertisedEndpoints).toEqual(["wss://relay.example.invalid/"]);
    expect(selected.advertisedEpochInboxKeys).toEqual([
      "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
    ]);
    expect(Object.isFrozen(selected)).toBe(true);
    expect(Object.isFrozen(selected.advertisedEndpoints)).toBe(true);
    expect(importAtFixtureTime(text, APPROVED_IDENTITY, REGTEST_NETWORK, "ln-to-btc/v1").profileId)
      .toBe("ln-to-btc/v1");
  });

  test("a second signer is independently accepted only under their own approved pin", () => {
    const second = copyFixture();
    const scalar = Uint8Array.from({ length: 32 }, (_, i) => i === 31 ? 4 : 0);
    const other = Buffer.from(schnorr.getPublicKey(scalar)).toString("hex");
    second.advertisement.provider_identity_xonly_key = other;
    second.advertisement.slot = "another-provider";
    second.signature = resignTestOnly(second.advertisement, scalar);
    expect(importAtFixtureTime(canonical(second), other).identityXOnlyKey).toBe(other);
    expect(() => importAtFixtureTime(canonical(second), APPROVED_IDENTITY))
      .toThrow(ManualAdvertisementRefusedError);
  });

  test.each([
    ["signature", (ad: typeof fixture) => { ad.signature = "00".repeat(64); }],
    ["identity", (ad: typeof fixture) => { ad.advertisement.provider_identity_xonly_key = "aa".repeat(32); }],
    ["mailbox", (ad: typeof fixture) => { ad.advertisement.epoch_inbox_xonly_keys = [OTHER_MAILBOX]; }],
    ["unusable signed mailbox", (ad: typeof fixture) => {
      ad.advertisement.epoch_inbox_xonly_keys = ["ff".repeat(32)];
    }],
    ["suite", (ad: typeof fixture) => { ad.advertisement.communication_suites = ["unsupported/v1"]; }],
    ["profiles", (ad: typeof fixture) => { ad.advertisement.profiles = ["ln-to-btc/v1"]; }],
    ["network", (ad: typeof fixture) => { ad.advertisement.network_identities[0]!.genesis_hash = "aa".repeat(32); }],
    ["reversed band", (ad: typeof fixture) => { ad.advertisement.amount_bands[0]!.minimum_sat = "100001"; }],
    ["zero-only band", (ad: typeof fixture) => {
      ad.advertisement.amount_bands[0]!.minimum_sat = "0";
      ad.advertisement.amount_bands[0]!.maximum_sat = "0";
    }],
    ["amount above max supply", (ad: typeof fixture) => {
      ad.advertisement.amount_bands[0]!.maximum_sat = "2100000000000001";
    }],
    ["fee above max supply", (ad: typeof fixture) => {
      ad.advertisement.indicative_fee_policy.base_sat = "2100000000000001";
    }],
    ["fractional extension", (ad: typeof fixture) => {
      (ad.advertisement.extensions as Record<string, unknown>)["test/data"] = { amount: 0.5 };
    }],
    ["unsafe extension integer", (ad: typeof fixture) => {
      (ad.advertisement.extensions as Record<string, unknown>)["test/data"] = {
        counter: 9007199254740992,
      };
    }],
    ["extra field", (ad: typeof fixture) => { (ad.advertisement as unknown as Record<string, unknown>).unexpected = "a"; }],
    ["expiry", (ad: typeof fixture) => { ad.advertisement.expires_at = NOW - 1; }],
    ["future", (ad: typeof fixture) => { ad.advertisement.created_at = NOW + 301; }],
  ] as [string, (ad: typeof fixture) => void][])("rejects %s even when JSON is canonical", (_label, mutate) => {
    const input = copyFixture();
    mutate(input);
    if (_label !== "signature" && _label !== "mailbox") {
      input.signature = resignTestOnly(input.advertisement, APPROVED_TEST_SCALAR);
    }
    expect(() => importAtFixtureTime(canonical(input)))
      .toThrow(ManualAdvertisementRefusedError);
  });

  test("accepts valid signed integer, zero-fee and total-supply boundaries", () => {
    const input = copyFixture();
    input.advertisement.amount_bands[0]!.minimum_sat = "1";
    input.advertisement.amount_bands[0]!.maximum_sat = "2100000000000000";
    input.advertisement.indicative_fee_policy.base_sat = "0";
    (input.advertisement.extensions as Record<string, unknown>)["test/data"] = {
      counter: Number.MAX_SAFE_INTEGER,
    };
    input.signature = resignTestOnly(input.advertisement, APPROVED_TEST_SCALAR);
    expect(importAtFixtureTime(canonical(input)).revision).toBe(1);
  });

  test("a properly signed mailbox rotation remains an inert advertised proposal", () => {
    const input = copyFixture();
    input.advertisement.epoch_inbox_xonly_keys = [OTHER_MAILBOX];
    input.signature = resignTestOnly(input.advertisement, APPROVED_TEST_SCALAR);
    const candidate = importAtFixtureTime(canonical(input));
    expect(candidate.advertisedEpochInboxKeys).toEqual([OTHER_MAILBOX]);
    expect(candidate.source).toBe("manual-app-signature-only");
  });

  test("rejects mismatched independent selection and malformed canonical input", () => {
    const text = canonical(fixture);
    const differentNetwork = { ...REGTEST_NETWORK, deployment_namespace: "other-regtest" };
    expect(() => importAtFixtureTime(text, APPROVED_IDENTITY, differentNetwork))
      .toThrow(ManualAdvertisementRefusedError);
    expect(() => importAtFixtureTime(text, "aa".repeat(32)))
      .toThrow(ManualAdvertisementRefusedError);
    expect(() => importAtFixtureTime(JSON.stringify(fixture)))
      .toThrow(ManualAdvertisementRefusedError);
    expect(() => importAtFixtureTime(`{"advertisement":{},"advertisement":{},"signature":""}`))
      .toThrow(ManualAdvertisementRefusedError);
    expect(() => importAtFixtureTime(text + " "))
      .toThrow(ManualAdvertisementRefusedError);
    expect(() => importAtFixtureTime(text + " ".repeat(64 * 1024)))
      .toThrow(ManualAdvertisementRefusedError);
  });

  test("historical signature is expired now and never silently refreshed", () => {
    expect(() => verifyManualProviderAdvertisement(
      canonical(fixture), APPROVED_IDENTITY, REGTEST_NETWORK, "btc-to-ln/v1",
    )).toThrow(ManualAdvertisementRefusedError);
  });
});
