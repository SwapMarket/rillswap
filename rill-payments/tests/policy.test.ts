import { describe, expect, test } from "bun:test";
import fixture from "../../rill-docs/fixtures/checkout/native-lightning.json";
import { evaluateNative, parseTerms, type NativePolicy } from "../src/index";

const policy: NativePolicy = { version: "native-lightning/1", merchantOrigin: fixture.merchantOrigin, receiver: fixture.receiver, network: "regtest", maxBuyerExtraMsat: "100000", maxBuyerExtraBps: 1000 };

describe("native Lightning contract and pure policy", () => {
  test("valid terms are frozen copies and eligibility carries no acceptance", () => {
    const original = structuredClone(fixture);
    expect(parseTerms(original)).not.toBe(original);
    expect(Object.isFrozen(parseTerms(original))).toBe(true);
    expect(evaluateNative(original, policy, fixture.expiresAt - 1)).toEqual({ eligible: true, reason: "eligible" });
    expect(original).toEqual(fixture);
  });
  test.each(["0", "-1", "1.5", "01000", "1001", "2100000000000001000", "99999999999999999999"])("reject quantity %s", (amountMsat) => {
    expect(() => parseTerms({ ...fixture, amountMsat })).toThrow();
  });
  test.each([
    { version: "checkout/2" }, { network: "testnet" }, { paid: true },
    { merchantOrigin: "http://merchant.example" }, { merchantOrigin: "https://merchant.example/path" },
    { merchantOrigin: "https://secret@merchant.example" }, { expiresAt: 1.5 }, { paymentHash: "f" },
  ])("reject malformed or ambiguous terms %j", (patch) => {
    expect(evaluateNative({ ...fixture, ...patch }, policy, 1).reason).toBe("invalid_terms");
  });
  test("expiry is exclusive", () => {
    expect(evaluateNative(fixture, policy, fixture.expiresAt - 1).eligible).toBe(true);
    expect(evaluateNative(fixture, policy, fixture.expiresAt).reason).toBe("expired");
    expect(evaluateNative(fixture, policy, fixture.expiresAt + 1).reason).toBe("expired");
  });
  test("pinned merchant, receiver and network", () => {
    expect(evaluateNative(fixture, { ...policy, merchantOrigin: "https://other.example" }, 1).reason).toBe("origin_mismatch");
    expect(evaluateNative(fixture, { ...policy, receiver: "03" + "1".repeat(64) }, 1).reason).toBe("receiver_mismatch");
    expect(evaluateNative(fixture, { ...policy, network: "signet" }, 1).reason).toBe("network_mismatch");
  });
  test("both fee caps use exact integer arithmetic", () => {
    expect(evaluateNative({ ...fixture, buyerExtraMsat: "100000" }, policy, 1).eligible).toBe(true);
    expect(evaluateNative({ ...fixture, buyerExtraMsat: "100001" }, policy, 1).reason).toBe("fee_limit");
    expect(evaluateNative({ ...fixture, buyerExtraMsat: "50001" }, { ...policy, maxBuyerExtraBps: 500 }, 1).reason).toBe("fee_limit");
  });
  test("invalid policy and time fail closed", () => {
    expect(evaluateNative(fixture, policy, NaN).reason).toBe("invalid_policy");
    expect(evaluateNative(fixture, { ...policy, maxBuyerExtraBps: -1 }, 1).reason).toBe("invalid_policy");
    expect(evaluateNative(fixture, { ...policy, maxBuyerExtraMsat: "01" }, 1).reason).toBe("invalid_policy");
  });
});
