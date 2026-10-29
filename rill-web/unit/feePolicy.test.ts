import { describe, expect, test } from "bun:test";
import vector from "../../rill-docs/vectors/wire/btc-network-fees-v1.json";
import {
  checkFeeBreakdown, feePolicyHash, FEE_MODEL, FEE_POLICY_EXTENSION, FEE_POLICY_FEATURE,
  networkFeeRequest, parseFeePolicy, type BtcFeePolicy,
} from "../src/swap/feePolicy";

const policy = vector.policy as BtcFeePolicy;
const terms: Parameters<typeof checkFeeBreakdown>[0] = {
  profile_id: "btc-to-ln/v1", required_features: [FEE_POLICY_FEATURE],
  extensions: { [FEE_POLICY_EXTENSION]: vector.breakdown }, terms_expiry: vector.expires_at,
  max_claim_fee_sat: "5000", max_funding_fee_sat: "5000",
  economics: { kind: "btc-to-ln", lightning_principal_sat: vector.principal_sat,
    success_fee_sat: vector.success_fee_sat, contract_amount_sat: "100535" },
};

describe("offer-bound network fees", () => {
  test("shared policy hash and complete economics match Python's byte vector", () => {
    expect(feePolicyHash(policy)).toBe(vector.policy_hash);
    expect(parseFeePolicy({ [FEE_POLICY_EXTENSION]: policy })).toEqual(policy);
    expect(checkFeeBreakdown(terms, { [FEE_POLICY_EXTENSION]: vector.request }, 1000)).toEqual({ ...vector.breakdown, policy });
  });

  test("independent request ceiling cannot be replaced by provider's high maximum", () => {
    expect(networkFeeRequest({ feePolicy: policy, outerEventId: vector.request.offer_event_id }, 1000))
      .toEqual({ [FEE_POLICY_EXTENSION]: { ...vector.request, max_network_feerate_sat_kvb: "2000" } });
    expect(() => networkFeeRequest({ feePolicy: policy, outerEventId: vector.request.offer_event_id })).toThrow("independent");
    expect(networkFeeRequest({ outerEventId: "" })).toEqual({});
  });

  test.each([
    [{ offer_event_id: "22".repeat(32) }, "different announcement"],
    [{ policy_hash: "22".repeat(32) }, "policy changed"],
    [{ max_network_feerate_sat_kvb: "2499" }, "independent ceiling"],
  ])("rejects request substitution %j", (change, reason) => {
    expect(() => checkFeeBreakdown(terms, { [FEE_POLICY_EXTENSION]: { ...vector.request, ...change } }, 1000)).toThrow(reason);
  });

  test.each([
    [{ network_fee_sat: "386" }, "transaction-size"],
    [{ service_fee_sat: "151" }, "service fee"],
    [{ feerate_sat_kvb: "10001" }, "advertised maximum"],
    [{ estimated_at: 989 }, "stale"],
    [{ estimated_at: 1001 }, "future"],
    [{ vbytes: 9999 }, "unexpected fields"],
    [{ policy: { ...policy, model: "other/v1" } }, "model"],
  ])("rejects inflated fee evidence %j", (change, reason) => {
    const changed = { ...terms, extensions: { [FEE_POLICY_EXTENSION]: { ...vector.breakdown, ...change } } };
    expect(() => checkFeeBreakdown(changed)).toThrow(reason);
  });

  test("60 seconds gates acceptance, not historical recovery", () => {
    expect(checkFeeBreakdown(terms, undefined, 1059)).toBeDefined();
    expect(() => checkFeeBreakdown(terms, undefined, 1060)).toThrow("expired");
    expect(() => checkFeeBreakdown({ ...terms, terms_expiry: 1061 })).toThrow("60 seconds");
    expect(checkFeeBreakdown(terms)).toBeDefined();
  });

  test("no optional extension or missing requested feature can downgrade enforcement", () => {
    expect(() => checkFeeBreakdown({ ...terms, required_features: [] })).toThrow("required");
    expect(() => checkFeeBreakdown({ ...terms, required_features: [], extensions: {} }, { [FEE_POLICY_EXTENSION]: vector.request })).toThrow("omitted");
  });

  test("the transaction-size model is fixed", () => {
    expect(FEE_MODEL).toBe("p2tr-cooperative-1in-2out/v1");
  });

  test("accepted feature lists remain readable by independent recovery implementations", () => {
    expect(() => checkFeeBreakdown({ ...terms, required_features: ["cooperative-claim/v1", FEE_POLICY_FEATURE] })).toThrow("sorted");
    expect(checkFeeBreakdown({ ...terms, required_features: [FEE_POLICY_FEATURE, "cooperative-claim/v1"] })).toBeDefined();
  });
});
