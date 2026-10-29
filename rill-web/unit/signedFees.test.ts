import { describe, expect, test } from "bun:test";
import economicsVectors from "../../rill-docs/vectors/economics/cases-v1.json";
import feeVector from "../../rill-docs/vectors/wire/btc-network-fees-v1.json";
import quoteVectors from "../../rill-docs/vectors/wire/quote-v1.json";
import { checkFeeBreakdown, FEE_POLICY_EXTENSION, FEE_POLICY_FEATURE } from "../src/swap/feePolicy";
import { checkReverseQuoteOffer } from "../src/swap/reverseSwap";
import {
  checkBtcToLnTerms, checkLnToBtcTerms, COOPERATIVE_CLAIM_FEATURE, signedSats, type BtcToLnTerms, type LnToBtcTerms,
} from "../src/swap/wire";

const clone = <T>(value: T): T => JSON.parse(JSON.stringify(value)) as T;
type Case = { readonly id: string; readonly contract_terms: { readonly object: unknown } };
const valid = economicsVectors.valid as unknown as Case[];
const termsOf = (id: string) => clone(valid.find((entry) => entry.id === id)!.contract_terms.object);

describe("signed fee strings", () => {
  test.each(["0", "1", "-1", "2100000000000000", "-2100000000000000"])("accepts %s", (value) => {
    expect(signedSats(value, "fee")).toBe(BigInt(value));
  });

  test.each(["-0", "+1", "01", "-01", " 1", "1.0", "--1", "-", "", "2100000000000001", "-2100000000000001"])("refuses %j", (value) => {
    expect(() => signedSats(value, "fee")).toThrow("fee");
  });
});

describe("rebate economics shared with the specification vectors", () => {
  test("BTC to LN: a rebate lowers the contract amount, which must still match V = L + S", () => {
    const terms = termsOf("btc-to-ln-rebate") as { required_features: string[]; economics: Record<string, string> };
    expect(terms.economics.success_fee_sat).toBe("-100");
    // This browser additionally requires cooperative claims for BTC to LN.
    terms.required_features = [COOPERATIVE_CLAIM_FEATURE];
    expect(() => checkBtcToLnTerms(terms as unknown as BtcToLnTerms)).not.toThrow();
    terms.economics.contract_amount_sat = (BigInt(terms.economics.lightning_principal_sat!) + 100n).toString();
    expect(() => checkBtcToLnTerms(terms as unknown as BtcToLnTerms)).toThrow("V = L + S");
  });

  test("LN to BTC: a rebate lowers the hold invoice and forbids a mining prepayment", () => {
    const terms = termsOf("ln-to-btc-rebate") as LnToBtcTerms;
    expect(terms.economics.success_fee_sat).toBe("-100");
    expect(() => checkLnToBtcTerms(terms)).not.toThrow();
    const invalid = economicsVectors.invalid.find((entry) => entry.id === "ln-to-btc-prepayment-with-rebate")!;
    expect(() => checkLnToBtcTerms(clone(invalid.replacement) as unknown as LnToBtcTerms)).toThrow("H = V + S - M");
  });
});

describe("indicative reverse quotes", () => {
  const offer = (quoteVectors as unknown as { valid: Record<string, Record<string, unknown>[]> }).valid.reverseQuoteOffer![0]!;
  const economics = offer.economics as Record<string, string>;
  const request = {
    network: { name: "regtest" } as never,
    payoutSat: BigInt(economics.nominal_payout_sat!),
    limits: { maxSuccessFeeSat: 0n, minClaimFeeReserveSat: BigInt(economics.claim_fee_reserve_sat!),
      maxClaimFeeSat: BigInt(offer.max_claim_fee_sat as string), minRefundDelayBlocks: offer.refund_delay_blocks as number,
      maxIncomingHtlcDelayBlocks: offer.incoming_htlc_expiry_delta_blocks as number },
  };
  const now = (offer.expires_at as number) - 60;
  const rebate = (prepayment: bigint) => ({ ...offer, economics: { ...economics, success_fee_sat: "-100",
    mining_prepayment_sat: prepayment.toString(),
    hold_invoice_sat: (BigInt(economics.contract_amount_sat!) - 100n - prepayment).toString() } });

  test("a rebate passes even a zero fee limit", () => {
    expect(checkReverseQuoteOffer(rebate(0n), request, now).economics.success_fee_sat).toBe("-100");
  });

  test("a prepayment against a rebate is inconsistent", () => {
    expect(() => checkReverseQuoteOffer(rebate(1n), request, now)).toThrow("inconsistent");
  });
});

describe("fee breakdown", () => {
  const terms = (service: bigint): Parameters<typeof checkFeeBreakdown>[0] => {
    const success = service + BigInt(feeVector.breakdown.network_fee_sat);
    return {
      profile_id: "btc-to-ln/v1", required_features: [FEE_POLICY_FEATURE], terms_expiry: feeVector.expires_at,
      extensions: { [FEE_POLICY_EXTENSION]: { ...feeVector.breakdown, service_fee_sat: service.toString() } },
      max_claim_fee_sat: "5000", max_funding_fee_sat: "5000",
      economics: { kind: "btc-to-ln", lightning_principal_sat: feeVector.principal_sat, success_fee_sat: success.toString(),
        contract_amount_sat: (BigInt(feeVector.principal_sat) + success).toString() },
    };
  };
  const advertised = BigInt(feeVector.breakdown.service_fee_sat);

  test.each([advertised, advertised - 1n, 0n, -100n, -500n])("allows a service fee of %p, never above the policy", (service) => {
    expect(checkFeeBreakdown(terms(service), { [FEE_POLICY_EXTENSION]: feeVector.request }, 1000)?.service_fee_sat).toBe(service.toString());
  });

  test("a surcharge or a negative zero is refused", () => {
    expect(() => checkFeeBreakdown(terms(advertised + 1n))).toThrow("exceeds advertised policy");
    const negativeZero = terms(0n);
    (negativeZero.extensions[FEE_POLICY_EXTENSION] as Record<string, string>).service_fee_sat = "-0";
    expect(() => checkFeeBreakdown(negativeZero)).toThrow("malformed");
  });
});
