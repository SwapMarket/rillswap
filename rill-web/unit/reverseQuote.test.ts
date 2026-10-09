import { expect, test } from "bun:test";
import vectors from "../../rill-docs/vectors/wire/quote-v1.json";
import { checkReverseQuoteOffer } from "../src/swap/reverseSwap";

const offer = (vectors as unknown as { valid: Record<string, Record<string, unknown>[]> }).valid.reverseQuoteOffer![0]!;
const economics = offer.economics as Record<string, string>;
const request = {
  network: { name: "regtest" } as never,
  payoutSat: BigInt(economics.nominal_payout_sat!),
  limits: { maxSuccessFeeSat: BigInt(economics.success_fee_sat!), minClaimFeeReserveSat: BigInt(economics.claim_fee_reserve_sat!),
    maxClaimFeeSat: BigInt(offer.max_claim_fee_sat as string), minRefundDelayBlocks: offer.refund_delay_blocks as number,
    maxIncomingHtlcDelayBlocks: offer.incoming_htlc_expiry_delta_blocks as number },
};
const now = (offer.expires_at as number) - 60;
const prepaid = BigInt(economics.mining_prepayment_sat!) !== 0n;

test("an indicative offer at exactly the client's limits is accepted", () => {
  const withoutPrepayment = { ...offer, economics: { ...economics, mining_prepayment_sat: "0",
    hold_invoice_sat: (BigInt(economics.contract_amount_sat!) + BigInt(economics.success_fee_sat!)).toString() } };
  expect(checkReverseQuoteOffer(prepaid ? withoutPrepayment : offer, request, now).kind).toBe("ln-to-btc");
});

test("offers beyond any limit, expired, inconsistent, or for another payout are refused", () => {
  const { limits } = request;
  for (const tightened of [
    { ...limits, maxSuccessFeeSat: limits.maxSuccessFeeSat - 1n },
    { ...limits, minClaimFeeReserveSat: limits.minClaimFeeReserveSat + 1n },
    { ...limits, maxClaimFeeSat: limits.maxClaimFeeSat - 1n },
    { ...limits, minRefundDelayBlocks: limits.minRefundDelayBlocks + 1 },
    { ...limits, maxIncomingHtlcDelayBlocks: limits.maxIncomingHtlcDelayBlocks - 1 },
  ]) expect(() => checkReverseQuoteOffer(offer, { ...request, limits: tightened }, now)).toThrow();
  expect(() => checkReverseQuoteOffer(offer, request, offer.expires_at as number)).toThrow();
  expect(() => checkReverseQuoteOffer(offer, { ...request, payoutSat: request.payoutSat + 1n }, now)).toThrow();
  expect(() => checkReverseQuoteOffer({ ...offer, economics: { ...economics, hold_invoice_sat: "1" } }, request, now)).toThrow("inconsistent");
  expect(() => checkReverseQuoteOffer({ ...offer, refund_delay_blocks: offer.incoming_htlc_expiry_delta_blocks }, request, now)).toThrow();
  expect(() => checkReverseQuoteOffer({ ...offer, kind: "btc-to-ln" }, request, now)).toThrow("validateReverseQuoteOffer");
  const hold = BigInt(economics.contract_amount_sat!) + BigInt(economics.success_fee_sat!) - 1n;
  const prepayment = { ...offer, economics: { ...economics, mining_prepayment_sat: "1", hold_invoice_sat: hold.toString() } };
  expect(() => checkReverseQuoteOffer(prepayment, request, now)).toThrow("mining prepayment");
});

test("price discovery sends only an indicative request, exposes no invoice, and zeroes its session secret", async () => {
  const child = Bun.spawn([process.execPath, "unit/fixtures/reverseQuoteFixture.ts"], { stdout: "pipe", stderr: "pipe" });
  const [output, errors, status] = await Promise.all([new Response(child.stdout).text(), new Response(child.stderr).text(), child.exited]);
  expect(errors).toBe(""); expect(status).toBe(0);
  const result = JSON.parse(output);
  // Every message (including the refused second attempt's) is a hash-free indicative request.
  expect(result.sent).toEqual([economics.nominal_payout_sat, "1"].map((payout) => ({ type: "quote_request",
    payload: { kind: "ln-to-btc", mode: "indicative", nominal_payout_sat: payout, extensions: {} } })));
  expect(result.keys).not.toContain("holdInvoice");
  expect(result.beforeDispose[0]).toBe(true);
  expect(result.afterDispose).toEqual([false, false]);
  expect(result.refused).toContain("does not honor request: payout");
});
